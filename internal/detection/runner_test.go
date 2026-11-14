package detection

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
	"gorm.io/gorm"
)

const runnerRetention = 72 * time.Hour

type runnerFixture struct {
	runner       *Runner
	database     *gorm.DB
	store        *dataset.PostgresStore
	registration Registration
	manifest     config.DetectionManifest
	end          time.Time
}

func newRunnerFixture(t *testing.T, logic Detection, files config.Files, edits ...[2]string) *runnerFixture {
	t.Helper()
	database := databasetest.New(t)
	store := dataset.NewPostgresStore(database)
	registration := Registration{Manifest: manifestYAML(t, edits...), Logic: logic}
	manifest, err := config.ParseDetectionManifest(registration.Manifest)
	if err != nil {
		t.Fatalf("parse test manifest: %v", err)
	}
	registry, err := ValidateRegistrations([]Registration{registration}, files)
	if err != nil {
		t.Fatalf("ValidateRegistrations() error = %v, want nil", err)
	}
	return &runnerFixture{
		runner: &Runner{
			Database: database,
			Store:    store,
			Registry: registry,
			Logger:   slog.New(slog.DiscardHandler),
		},
		database:     database,
		store:        store,
		registration: registration,
		manifest:     manifest,
		end:          time.Now().UTC().Add(-time.Minute).Truncate(time.Second),
	}
}

func (fixture *runnerFixture) window() (time.Time, time.Time) {
	end := fixture.end
	return end.Add(-time.Duration(fixture.manifest.Window.Size)), end
}

func (fixture *runnerFixture) registerDataset(t *testing.T, name string) {
	t.Helper()
	err := fixture.database.Transaction(func(transaction *gorm.DB) error {
		return fixture.store.RegisterDataset(context.Background(), transaction, dataset.Dataset{
			Name:            name,
			PipelineID:      "pipeline-" + name,
			Retention:       runnerRetention,
			AllowedLateness: 0,
		})
	})
	if err != nil {
		t.Fatalf("register dataset %q: %v", name, err)
	}
}

func (fixture *runnerFixture) writeBatch(t *testing.T, name string, fetchWatermark time.Time, records []dataset.Record) {
	t.Helper()
	err := fixture.database.Transaction(func(transaction *gorm.DB) error {
		return fixture.store.WriteBatch(context.Background(), transaction, name, dataset.Batch{
			RunID:          "pipeline-run",
			Records:        records,
			FetchWatermark: fetchWatermark,
		})
	})
	if err != nil {
		t.Fatalf("write dataset %q batch: %v", name, err)
	}
}

func (fixture *runnerFixture) markReady(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		fixture.registerDataset(t, name)
		fixture.writeBatch(t, name, fixture.end, nil)
	}
}

func (fixture *runnerFixture) run(t *testing.T) (RunResult, error) {
	t.Helper()
	return fixture.runner.RunWindow(context.Background(), fixture.registration, fixture.end)
}

func countRows(t *testing.T, database *gorm.DB, model any) int64 {
	t.Helper()
	var count int64
	if err := database.Model(model).Count(&count).Error; err != nil {
		t.Fatalf("count %T rows: %v", model, err)
	}
	return count
}

func loadRuns(t *testing.T, database *gorm.DB) []runRow {
	t.Helper()
	var runs []runRow
	if err := database.Order("revision").Find(&runs).Error; err != nil {
		t.Fatalf("load detection_runs: %v", err)
	}
	return runs
}

func loadProposals(t *testing.T, database *gorm.DB) []proposalRow {
	t.Helper()
	var proposals []proposalRow
	if err := database.Find(&proposals).Error; err != nil {
		t.Fatalf("load detection_proposals: %v", err)
	}
	return proposals
}

func zeroRunResult(result RunResult) bool {
	return result.RunID == "" && result.Status == "" &&
		result.WindowStart.IsZero() && result.WindowEnd.IsZero() &&
		result.Revision == 0 && result.RowsRead == 0 &&
		result.Proposals == 0 && result.Error == ""
}

func runnerEvidence(start time.Time) []Evidence {
	return []Evidence{{
		SourceKey: dataset.SourceKey{FetcherInstanceID: "fixture", Index: "auth", DocumentID: "1"},
		EventTime: start.Add(time.Minute),
	}}
}

func runnerProposal(start time.Time) Proposal {
	return Proposal{
		Subject:  identitySubject("alice", "web01", ""),
		Summary:  "10 failed logons, then a success",
		Details:  map[string]string{"failed_attempts": "10"},
		Evidence: runnerEvidence(start),
	}
}

func TestRunWindowRecordsOKRunAndProposals(t *testing.T) {
	logic := stubDetection(func(ctx context.Context, window Window) ([]Proposal, error) {
		if window.Revision != 1 {
			return nil, fmt.Errorf("window revision = %d, want 1", window.Revision)
		}
		var evidence []Evidence
		for record, err := range window.Events(ctx, "auth_events") {
			if err != nil {
				return nil, err
			}
			evidence = append(evidence, EvidenceOf(record))
		}
		proposal := runnerProposal(window.Start)
		proposal.Evidence = evidence
		return []Proposal{proposal}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	start, end := fixture.window()
	fixture.registerDataset(t, "auth_events")
	fixture.writeBatch(t, "auth_events", end, []dataset.Record{
		testRecord("2", start.Add(2*time.Minute), udm.EventTypeUserLogin),
		testRecord("other-type", start.Add(3*time.Minute), udm.EventTypeGenericEvent),
		testRecord("1", start.Add(time.Minute), udm.EventTypeUserLogin),
	})

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want nil", err)
	}

	if result.Status != RunStatusOK {
		t.Fatalf("RunWindow() status = %s, want OK (error %q)", result.Status, result.Error)
	}
	if result.RunID == "" {
		t.Fatal("RunWindow() run id is empty")
	}
	if !result.WindowStart.Equal(start) || !result.WindowEnd.Equal(end) {
		t.Fatalf("RunWindow() window = [%s, %s), want [%s, %s)", result.WindowStart, result.WindowEnd, start, end)
	}
	if result.Revision != 1 || result.RowsRead != 2 || result.Proposals != 1 || result.Error != "" {
		t.Fatalf("RunWindow() result = %+v, want revision 1, 2 rows, 1 proposal", result)
	}

	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 {
		t.Fatalf("detection_runs rows = %d, want 1", len(runs))
	}
	run := runs[0]
	if run.ID != result.RunID || run.DetectionID != "brute-force-then-success" || run.DetectionVersion != "1.0.0" {
		t.Fatalf("run row = %+v, want the OK run of the manifest", run)
	}
	if run.Status != string(RunStatusOK) || run.Revision != 1 || run.RowsRead != 2 || run.Proposals != 1 || run.Error != nil {
		t.Fatalf("run row = %+v, want OK, revision 1, 2 rows, 1 proposal, no error", run)
	}
	if run.StartedAt.IsZero() || run.FinishedAt == nil {
		t.Fatalf("run row timestamps = started %s, finished %v, want both set", run.StartedAt, run.FinishedAt)
	}

	proposals := loadProposals(t, fixture.database)
	if len(proposals) != 1 {
		t.Fatalf("detection_proposals rows = %d, want 1", len(proposals))
	}
	proposal := proposals[0]
	if proposal.DetectionRunID != run.ID {
		t.Fatalf("proposal run id = %q, want %q", proposal.DetectionRunID, run.ID)
	}
	wantIdentity, err := ComputeIdentity(fixture.manifest.ID, fixture.manifest.Alerting, proposal.Subject)
	if err != nil {
		t.Fatalf("ComputeIdentity() error = %v", err)
	}
	if proposal.IdentityHash != wantIdentity.Hash || !equalIdentityValues(proposal.Identity, wantIdentity.Values) {
		t.Fatalf("proposal identity = %s %v, want %s %v", proposal.IdentityHash, proposal.Identity, wantIdentity.Hash, wantIdentity.Values)
	}
	if proposal.Severity != string(SeverityHigh) || proposal.Summary != "10 failed logons, then a success" {
		t.Fatalf("proposal = %+v, want HIGH with the summary", proposal)
	}
	if proposal.Details["failed_attempts"] != "10" {
		t.Fatalf("proposal details = %v, want failed_attempts=10", proposal.Details)
	}
	if len(proposal.Evidence) != 2 {
		t.Fatalf("proposal evidence = %d, want the two USER_LOGIN records", len(proposal.Evidence))
	}
	if proposal.Evidence[0].SourceKey.DocumentID != "1" || proposal.Evidence[1].SourceKey.DocumentID != "2" {
		t.Fatalf("proposal evidence order = %+v, want document 1 then 2", proposal.Evidence)
	}
	if !proposal.Evidence[0].EventTime.Equal(start.Add(time.Minute)) {
		t.Fatalf("proposal evidence time = %s, want %s", proposal.Evidence[0].EventTime, start.Add(time.Minute))
	}
}

func TestRunWindowIncrementsRevision(t *testing.T) {
	var revisions []int
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		revisions = append(revisions, window.Revision)
		return nil, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	fixture.markReady(t, "auth_events")

	first, err := fixture.run(t)
	if err != nil {
		t.Fatalf("first RunWindow() error = %v, want nil", err)
	}
	second, err := fixture.run(t)
	if err != nil {
		t.Fatalf("second RunWindow() error = %v, want nil", err)
	}

	if first.Revision != 1 || second.Revision != 2 {
		t.Fatalf("revisions = %d, %d, want 1, 2", first.Revision, second.Revision)
	}
	if len(revisions) != 2 || revisions[0] != 1 || revisions[1] != 2 {
		t.Fatalf("window revisions = %v, want [1 2]", revisions)
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 2 || runs[0].Revision != 1 || runs[1].Revision != 2 {
		t.Fatalf("detection_runs = %+v, want revisions 1 and 2", runs)
	}
}

func TestRunWindowRejectsInactiveDetection(t *testing.T) {
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, nil })
	fixture := newRunnerFixture(t, logic, config.Files{})

	result, err := fixture.run(t)

	if !errors.Is(err, ErrDetectionInactive) {
		t.Fatalf("RunWindow() error = %v, want ErrDetectionInactive", err)
	}
	wantWarning := "detection brute-force-then-success inactive: input dataset auth_events not configured"
	if err.Error() != wantWarning {
		t.Fatalf("RunWindow() error = %q, want exactly the inactive warning %q", err, wantWarning)
	}
	if !zeroRunResult(result) {
		t.Fatalf("RunWindow() result = %+v, want the zero result", result)
	}
	if count := countRows(t, fixture.database, &runRow{}); count != 0 {
		t.Fatalf("detection_runs rows = %d, want none", count)
	}
}

func TestRunWindowRejectsUnknownDetection(t *testing.T) {
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, nil })
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	fixture.runner.Registry = Registry{
		Manifests: map[string]config.DetectionManifest{},
		Inactive:  map[string]string{},
	}

	_, err := fixture.run(t)

	if !errors.Is(err, ErrUnknownDetection) {
		t.Fatalf("RunWindow() error = %v, want ErrUnknownDetection", err)
	}
	if count := countRows(t, fixture.database, &runRow{}); count != 0 {
		t.Fatalf("detection_runs rows = %d, want none", count)
	}
}

func TestRunWindowRejectsInvalidWindowEnd(t *testing.T) {
	tests := []struct {
		name      string
		windowEnd func(fixture *runnerFixture) time.Time
		wantError string
	}{
		{
			name:      "future window end",
			windowEnd: func(fixture *runnerFixture) time.Time { return fixture.end.Add(time.Hour) },
			wantError: "future",
		},
		{
			name:      "window end is not a whole second",
			windowEnd: func(fixture *runnerFixture) time.Time { return fixture.end.Add(500 * time.Millisecond) },
			wantError: "whole second",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logic := stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, nil })
			fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
			fixture.markReady(t, "auth_events")

			_, err := fixture.runner.RunWindow(context.Background(), fixture.registration, test.windowEnd(fixture))

			if !errors.Is(err, ErrInvalidWindow) {
				t.Fatalf("RunWindow() error = %v, want ErrInvalidWindow", err)
			}
			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("RunWindow() error = %q, want it to contain %q", err, test.wantError)
			}
			if count := countRows(t, fixture.database, &runRow{}); count != 0 {
				t.Fatalf("detection_runs rows = %d, want none", count)
			}
		})
	}
}

func TestRunWindowRequiresEveryInputToBeReady(t *testing.T) {
	twoInputs := [2]string{
		"inputs:\n  - dataset: auth_events\n    eventTypes: [USER_LOGIN]\n",
		"inputs:\n  - dataset: auth_events\n    eventTypes: [USER_LOGIN]\n  - dataset: edr_events\n    eventTypes: [USER_LOGIN]\n",
	}

	t.Run("one input behind", func(t *testing.T) {
		logic := stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, nil })
		fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
		fixture.registerDataset(t, "auth_events")

		_, err := fixture.run(t)

		if !errors.Is(err, ErrInputNotReady) {
			t.Fatalf("RunWindow() error = %v, want ErrInputNotReady", err)
		}
		if !strings.Contains(err.Error(), "auth_events") {
			t.Fatalf("RunWindow() error = %q, want it to name auth_events", err)
		}
		if count := countRows(t, fixture.database, &runRow{}); count != 0 {
			t.Fatalf("detection_runs rows = %d, want none", count)
		}
	})

	t.Run("dataset has never been written", func(t *testing.T) {
		logic := stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, nil })
		fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))

		_, err := fixture.run(t)

		if !errors.Is(err, ErrInputNotReady) {
			t.Fatalf("RunWindow() error = %v, want ErrInputNotReady", err)
		}
		if !strings.Contains(err.Error(), "auth_events") || !strings.Contains(err.Error(), "unset") {
			t.Fatalf("RunWindow() error = %q, want it to name auth_events with an unset watermark", err)
		}
		if count := countRows(t, fixture.database, &runRow{}); count != 0 {
			t.Fatalf("detection_runs rows = %d, want none", count)
		}
	})

	t.Run("only the behind input is named", func(t *testing.T) {
		logic := stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, nil })
		fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events", "edr_events"), twoInputs)
		fixture.registerDataset(t, "auth_events")
		fixture.writeBatch(t, "auth_events", fixture.end, nil)
		fixture.registerDataset(t, "edr_events")

		_, err := fixture.run(t)

		if !errors.Is(err, ErrInputNotReady) {
			t.Fatalf("RunWindow() error = %v, want ErrInputNotReady", err)
		}
		if !strings.Contains(err.Error(), "edr_events") {
			t.Fatalf("RunWindow() error = %q, want it to name edr_events", err)
		}
		if strings.Contains(err.Error(), "auth_events watermark") {
			t.Fatalf("RunWindow() error = %q, want only the behind input", err)
		}
		if count := countRows(t, fixture.database, &runRow{}); count != 0 {
			t.Fatalf("detection_runs rows = %d, want none", count)
		}
	})
}

func TestRunWindowRecordsFailure(t *testing.T) {
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) {
		return nil, errors.New("evaluation exploded")
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	fixture.markReady(t, "auth_events")

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want a recorded run", err)
	}

	if result.Status != RunStatusFailed || !strings.Contains(result.Error, "evaluation exploded") {
		t.Fatalf("RunWindow() result = %+v, want FAILED with the evaluation error", result)
	}
	if result.Proposals != 0 {
		t.Fatalf("RunWindow() proposals = %d, want 0", result.Proposals)
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 || runs[0].Status != string(RunStatusFailed) {
		t.Fatalf("detection_runs = %+v, want one FAILED row", runs)
	}
	if runs[0].Error == nil || !strings.Contains(*runs[0].Error, "evaluation exploded") {
		t.Fatalf("run row error = %v, want the evaluation error", runs[0].Error)
	}
	if count := countRows(t, fixture.database, &proposalRow{}); count != 0 {
		t.Fatalf("detection_proposals rows = %d, want none", count)
	}
}

func TestRunWindowRecordsPanic(t *testing.T) {
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) {
		panic("kaboom")
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	fixture.markReady(t, "auth_events")

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want a recorded run", err)
	}

	if result.Status != RunStatusFailed || !strings.Contains(result.Error, "panic: kaboom") {
		t.Fatalf("RunWindow() result = %+v, want FAILED with panic: kaboom", result)
	}
	if len(result.Error) > maxPanicStackBytes+64 {
		t.Fatalf("RunWindow() error length = %d, want the stack trimmed to %d bytes", len(result.Error), maxPanicStackBytes)
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 || runs[0].Status != string(RunStatusFailed) {
		t.Fatalf("detection_runs = %+v, want one FAILED row", runs)
	}
}

func TestRunWindowTimesOut(t *testing.T) {
	tests := []struct {
		name  string
		logic Detection
	}{
		{
			name: "detection blocks on its context",
			logic: stubDetection(func(ctx context.Context, _ Window) ([]Proposal, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}),
		},
		{
			name: "detection ignores its context",
			logic: stubDetection(func(context.Context, Window) ([]Proposal, error) {
				var never chan struct{}
				<-never
				return nil, nil
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRunnerFixture(t, test.logic, configFilesWriting("auth_events"),
				[2]string{"timeout: 30s", "timeout: 1s"})
			fixture.markReady(t, "auth_events")

			started := time.Now()
			result, err := fixture.run(t)
			elapsed := time.Since(started)

			if err != nil {
				t.Fatalf("RunWindow() error = %v, want a recorded run", err)
			}
			if result.Status != RunStatusTimedOut {
				t.Fatalf("RunWindow() status = %s, want TIMED_OUT (error %q)", result.Status, result.Error)
			}
			if elapsed > 1500*time.Millisecond {
				t.Fatalf("RunWindow() took %s, want about the 1s deadline", elapsed)
			}
			runs := loadRuns(t, fixture.database)
			if len(runs) != 1 || runs[0].Status != string(RunStatusTimedOut) {
				t.Fatalf("detection_runs = %+v, want one TIMED_OUT row", runs)
			}
			if count := countRows(t, fixture.database, &proposalRow{}); count != 0 {
				t.Fatalf("detection_proposals rows = %d, want none", count)
			}
		})
	}
}

func TestRunWindowChecksProposals(t *testing.T) {
	tooManyDetails := func(start time.Time) Proposal {
		proposal := runnerProposal(start)
		proposal.Details = make(map[string]string, 51)
		for index := 0; index < 51; index++ {
			proposal.Details[fmt.Sprintf("key-%d", index)] = "value"
		}
		return proposal
	}

	tests := []struct {
		name      string
		edits     [][2]string
		proposals func(start time.Time) []Proposal
		wantError string
	}{
		{
			name:  "too many proposals",
			edits: [][2]string{{"maxProposals: 100", "maxProposals: 1"}},
			proposals: func(start time.Time) []Proposal {
				return []Proposal{runnerProposal(start), runnerProposal(start)}
			},
			wantError: "proposal count 2 exceeds budget 1",
		},
		{
			name: "empty summary",
			proposals: func(start time.Time) []Proposal {
				proposal := runnerProposal(start)
				proposal.Summary = ""
				return []Proposal{proposal}
			},
			wantError: "summary is empty",
		},
		{
			name: "summary too long",
			proposals: func(start time.Time) []Proposal {
				proposal := runnerProposal(start)
				proposal.Summary = strings.Repeat("a", 501)
				return []Proposal{proposal}
			},
			wantError: "summary is longer than 500 bytes",
		},
		{
			name: "no evidence",
			proposals: func(start time.Time) []Proposal {
				proposal := runnerProposal(start)
				proposal.Evidence = nil
				return []Proposal{proposal}
			},
			wantError: "evidence is empty",
		},
		{
			name:  "too much evidence",
			edits: [][2]string{{"maxEvidencePerProposal: 1000", "maxEvidencePerProposal: 1"}},
			proposals: func(start time.Time) []Proposal {
				proposal := runnerProposal(start)
				proposal.Evidence = append(proposal.Evidence, Evidence{EventTime: start.Add(2 * time.Minute)})
				return []Proposal{proposal}
			},
			wantError: "evidence count 2 exceeds budget 1",
		},
		{
			name: "evidence before the window",
			proposals: func(start time.Time) []Proposal {
				proposal := runnerProposal(start)
				proposal.Evidence[0].EventTime = start.Add(-time.Second)
				return []Proposal{proposal}
			},
			wantError: "outside the window",
		},
		{
			name: "evidence at the window end",
			proposals: func(start time.Time) []Proposal {
				proposal := runnerProposal(start)
				proposal.Evidence[0].EventTime = start.Add(time.Duration(15) * time.Minute)
				return []Proposal{proposal}
			},
			wantError: "outside the window",
		},
		{
			name: "invalid severity",
			proposals: func(start time.Time) []Proposal {
				proposal := runnerProposal(start)
				proposal.Severity = "CRITICAL"
				return []Proposal{proposal}
			},
			wantError: "invalid severity",
		},
		{
			name:      "too many details",
			proposals: func(start time.Time) []Proposal { return []Proposal{tooManyDetails(start)} },
			wantError: "details has 51 entries",
		},
		{
			name: "detail value too long",
			proposals: func(start time.Time) []Proposal {
				proposal := runnerProposal(start)
				proposal.Details = map[string]string{"failed_attempts": strings.Repeat("a", 1025)}
				return []Proposal{proposal}
			},
			wantError: "longer than 1024 bytes",
		},
		{
			name: "missing required identity",
			proposals: func(start time.Time) []Proposal {
				proposal := runnerProposal(start)
				proposal.Subject = identitySubject("", "web01", "")
				return []Proposal{proposal}
			},
			wantError: "target.user.userid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
				return test.proposals(window.Start), nil
			})
			fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), test.edits...)
			fixture.markReady(t, "auth_events")

			result, err := fixture.run(t)
			if err != nil {
				t.Fatalf("RunWindow() error = %v, want a recorded run", err)
			}

			if result.Status != RunStatusFailed || !strings.Contains(result.Error, test.wantError) {
				t.Fatalf("RunWindow() result = %+v, want FAILED containing %q", result, test.wantError)
			}
			if result.Proposals != 0 {
				t.Fatalf("RunWindow() proposals = %d, want 0", result.Proposals)
			}
			runs := loadRuns(t, fixture.database)
			if len(runs) != 1 || runs[0].Status != string(RunStatusFailed) {
				t.Fatalf("detection_runs = %+v, want one FAILED row", runs)
			}
			if count := countRows(t, fixture.database, &proposalRow{}); count != 0 {
				t.Fatalf("detection_proposals rows = %d, want none", count)
			}
		})
	}
}

func TestRunWindowBudgetFailureAgainstStore(t *testing.T) {
	logic := stubDetection(func(ctx context.Context, window Window) ([]Proposal, error) {
		for _, err := range window.Events(ctx, "auth_events") {
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"),
		[2]string{"maxRows: 1000000", "maxRows: 1"})
	start, end := fixture.window()
	fixture.registerDataset(t, "auth_events")
	fixture.writeBatch(t, "auth_events", end, []dataset.Record{
		testRecord("1", start.Add(time.Minute), udm.EventTypeUserLogin),
		testRecord("2", start.Add(2*time.Minute), udm.EventTypeUserLogin),
	})

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want a recorded run", err)
	}

	if result.Status != RunStatusFailed || !strings.Contains(result.Error, "row budget exceeded") {
		t.Fatalf("RunWindow() result = %+v, want FAILED with the row budget error", result)
	}
	if result.RowsRead != 1 {
		t.Fatalf("RunWindow() rows read = %d, want 1", result.RowsRead)
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 || runs[0].RowsRead != 1 || runs[0].Status != string(RunStatusFailed) {
		t.Fatalf("detection_runs = %+v, want one FAILED row with 1 row read", runs)
	}
}

func TestRunWindowWritesRunAndProposalsInOneTransaction(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{runnerProposal(window.Start)}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	fixture.markReady(t, "auth_events")

	callback := "test:fail_detection_proposals"
	err := fixture.database.Callback().Create().Before("gorm:create").Register(callback, func(transaction *gorm.DB) {
		if transaction.Statement.Schema != nil && transaction.Statement.Schema.Table == "detection_proposals" {
			_ = transaction.AddError(errors.New("forced proposal insert failure"))
		}
	})
	if err != nil {
		t.Fatalf("register GORM callback: %v", err)
	}
	t.Cleanup(func() {
		if err := fixture.database.Callback().Create().Remove(callback); err != nil {
			t.Errorf("remove GORM callback: %v", err)
		}
	})

	result, err := fixture.run(t)

	if err == nil || !strings.Contains(err.Error(), "forced proposal insert failure") {
		t.Fatalf("RunWindow() error = %v, want the forced proposal failure", err)
	}
	if !zeroRunResult(result) {
		t.Fatalf("RunWindow() result = %+v, want the zero result when no run row was written", result)
	}
	if count := countRows(t, fixture.database, &runRow{}); count != 0 {
		t.Fatalf("detection_runs rows = %d, want the transaction rolled back", count)
	}
}
