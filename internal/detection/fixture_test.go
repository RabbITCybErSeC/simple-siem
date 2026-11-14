package detection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

var (
	fixtureStart = time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	fixtureEnd   = time.Date(2026, 5, 11, 10, 15, 0, 0, time.UTC)
)

type stubDetection func(ctx context.Context, window Window) ([]Proposal, error)

func (stub stubDetection) Evaluate(ctx context.Context, window Window) ([]Proposal, error) {
	return stub(ctx, window)
}

func writeFixtureFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// fixtureBody is one window with one BLOCK login event. expectProposal is the
// JSON of the single expected proposal, or empty for none.
func fixtureBody(expectProposal string) string {
	return fmt.Sprintf(`{
  "window": {"start": "2026-05-11T10:00:00Z", "end": "2026-05-11T10:15:00Z"},
  "datasets": {
    "auth_events": [
      {
        "sourceKey": {"fetcherInstanceId": "fixture", "index": "auth", "documentId": "1"},
        "event": {
          "metadata": {"event_timestamp": "2026-05-11T10:01:00Z", "event_type": "USER_LOGIN"},
          "target": {"user": {"userid": "alice"}, "hostname": "web01"},
          "principal": {"ip": ["203.0.113.7"]},
          "security_result": {"action": "BLOCK"}
        }
      }
    ]
  },
  "expect": {"proposals": [%s]}
}`, expectProposal)
}

const expectedProposalJSON = `{"identity": {"target.user.userid": "alice", "target.hostname": "web01"}, "severity": "HIGH", "evidenceCount": 1}`

func TestLoadFixture(t *testing.T) {
	path := writeFixtureFile(t, fixtureBody(expectedProposalJSON))

	fixture, err := LoadFixture(path)
	if err != nil {
		t.Fatalf("LoadFixture() error = %v, want nil", err)
	}

	if !fixture.Window.Start.Equal(fixtureStart) || !fixture.Window.End.Equal(fixtureEnd) {
		t.Fatalf("fixture window = [%s, %s), want [%s, %s)", fixture.Window.Start, fixture.Window.End, fixtureStart, fixtureEnd)
	}
	records := fixture.Datasets["auth_events"]
	if len(records) != 1 {
		t.Fatalf("fixture auth_events records = %d, want 1", len(records))
	}
	record := records[0]
	if record.Key.DocumentID != "1" || record.Key.FetcherInstanceID != "fixture" || record.Key.Index != "auth" {
		t.Fatalf("fixture source key = %+v, want the file's sourceKey", record.Key)
	}
	if !record.EventTime.Equal(time.Date(2026, 5, 11, 10, 1, 0, 0, time.UTC)) {
		t.Fatalf("fixture record event time = %s, want the event's metadata.event_timestamp", record.EventTime)
	}
	if record.Event.Target.User.UserID != "alice" || record.Event.SecurityResult.Action != udm.ActionBlock {
		t.Fatalf("fixture record event = %+v, want alice's BLOCK event", record.Event)
	}
	if len(fixture.Expect.Proposals) != 1 {
		t.Fatalf("fixture expected proposals = %d, want 1", len(fixture.Expect.Proposals))
	}
	expected := fixture.Expect.Proposals[0]
	if expected.Severity != SeverityHigh || expected.EvidenceCount != 1 {
		t.Fatalf("fixture expected proposal = %+v, want HIGH with 1 evidence", expected)
	}
	if expected.Identity["target.user.userid"] == nil || *expected.Identity["target.user.userid"] != "alice" {
		t.Fatalf("fixture expected identity = %v, want target.user.userid=alice", expected.Identity)
	}
}

func TestLoadFixtureErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "unknown field",
			body: strings.Replace(fixtureBody(expectedProposalJSON), `"window":`, `"timeWindow":`, 1),
			want: []string{"unknown field", "timeWindow"},
		},
		{
			name: "invalid event",
			body: strings.Replace(fixtureBody(expectedProposalJSON), `"action": "BLOCK"`, `"action": "allow"`, 1),
			want: []string{"dataset auth_events[0]", "security_result.action", "allow"},
		},
		{
			name: "missing event timestamp",
			body: strings.Replace(fixtureBody(expectedProposalJSON), `"event_timestamp": "2026-05-11T10:01:00Z", `, "", 1),
			want: []string{"metadata.event_timestamp", "required"},
		},
		{
			name: "invalid window",
			body: strings.Replace(fixtureBody(expectedProposalJSON), `"start": "2026-05-11T10:00:00Z", "end": "2026-05-11T10:15:00Z"`, `"start": "2026-05-11T10:15:00Z", "end": "2026-05-11T10:00:00Z"`, 1),
			want: []string{"window.start", "before", "window.end"},
		},
		{
			name: "malformed json",
			body: `{"window":`,
			want: []string{"fixture"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeFixtureFile(t, test.body)

			_, err := LoadFixture(path)

			if err == nil {
				t.Fatalf("LoadFixture() error = nil, want an error containing %q", test.want)
			}
			for _, want := range test.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("LoadFixture() error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestLoadFixtureMissingFile(t *testing.T) {
	_, err := LoadFixture(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "absent.json") {
		t.Fatalf("LoadFixture() error = %v, want an error naming the missing file", err)
	}
}

func TestEvaluateFixtureRejectsUndeclaredDataset(t *testing.T) {
	manifest := parseManifest(t)
	body := strings.Replace(fixtureBody(""), `"auth_events"`, `"auth_event"`, 1)
	path := writeFixtureFile(t, body)
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) {
		return nil, nil
	})

	_, err := EvaluateFixture(Registration{Manifest: manifestYAML(t), Logic: logic}, manifest, path)

	if err == nil {
		t.Fatal("EvaluateFixture() error = nil, want the undeclared dataset rejection")
	}
	if !strings.Contains(err.Error(), "auth_event") {
		t.Fatalf("EvaluateFixture() error = %q, want it to name auth_event", err)
	}
	if !strings.Contains(err.Error(), "not a declared input") {
		t.Fatalf("EvaluateFixture() error = %q, want the undeclared input message", err)
	}
}

func TestEvaluateFixturePasses(t *testing.T) {
	manifest := parseManifest(t)
	path := writeFixtureFile(t, fixtureBody(expectedProposalJSON))
	logic := stubDetection(func(ctx context.Context, window Window) ([]Proposal, error) {
		var evidence []Evidence
		for record, err := range window.Events(ctx, "auth_events") {
			if err != nil {
				return nil, err
			}
			evidence = append(evidence, EvidenceOf(record))
		}
		return []Proposal{{
			Subject:  identitySubject("alice", "web01", ""),
			Summary:  "failed logon",
			Evidence: evidence,
		}}, nil
	})

	result, err := EvaluateFixture(Registration{Manifest: manifestYAML(t), Logic: logic}, manifest, path)
	if err != nil {
		t.Fatalf("EvaluateFixture() error = %v, want nil", err)
	}

	if !result.Passed {
		t.Fatalf("EvaluateFixture() differences = %v, want a pass", result.Differences)
	}
	if len(result.Proposals) != 1 {
		t.Fatalf("EvaluateFixture() proposals = %d, want 1", len(result.Proposals))
	}
	if result.Proposals[0].Severity != SeverityHigh {
		t.Fatalf("EvaluateFixture() severity = %q, want the manifest default HIGH", result.Proposals[0].Severity)
	}
}

func TestEvaluateFixtureComparesProposals(t *testing.T) {
	manifest := parseManifest(t)
	subject := identitySubject("alice", "web01", "")
	evidence := []Evidence{{SourceKey: dataset.SourceKey{FetcherInstanceID: "fixture", Index: "auth", DocumentID: "1"}, EventTime: fixtureStart.Add(time.Minute)}}

	tests := []struct {
		name     string
		expected string
		proposal *Proposal
		want     []string
	}{
		{
			name:     "identity mismatch",
			expected: `{"identity": {"target.user.userid": "bob"}, "severity": "HIGH", "evidenceCount": 1}`,
			proposal: &Proposal{Subject: subject, Summary: "s", Evidence: evidence},
			want:     []string{"proposal 1", "target.user.userid", "alice", "bob"},
		},
		{
			name:     "severity mismatch",
			expected: `{"identity": {"target.user.userid": "alice"}, "severity": "LOW", "evidenceCount": 1}`,
			proposal: &Proposal{Subject: subject, Summary: "s", Severity: SeverityHigh, Evidence: evidence},
			want:     []string{"proposal 1", "severity", "HIGH", "LOW"},
		},
		{
			name:     "evidence count mismatch",
			expected: `{"identity": {"target.user.userid": "alice"}, "severity": "HIGH", "evidenceCount": 2}`,
			proposal: &Proposal{Subject: subject, Summary: "s", Evidence: evidence},
			want:     []string{"proposal 1", "evidence count", "1", "2"},
		},
		{
			name:     "proposal count mismatch",
			expected: `{"identity": {"target.user.userid": "alice"}, "severity": "HIGH", "evidenceCount": 1}`,
			proposal: nil,
			want:     []string{"proposal count", "0", "1"},
		},
		{
			name:     "only listed identity paths are compared",
			expected: `{"identity": {"target.user.userid": "alice"}, "severity": "HIGH", "evidenceCount": 1}`,
			proposal: &Proposal{Subject: identitySubject("alice", "other-host", ""), Summary: "s", Evidence: evidence},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeFixtureFile(t, fixtureBody(test.expected))
			logic := stubDetection(func(context.Context, Window) ([]Proposal, error) {
				if test.proposal == nil {
					return nil, nil
				}
				return []Proposal{*test.proposal}, nil
			})

			result, err := EvaluateFixture(Registration{Manifest: manifestYAML(t), Logic: logic}, manifest, path)
			if err != nil {
				t.Fatalf("EvaluateFixture() error = %v, want nil", err)
			}

			if len(test.want) == 0 {
				if !result.Passed {
					t.Fatalf("EvaluateFixture() differences = %v, want a pass", result.Differences)
				}
				return
			}
			if result.Passed {
				t.Fatalf("EvaluateFixture() passed, want differences containing %q", test.want)
			}
			differences := strings.Join(result.Differences, "\n")
			for _, want := range test.want {
				if !strings.Contains(differences, want) {
					t.Fatalf("EvaluateFixture() differences = %q, want them to contain %q", differences, want)
				}
			}
		})
	}
}

func TestEvaluateFixtureReportsEvaluationFailures(t *testing.T) {
	manifest := parseManifest(t)
	path := writeFixtureFile(t, fixtureBody(expectedProposalJSON))

	tests := []struct {
		name  string
		logic Detection
		want  string
	}{
		{
			name:  "panic",
			logic: stubDetection(func(context.Context, Window) ([]Proposal, error) { panic("kaboom") }),
			want:  "panic: kaboom",
		},
		{
			name:  "error",
			logic: stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, errors.New("boom") }),
			want:  "boom",
		},
		{
			name: "invalid proposal",
			logic: stubDetection(func(context.Context, Window) ([]Proposal, error) {
				return []Proposal{{Evidence: []Evidence{{EventTime: fixtureStart}}}}, nil
			}),
			want: "summary is empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := EvaluateFixture(Registration{Manifest: manifestYAML(t), Logic: test.logic}, manifest, path)
			if err != nil {
				t.Fatalf("EvaluateFixture() error = %v, want nil", err)
			}
			if result.Passed {
				t.Fatalf("EvaluateFixture() passed, want a failure containing %q", test.want)
			}
			if differences := strings.Join(result.Differences, "\n"); !strings.Contains(differences, test.want) {
				t.Fatalf("EvaluateFixture() differences = %q, want them to contain %q", differences, test.want)
			}
		})
	}
}

func TestEvaluateFixtureHonorsDeadline(t *testing.T) {
	manifest := parseManifest(t, [2]string{"timeout: 30s", "timeout: 50ms"})
	path := writeFixtureFile(t, fixtureBody(""))
	logic := stubDetection(func(ctx context.Context, _ Window) ([]Proposal, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	started := time.Now()
	result, err := EvaluateFixture(Registration{Manifest: manifestYAML(t, [2]string{"timeout: 30s", "timeout: 50ms"}), Logic: logic}, manifest, path)
	elapsed := time.Since(started)

	if err != nil {
		t.Fatalf("EvaluateFixture() error = %v, want nil", err)
	}
	if result.Passed {
		t.Fatal("EvaluateFixture() passed, want a timeout failure")
	}
	if differences := strings.Join(result.Differences, "\n"); !strings.Contains(differences, "TIMED_OUT") {
		t.Fatalf("EvaluateFixture() differences = %q, want TIMED_OUT", differences)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("EvaluateFixture() took %s, want about the 50ms deadline", elapsed)
	}
}

func validProposal() Proposal {
	return Proposal{
		Subject:  identitySubject("alice", "web01", ""),
		Summary:  "10 failed logons, then a success",
		Details:  map[string]string{"failed_attempts": "10"},
		Evidence: []Evidence{{SourceKey: dataset.SourceKey{FetcherInstanceID: "fixture", Index: "auth", DocumentID: "1"}, EventTime: fixtureStart.Add(time.Minute)}},
	}
}

func TestCheckProposals(t *testing.T) {
	manifest := parseManifest(t)
	window := Window{Start: fixtureStart, End: fixtureEnd}

	tests := []struct {
		name         string
		manifest     config.DetectionManifest
		proposals    []Proposal
		want         string
		wantSeverity Severity
	}{
		{
			name:         "valid proposals pass and take the manifest severity",
			proposals:    []Proposal{validProposal()},
			wantSeverity: SeverityHigh,
		},
		{
			name:      "too many proposals",
			manifest:  parseManifest(t, [2]string{"maxProposals: 100", "maxProposals: 1"}),
			proposals: []Proposal{validProposal(), validProposal()},
			want:      "proposal count 2 exceeds budget 1",
		},
		{
			name:      "empty summary",
			proposals: []Proposal{withSummary(validProposal(), "   ")},
			want:      "summary is empty",
		},
		{
			name:      "summary too long",
			proposals: []Proposal{withSummary(validProposal(), strings.Repeat("a", 501))},
			want:      "summary is longer than 500 bytes",
		},
		{
			name: "no evidence",
			proposals: []Proposal{func() Proposal {
				proposal := validProposal()
				proposal.Evidence = nil
				return proposal
			}()},
			want: "evidence is empty",
		},
		{
			name:     "too much evidence",
			manifest: parseManifest(t, [2]string{"maxEvidencePerProposal: 1000", "maxEvidencePerProposal: 1"}),
			proposals: []Proposal{func() Proposal {
				proposal := validProposal()
				proposal.Evidence = append(proposal.Evidence, Evidence{EventTime: fixtureStart.Add(2 * time.Minute)})
				return proposal
			}()},
			want: "evidence count 2 exceeds budget 1",
		},
		{
			name: "evidence before the window",
			proposals: []Proposal{func() Proposal {
				proposal := validProposal()
				proposal.Evidence[0].EventTime = fixtureStart.Add(-time.Second)
				return proposal
			}()},
			want: "outside the window",
		},
		{
			name: "evidence at the window end is outside",
			proposals: []Proposal{func() Proposal {
				proposal := validProposal()
				proposal.Evidence[0].EventTime = fixtureEnd
				return proposal
			}()},
			want: "outside the window",
		},
		{
			name: "invalid severity",
			proposals: []Proposal{func() Proposal {
				proposal := validProposal()
				proposal.Severity = "CRITICAL"
				return proposal
			}()},
			want: "invalid severity",
		},
		{
			name: "explicit severity is kept",
			proposals: []Proposal{func() Proposal {
				proposal := validProposal()
				proposal.Severity = SeverityLow
				return proposal
			}()},
			wantSeverity: SeverityLow,
		},
		{
			name: "too many details",
			proposals: []Proposal{func() Proposal {
				proposal := validProposal()
				proposal.Details = make(map[string]string, 51)
				for index := 0; index < 51; index++ {
					proposal.Details[fmt.Sprintf("key-%d", index)] = "value"
				}
				return proposal
			}()},
			want: "details has 51 entries",
		},
		{
			name: "detail value too long",
			proposals: []Proposal{func() Proposal {
				proposal := validProposal()
				proposal.Details = map[string]string{"failed_attempts": strings.Repeat("a", 1025)}
				return proposal
			}()},
			want: "longer than 1024 bytes",
		},
		{
			name: "missing required identity",
			proposals: []Proposal{func() Proposal {
				proposal := validProposal()
				proposal.Subject = identitySubject("", "web01", "")
				return proposal
			}()},
			want: "target.user.userid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testManifest := manifest
			if test.manifest.ID != "" {
				testManifest = test.manifest
			}

			checked, err := checkProposals(testManifest, window, test.proposals)

			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("checkProposals() error = %v, want an error containing %q", err, test.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkProposals() error = %v, want nil", err)
			}
			if len(checked) != len(test.proposals) {
				t.Fatalf("checkProposals() proposals = %d, want %d", len(checked), len(test.proposals))
			}
			if checked[0].Severity != test.wantSeverity {
				t.Fatalf("checkProposals() severity = %q, want %q", checked[0].Severity, test.wantSeverity)
			}
		})
	}
}

func withSummary(proposal Proposal, summary string) Proposal {
	proposal.Summary = summary
	return proposal
}

func TestEvaluateIsolation(t *testing.T) {
	window := Window{
		Start:    fixtureStart,
		End:      fixtureEnd,
		Revision: 1,
		reader: newFixtureReader(map[string][]dataset.Record{
			"auth_events": {
				testRecord("1", fixtureStart.Add(time.Minute), udm.EventTypeUserLogin),
				testRecord("2", fixtureStart.Add(2*time.Minute), udm.EventTypeUserLogin),
			},
		}),
		inputs: map[string][]udm.EventType{"auth_events": {udm.EventTypeUserLogin}},
		budget: newRowBudget(100),
	}

	tests := []struct {
		name     string
		manifest config.DetectionManifest
		logic    Detection
		want     RunStatus
		wantErr  string
	}{
		{
			name:  "success",
			logic: stubDetection(func(context.Context, Window) ([]Proposal, error) { return []Proposal{validProposal()}, nil }),
			want:  RunStatusOK,
		},
		{
			name:    "evaluation error",
			logic:   stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, errors.New("boom") }),
			want:    RunStatusFailed,
			wantErr: "boom",
		},
		{
			name:    "panic",
			logic:   stubDetection(func(context.Context, Window) ([]Proposal, error) { panic("kaboom") }),
			want:    RunStatusFailed,
			wantErr: "panic: kaboom",
		},
		{
			name:    "nil logic",
			want:    RunStatusFailed,
			wantErr: "logic",
		},
		{
			name:     "deadline while blocking on the context",
			manifest: parseManifest(t, [2]string{"timeout: 30s", "timeout: 50ms"}),
			logic: stubDetection(func(ctx context.Context, _ Window) ([]Proposal, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}),
			want:    RunStatusTimedOut,
			wantErr: "timed out",
		},
		{
			name:     "deadline while ignoring the context",
			manifest: parseManifest(t, [2]string{"timeout: 30s", "timeout: 50ms"}),
			logic: stubDetection(func(context.Context, Window) ([]Proposal, error) {
				var never chan struct{}
				<-never
				return nil, nil
			}),
			want:    RunStatusTimedOut,
			wantErr: "timed out",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testManifest := parseManifest(t)
			if test.manifest.ID != "" {
				testManifest = test.manifest
			}

			started := time.Now()
			result := evaluate(context.Background(), testManifest, test.logic, window)
			elapsed := time.Since(started)

			if result.status != test.want {
				t.Fatalf("evaluate() status = %s, want %s (error %v)", result.status, test.want, result.err)
			}
			if test.wantErr != "" {
				if result.err == nil || !strings.Contains(result.err.Error(), test.wantErr) {
					t.Fatalf("evaluate() error = %v, want an error containing %q", result.err, test.wantErr)
				}
			}
			if test.want == RunStatusTimedOut && elapsed > 2*time.Second {
				t.Fatalf("evaluate() took %s, want about the 50ms deadline", elapsed)
			}
		})
	}
}

func TestEvaluateHonorsRowBudget(t *testing.T) {
	manifest := parseManifest(t, [2]string{"maxRows: 1000000", "maxRows: 1"})
	window := Window{
		Start:    fixtureStart,
		End:      fixtureEnd,
		Revision: 1,
		reader: newFixtureReader(map[string][]dataset.Record{
			"auth_events": {
				testRecord("1", fixtureStart.Add(time.Minute), udm.EventTypeUserLogin),
				testRecord("2", fixtureStart.Add(2*time.Minute), udm.EventTypeUserLogin),
			},
		}),
		inputs: map[string][]udm.EventType{"auth_events": {udm.EventTypeUserLogin}},
		budget: newRowBudget(manifest.Budgets.MaxRows),
	}
	logic := stubDetection(func(ctx context.Context, window Window) ([]Proposal, error) {
		for _, err := range window.Events(ctx, "auth_events") {
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})

	result := evaluate(context.Background(), manifest, logic, window)

	if result.status != RunStatusFailed {
		t.Fatalf("evaluate() status = %s, want FAILED", result.status)
	}
	if !errors.Is(result.err, ErrRowBudgetExceeded) {
		t.Fatalf("evaluate() error = %v, want ErrRowBudgetExceeded", result.err)
	}
}

func TestEvaluateParentCancellationIsFailed(t *testing.T) {
	manifest := parseManifest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	window := Window{Start: fixtureStart, End: fixtureEnd, reader: newFixtureReader(nil), inputs: map[string][]udm.EventType{}, budget: newRowBudget(10)}
	logic := stubDetection(func(ctx context.Context, _ Window) ([]Proposal, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	result := evaluate(ctx, manifest, logic, window)

	if result.status != RunStatusFailed {
		t.Fatalf("evaluate() status = %s, want FAILED for a canceled parent", result.status)
	}
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("evaluate() error = %v, want context.Canceled", result.err)
	}
}
