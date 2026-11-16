package detection

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/alerts"
	"github.com/RabbITCybErSeC/simple-siem/internal/cases"
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

// alertTableRow counts alerts; the detection package has no alert model.
type alertTableRow struct {
	ID string `gorm:"column:id"`
}

func (alertTableRow) TableName() string {
	return "alerts"
}

// guardrailHook trips the guardrail on the first created alert.
type guardrailHook struct {
	tripped bool
}

func (hook *guardrailHook) AlertCreated(context.Context, *gorm.DB, alerts.NewAlert) (alerts.CaseOutcome, error) {
	if hook.tripped {
		return alerts.CaseOutcome{}, nil
	}
	hook.tripped = true
	return alerts.CaseOutcome{GuardrailTripped: true}, nil
}

func (hook *guardrailHook) EvidenceAdded(context.Context, *gorm.DB, string, time.Time, int) error {
	return nil
}

// failingHook makes AlertCreated fail.
type failingHook struct {
	err error
}

func (hook failingHook) AlertCreated(context.Context, *gorm.DB, alerts.NewAlert) (alerts.CaseOutcome, error) {
	return alerts.CaseOutcome{}, hook.err
}

func (hook failingHook) EvidenceAdded(context.Context, *gorm.DB, string, time.Time, int) error {
	return nil
}

// recordingHook records created alerts in call order.
type recordingHook struct {
	created []alerts.NewAlert
}

func (hook *recordingHook) AlertCreated(_ context.Context, _ *gorm.DB, alert alerts.NewAlert) (alerts.CaseOutcome, error) {
	hook.created = append(hook.created, alert)
	return alerts.CaseOutcome{}, nil
}

func (hook *recordingHook) EvidenceAdded(context.Context, *gorm.DB, string, time.Time, int) error {
	return nil
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
			Alerts:   &alerts.Service{},
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

func (fixture *runnerFixture) insertRun(t *testing.T, revision int) string {
	t.Helper()
	start, end := fixture.window()
	run := runRow{
		DetectionID:      fixture.manifest.ID,
		DetectionVersion: fixture.manifest.Version,
		Status:           string(RunStatusOK),
		WindowStart:      start,
		WindowEnd:        end,
		Revision:         revision,
		Mode:             string(RunModeShadow),
		StartedAt:        time.Now().UTC(),
	}
	if err := fixture.database.Create(&run).Error; err != nil {
		t.Fatalf("insert detection run %d: %v", revision, err)
	}
	return run.ID
}

func (fixture *runnerFixture) run(t *testing.T) (RunResult, error) {
	t.Helper()
	return fixture.runner.RunWindow(context.Background(), fixture.registration, fixture.end, RunOptions{})
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

// enableDetection makes the test manifest start ENABLED.
var enableDetection = [2]string{"severity: HIGH", "severity: HIGH\ninitialStatus: ENABLED"}

func proposalAt(userID, hostname, documentID string, eventTime time.Time) Proposal {
	return Proposal{
		Subject:  identitySubject(userID, hostname, ""),
		Summary:  "brute force",
		Details:  map[string]string{"failed_attempts": "10"},
		Severity: SeverityHigh,
		Evidence: []Evidence{{
			SourceKey: dataset.SourceKey{FetcherInstanceID: "fixture", Index: "auth", DocumentID: documentID},
			EventTime: eventTime,
		}},
	}
}

func detectionRuntimeRow(t *testing.T, db *gorm.DB, detectionID string) (status string, version int) {
	t.Helper()
	var row struct {
		Status  string `gorm:"column:status"`
		Version int    `gorm:"column:version"`
	}
	err := db.Raw("SELECT status, version FROM detection_runtime WHERE detection_id = ?", detectionID).Scan(&row).Error
	if err != nil {
		t.Fatalf("read detection runtime %q: %v", detectionID, err)
	}
	return row.Status, row.Version
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

func TestRunWindowSerializesConcurrentRuns(t *testing.T) {
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) {
		// Holding inside evaluation widens the gap between the revision read
		// and the insert, which made the pre-fix collision reliable; the run
		// lock now serialises the two runs, so this only delays them in turn.
		time.Sleep(50 * time.Millisecond)
		return nil, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	fixture.markReady(t, "auth_events")

	type outcome struct {
		result RunResult
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	for range 2 {
		go func() {
			<-start
			result, err := fixture.runner.RunWindow(context.Background(), fixture.registration, fixture.end, RunOptions{})
			outcomes <- outcome{result: result, err: err}
		}()
	}
	close(start)

	revisions := make([]int, 0, 2)
	for range 2 {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf("RunWindow() error = %v, want both runs recorded", outcome.err)
		}
		revisions = append(revisions, outcome.result.Revision)
	}
	slices.Sort(revisions)
	if !slices.Equal(revisions, []int{1, 2}) {
		t.Fatalf("result revisions = %v, want [1 2]", revisions)
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 2 || runs[0].Revision != 1 || runs[1].Revision != 2 {
		t.Fatalf("detection_runs = %+v, want revisions 1 and 2", runs)
	}
}

// pausedCaseHook passes calls to the real case service and holds run A after
// its first alert, so a second run can start applying while A still holds the
// rows every identity of the detection shares.
type pausedCaseHook struct {
	inner      *cases.Service
	pauseAfter string
	paused     chan struct{}
	resume     chan struct{}
}

func (hook *pausedCaseHook) AlertCreated(ctx context.Context, tx *gorm.DB, alert alerts.NewAlert) (alerts.CaseOutcome, error) {
	outcome, err := hook.inner.AlertCreated(ctx, tx, alert)
	if err != nil {
		return alerts.CaseOutcome{}, err
	}
	if alert.IdentityHash == hook.pauseAfter {
		close(hook.paused)
		select {
		case <-hook.resume:
		case <-ctx.Done():
		}
	}
	return outcome, nil
}

func (hook *pausedCaseHook) EvidenceAdded(ctx context.Context, tx *gorm.DB, alertID string, lastEventAt time.Time, added int) error {
	return hook.inner.EvidenceAdded(ctx, tx, alertID, lastEventAt, added)
}

func TestConcurrentApplyOfOneDetectionCommitsBoth(t *testing.T) {
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, nil })
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	if err := fixture.database.Exec(`
		WITH analyst AS (
			INSERT INTO users (email, display_name, on_call)
			VALUES ('oncall@example.com', 'on call', true)
			RETURNING id
		)
		INSERT INTO user_roles (user_id, role_name)
		SELECT id, 'ANALYST' FROM analyst`).Error; err != nil {
		t.Fatalf("insert the on-call analyst: %v", err)
	}

	start, _ := fixture.window()
	runA := fixture.insertRun(t, 1)
	runB := fixture.insertRun(t, 2)

	firstUser, firstHost := "alice", "web01"
	secondUser, secondHost := "bob", "dc01"
	firstIdentity, err := ComputeIdentity(fixture.manifest.ID, fixture.manifest.Alerting, identitySubject(firstUser, firstHost, ""))
	if err != nil {
		t.Fatalf("compute the first identity: %v", err)
	}
	secondIdentity, err := ComputeIdentity(fixture.manifest.ID, fixture.manifest.Alerting, identitySubject(secondUser, secondHost, ""))
	if err != nil {
		t.Fatalf("compute the second identity: %v", err)
	}
	if firstIdentity.Hash > secondIdentity.Hash {
		firstUser, firstHost, secondUser, secondHost = secondUser, secondHost, firstUser, firstHost
		firstIdentity, secondIdentity = secondIdentity, firstIdentity
	}

	proposalA := proposalAt(firstUser, firstHost, "run-a-alert-a", start.Add(time.Minute))
	proposalB := proposalAt(secondUser, secondHost, "run-a-alert-b", start.Add(2*time.Minute))
	proposalBAgain := proposalAt(secondUser, secondHost, "run-b-alert-b", start.Add(3*time.Minute))

	hook := &pausedCaseHook{
		inner:      cases.NewService(fixture.database, "http://localhost", 1000),
		pauseAfter: firstIdentity.Hash,
		paused:     make(chan struct{}),
		resume:     make(chan struct{}),
	}
	fixture.runner.Alerts = &alerts.Service{Hooks: hook}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type applyOutcome struct {
		applied appliedProposals
		err     error
	}
	startApply := func(runID string, proposals []Proposal) <-chan applyOutcome {
		outcomes := make(chan applyOutcome, 1)
		go func() {
			var applied appliedProposals
			err := fixture.database.Transaction(func(transaction *gorm.DB) error {
				if err := alerts.LockDetection(transaction, fixture.manifest.ID); err != nil {
					return err
				}
				var applyErr error
				applied, applyErr = fixture.runner.applyEnabledProposals(
					ctx, transaction, fixture.manifest, runID, proposals)
				return applyErr
			})
			outcomes <- applyOutcome{applied: applied, err: err}
		}()
		return outcomes
	}
	runAOutcome := startApply(runA, []Proposal{proposalA, proposalB})

	select {
	case <-hook.paused:
	case <-ctx.Done():
		t.Fatalf("run A did not pause after creating its first alert: %v", ctx.Err())
	}

	runBOutcome := startApply(runB, []Proposal{proposalBAgain})

	// Wait until run B blocks, so releasing run A forces the interleaving.
	waitDeadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		err := fixture.database.Raw(
			"SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()",
		).Scan(&waiting).Error
		if err != nil {
			t.Fatalf("read the waiting locks: %v", err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(waitDeadline) {
			t.Fatal("run B never waited on a lock")
		}
		time.Sleep(20 * time.Millisecond)
	}

	close(hook.resume)

	collect := func(outcomes <-chan applyOutcome, name string) applyOutcome {
		select {
		case outcome := <-outcomes:
			return outcome
		case <-ctx.Done():
			t.Fatalf("%s did not finish: %v", name, ctx.Err())
			return applyOutcome{}
		}
	}
	outcomeA := collect(runAOutcome, "run A")
	outcomeB := collect(runBOutcome, "run B")
	if outcomeA.err != nil || outcomeB.err != nil {
		t.Fatalf("apply errors: run A = %v, run B = %v; want both transactions to commit", outcomeA.err, outcomeB.err)
	}
	if outcomeB.applied.merged+outcomeB.applied.deduplicated != 1 {
		t.Errorf("run B applied = %+v, want one merged or no-op proposal", outcomeB.applied)
	}

	var openForSecond int64
	err = fixture.database.Raw(`
		SELECT count(*) FROM alerts
		WHERE detection_id = ? AND identity_hash = ? AND status = 'OPEN' AND coalescing`,
		fixture.manifest.ID, secondIdentity.Hash).Scan(&openForSecond).Error
	if err != nil {
		t.Fatalf("count the open coalescing alerts: %v", err)
	}
	if openForSecond != 1 {
		t.Errorf("open coalescing alerts for identity b = %d, want exactly 1", openForSecond)
	}
}

func TestDifferentDetectionsDoNotWait(t *testing.T) {
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, nil })
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	start, _ := fixture.window()
	runID := fixture.insertRun(t, 1)

	held := fixture.database.Begin()
	if held.Error != nil {
		t.Fatalf("begin the held transaction: %v", held.Error)
	}
	defer func() {
		if err := held.Rollback().Error; err != nil {
			t.Errorf("roll back the held transaction: %v", err)
		}
	}()
	if err := alerts.LockDetection(held, "detection-one"); err != nil {
		t.Fatalf("hold the first detection's lock: %v", err)
	}

	proposal := proposalAt("alice", "web01", "another-detection-alert", start.Add(time.Minute))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := fixture.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := alerts.LockDetection(transaction, fixture.manifest.ID); err != nil {
			return err
		}
		_, err := fixture.runner.applyEnabledProposals(
			ctx, transaction, fixture.manifest, runID, []Proposal{proposal})
		return err
	})
	if err != nil {
		t.Fatalf("apply the second detection: %v", err)
	}
}

func TestEmptyApplyDoesNotWaitForTheDetectionLock(t *testing.T) {
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) { return nil, nil })
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), enableDetection)
	fixture.markReady(t, "auth_events")

	held := fixture.database.Begin()
	if held.Error != nil {
		t.Fatalf("begin the held transaction: %v", held.Error)
	}
	defer func() {
		if err := held.Rollback().Error; err != nil {
			t.Errorf("roll back the held transaction: %v", err)
		}
	}()
	if err := alerts.LockDetection(held, fixture.manifest.ID); err != nil {
		t.Fatalf("hold the detection's lock: %v", err)
	}

	type runOutcome struct {
		result RunResult
		err    error
	}
	outcomes := make(chan runOutcome, 1)
	go func() {
		result, err := fixture.runner.RunWindow(context.Background(), fixture.registration, fixture.end, RunOptions{})
		outcomes <- runOutcome{result: result, err: err}
	}()

	// RunWindow survives caller cancellation, so bound the wait here.
	select {
	case outcome := <-outcomes:
		if outcome.err != nil {
			t.Fatalf("RunWindow() error = %v, want a recorded run", outcome.err)
		}
		if outcome.result.Mode != RunModeEnabled || outcome.result.AlertsCreated != 0 || outcome.result.Proposals != 0 {
			t.Errorf("empty run result = %+v, want ENABLED with no alerts or proposals", outcome.result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an empty run waited for the detection lock")
	}
}

func TestRunWindowWaitsForTheWindowLockOutsideItsBudget(t *testing.T) {
	// Two runs of one window, each using most of the 6s budget. The waiter
	// must not pay for the lock wait out of its own evaluation budget, or its
	// insert lands after the transaction deadline and no row is left behind.
	const evaluationTime = 5800 * time.Millisecond
	logic := stubDetection(func(context.Context, Window) ([]Proposal, error) {
		time.Sleep(evaluationTime)
		return nil, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"),
		[2]string{"timeout: 30s", "timeout: 6s"})
	fixture.markReady(t, "auth_events")

	type outcome struct {
		result RunResult
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan outcome, 2)
	for range 2 {
		go func() {
			<-start
			result, err := fixture.runner.RunWindow(context.Background(), fixture.registration, fixture.end, RunOptions{})
			outcomes <- outcome{result: result, err: err}
		}()
	}
	close(start)

	revisions := make([]int, 0, 2)
	for range 2 {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf("RunWindow() error = %v, want both runs recorded", outcome.err)
		}
		revisions = append(revisions, outcome.result.Revision)
	}
	slices.Sort(revisions)
	if !slices.Equal(revisions, []int{1, 2}) {
		t.Fatalf("result revisions = %v, want [1 2]", revisions)
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

			_, err := fixture.runner.RunWindow(context.Background(), fixture.registration, test.windowEnd(fixture), RunOptions{})

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

func TestRunWindowRecordsCanceledRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	logic := stubDetection(func(ctx context.Context, _ Window) ([]Proposal, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	fixture.markReady(t, "auth_events")

	result, err := fixture.runner.RunWindow(ctx, fixture.registration, fixture.end, RunOptions{})
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want the FAILED run recorded", err)
	}

	if result.Status != RunStatusFailed || !strings.Contains(result.Error, context.Canceled.Error()) {
		t.Fatalf("RunWindow() result = %+v, want FAILED with context canceled", result)
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 || runs[0].Status != string(RunStatusFailed) {
		t.Fatalf("detection_runs = %+v, want one FAILED row", runs)
	}
	if runs[0].Error == nil || !strings.Contains(*runs[0].Error, context.Canceled.Error()) {
		t.Fatalf("run row error = %v, want the cancellation reason", runs[0].Error)
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

func TestRunWindowCreatesAlertsWhenEnabled(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{
			proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute)),
			proposalAt("bob", "dc01", "bob-1", window.Start.Add(2*time.Minute)),
		}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), enableDetection)
	fixture.markReady(t, "auth_events")

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want nil", err)
	}
	if result.Status != RunStatusOK {
		t.Fatalf("RunWindow() status = %s, want OK (error %q)", result.Status, result.Error)
	}
	if result.Mode != RunModeEnabled {
		t.Errorf("mode = %q, want ENABLED", result.Mode)
	}
	if result.AlertsCreated != 2 || result.AlertsMerged != 0 || result.ProposalsDeduplicated != 0 {
		t.Errorf("result counters = %d/%d/%d, want 2/0/0", result.AlertsCreated, result.AlertsMerged, result.ProposalsDeduplicated)
	}
	if result.Proposals != 2 {
		t.Errorf("proposals = %d, want 2", result.Proposals)
	}

	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 {
		t.Fatalf("detection_runs rows = %d, want 1", len(runs))
	}
	if runs[0].Mode != string(RunModeEnabled) || runs[0].AlertsCreated != 2 ||
		runs[0].AlertsMerged != 0 || runs[0].ProposalsDeduplicated != 0 {
		t.Errorf("run row = %+v, want ENABLED with 2 created", runs[0])
	}
	if got := countRows(t, fixture.database, &alertTableRow{}); got != 2 {
		t.Errorf("alerts = %d, want 2", got)
	}
	if got := countRows(t, fixture.database, &proposalRow{}); got != 0 {
		t.Errorf("detection_proposals = %d, want 0", got)
	}
	if status, _ := detectionRuntimeRow(t, fixture.database, fixture.manifest.ID); status != "ENABLED" {
		t.Errorf("runtime status = %q, want ENABLED", status)
	}
}

func TestRunWaitingForTheDetectionLockSeesTheNewStatus(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute))}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), enableDetection)
	fixture.markReady(t, "auth_events")
	if err := fixture.database.Transaction(func(transaction *gorm.DB) error {
		return alerts.EnsureRuntime(transaction, fixture.manifest.ID, "ENABLED")
	}); err != nil {
		t.Fatalf("create the detection runtime row: %v", err)
	}

	held := fixture.database.Begin()
	if held.Error != nil {
		t.Fatalf("begin the held transaction: %v", held.Error)
	}
	heldOpen := true
	defer func() {
		if heldOpen {
			if err := held.Rollback().Error; err != nil {
				t.Errorf("roll back the held transaction: %v", err)
			}
		}
	}()
	if err := alerts.LockDetection(held, fixture.manifest.ID); err != nil {
		t.Fatalf("hold the detection lock: %v", err)
	}

	type runOutcome struct {
		result RunResult
		err    error
	}
	outcomes := make(chan runOutcome, 1)
	go func() {
		result, err := fixture.runner.RunWindow(context.Background(), fixture.registration, fixture.end, RunOptions{})
		outcomes <- runOutcome{result: result, err: err}
	}()

	// Wait until the run blocks on the detection lock before releasing it.
	waitDeadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		err := fixture.database.Raw(
			"SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()",
		).Scan(&waiting).Error
		if err != nil {
			t.Fatalf("read the waiting locks: %v", err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(waitDeadline) {
			t.Fatal("the run never waited for the detection lock")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The run has read the old status and waits for the lock now. Switch the
	// detection before releasing the lock, as a run that trips the guardrail
	// commits its switch together with the lock release.
	if err := held.Exec(
		"UPDATE detection_runtime SET status = 'SHADOW' WHERE detection_id = ?", fixture.manifest.ID,
	).Error; err != nil {
		t.Fatalf("switch the detection to SHADOW: %v", err)
	}
	if err := held.Commit().Error; err != nil {
		t.Fatalf("commit the status switch: %v", err)
	}
	heldOpen = false

	select {
	case outcome := <-outcomes:
		if outcome.err != nil {
			t.Fatalf("RunWindow() error = %v, want a recorded run", outcome.err)
		}
		if outcome.result.Mode != RunModeShadow {
			t.Errorf("mode = %q, want SHADOW", outcome.result.Mode)
		}
		if outcome.result.AlertsCreated != 0 {
			t.Errorf("alerts created = %d, want 0", outcome.result.AlertsCreated)
		}
		if outcome.result.Proposals != 1 {
			t.Errorf("proposals = %d, want 1", outcome.result.Proposals)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run did not finish after the detection lock was released")
	}

	if got := countRows(t, fixture.database, &alertTableRow{}); got != 0 {
		t.Errorf("alerts = %d, want 0", got)
	}
	if got := countRows(t, fixture.database, &proposalRow{}); got != 1 {
		t.Errorf("detection_proposals = %d, want 1", got)
	}
	if status, _ := detectionRuntimeRow(t, fixture.database, fixture.manifest.ID); status != "SHADOW" {
		t.Errorf("runtime status = %q, want SHADOW", status)
	}
}

func TestRunWindowStoresProposalsWhenShadow(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{
			proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute)),
			proposalAt("bob", "dc01", "bob-1", window.Start.Add(2*time.Minute)),
		}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"))
	fixture.markReady(t, "auth_events")

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want nil", err)
	}
	if result.Mode != RunModeShadow {
		t.Errorf("mode = %q, want SHADOW", result.Mode)
	}
	if result.AlertsCreated != 0 || result.AlertsMerged != 0 || result.ProposalsDeduplicated != 0 {
		t.Errorf("result counters = %d/%d/%d, want zero", result.AlertsCreated, result.AlertsMerged, result.ProposalsDeduplicated)
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 || runs[0].Mode != string(RunModeShadow) {
		t.Fatalf("detection_runs = %+v, want one SHADOW row", runs)
	}
	if got := countRows(t, fixture.database, &proposalRow{}); got != 2 {
		t.Errorf("detection_proposals = %d, want 2", got)
	}
	if got := countRows(t, fixture.database, &alertTableRow{}); got != 0 {
		t.Errorf("alerts = %d, want 0", got)
	}
	if status, _ := detectionRuntimeRow(t, fixture.database, fixture.manifest.ID); status != "SHADOW" {
		t.Errorf("runtime status = %q, want SHADOW", status)
	}
}

func TestRunWindowShadowOptionStoresProposals(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{
			proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute)),
			proposalAt("bob", "dc01", "bob-1", window.Start.Add(2*time.Minute)),
		}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), enableDetection)
	fixture.markReady(t, "auth_events")

	result, err := fixture.runner.RunWindow(context.Background(), fixture.registration, fixture.end, RunOptions{Shadow: true})
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want nil", err)
	}
	if result.Mode != RunModeShadow {
		t.Errorf("mode = %q, want SHADOW", result.Mode)
	}
	if result.AlertsCreated != 0 {
		t.Errorf("alerts created = %d, want 0", result.AlertsCreated)
	}
	if got := countRows(t, fixture.database, &proposalRow{}); got != 2 {
		t.Errorf("detection_proposals = %d, want 2", got)
	}
	if got := countRows(t, fixture.database, &alertTableRow{}); got != 0 {
		t.Errorf("alerts = %d, want 0", got)
	}
	if status, _ := detectionRuntimeRow(t, fixture.database, fixture.manifest.ID); status != "ENABLED" {
		t.Errorf("runtime status = %q, want ENABLED", status)
	}
}

func TestRunWindowDedupesSecondRun(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{
			proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute)),
			proposalAt("bob", "dc01", "bob-1", window.Start.Add(2*time.Minute)),
		}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), enableDetection)
	fixture.markReady(t, "auth_events")

	first, err := fixture.run(t)
	if err != nil {
		t.Fatalf("first RunWindow() error = %v, want nil", err)
	}
	if first.AlertsCreated != 2 {
		t.Fatalf("first alerts created = %d, want 2", first.AlertsCreated)
	}
	second, err := fixture.run(t)
	if err != nil {
		t.Fatalf("second RunWindow() error = %v, want nil", err)
	}
	if second.Mode != RunModeEnabled {
		t.Errorf("second mode = %q, want ENABLED", second.Mode)
	}
	if second.AlertsCreated != 0 || second.AlertsMerged != 0 {
		t.Errorf("second created/merged = %d/%d, want 0/0", second.AlertsCreated, second.AlertsMerged)
	}
	if second.ProposalsDeduplicated != 2 {
		t.Errorf("second deduplicated = %d, want 2", second.ProposalsDeduplicated)
	}
	if got := countRows(t, fixture.database, &alertTableRow{}); got != 2 {
		t.Errorf("alerts = %d, want 2", got)
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 2 || runs[1].Revision != 2 || runs[1].ProposalsDeduplicated != 2 || runs[1].AlertsCreated != 0 {
		t.Fatalf("detection_runs = %+v, want a second run with 2 deduplicated", runs)
	}
}

func TestRunWindowStoresRemainingProposalsAfterGuardrail(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{
			proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute)),
			proposalAt("bob", "dc01", "bob-1", window.Start.Add(2*time.Minute)),
			proposalAt("carol", "app01", "carol-1", window.Start.Add(3*time.Minute)),
		}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), enableDetection)
	fixture.runner.Alerts.Hooks = &guardrailHook{}
	fixture.markReady(t, "auth_events")

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want nil", err)
	}
	if result.Mode != RunModeEnabled {
		t.Errorf("mode = %q, want ENABLED", result.Mode)
	}
	if result.AlertsCreated != 1 {
		t.Errorf("alerts created = %d, want 1", result.AlertsCreated)
	}
	if got := countRows(t, fixture.database, &alertTableRow{}); got != 1 {
		t.Errorf("alerts = %d, want 1", got)
	}
	proposals := loadProposals(t, fixture.database)
	if len(proposals) != 2 {
		t.Fatalf("detection_proposals = %d, want the 2 after the trip", len(proposals))
	}
	for _, proposal := range proposals {
		if proposal.DetectionRunID != result.RunID {
			t.Errorf("proposal run id = %q, want %q", proposal.DetectionRunID, result.RunID)
		}
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 || runs[0].Mode != string(RunModeEnabled) || runs[0].AlertsCreated != 1 {
		t.Fatalf("detection_runs = %+v, want one ENABLED run with 1 created", runs)
	}
	if status, _ := detectionRuntimeRow(t, fixture.database, fixture.manifest.ID); status != "SHADOW" {
		t.Errorf("runtime status = %q, want SHADOW", status)
	}
}

func TestRunWindowRecordsApplyFailure(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{
			proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute)),
			proposalAt("bob", "dc01", "bob-1", window.Start.Add(2*time.Minute)),
		}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), enableDetection)
	fixture.runner.Alerts.Hooks = failingHook{err: errors.New("case store failed")}
	fixture.markReady(t, "auth_events")

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want the failure recorded", err)
	}
	if result.Status != RunStatusFailed || result.Error != "apply alerts failed" {
		t.Fatalf("RunWindow() result = %+v, want FAILED with apply alerts failed", result)
	}
	if result.Mode != RunModeShadow {
		t.Errorf("mode = %q, want SHADOW", result.Mode)
	}
	if result.RunID == "" || result.Revision != 1 {
		t.Errorf("result run id/revision = %q/%d, want a recorded run", result.RunID, result.Revision)
	}

	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 {
		t.Fatalf("detection_runs rows = %d, want exactly 1", len(runs))
	}
	run := runs[0]
	if run.Status != string(RunStatusFailed) || run.Mode != string(RunModeShadow) {
		t.Errorf("run row = %+v, want FAILED and SHADOW", run)
	}
	if run.Proposals != 0 || run.AlertsCreated != 0 {
		t.Errorf("run row proposals/created = %d/%d, want 0/0", run.Proposals, run.AlertsCreated)
	}
	if run.Error == nil || *run.Error != "apply alerts failed" {
		t.Errorf("run row error = %v, want apply alerts failed", run.Error)
	}
	if got := countRows(t, fixture.database, &alertTableRow{}); got != 0 {
		t.Errorf("alerts = %d, want 0", got)
	}
	if got := countRows(t, fixture.database, &proposalRow{}); got != 0 {
		t.Errorf("detection_proposals = %d, want 0", got)
	}
}

func TestRunWindowUsesRegisteredRuntimeStatus(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute))}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), enableDetection)
	fixture.markReady(t, "auth_events")

	first, err := fixture.run(t)
	if err != nil {
		t.Fatalf("first RunWindow() error = %v, want nil", err)
	}
	if first.Mode != RunModeEnabled || first.AlertsCreated != 1 {
		t.Fatalf("first run = %+v, want ENABLED with one alert", first)
	}
	if status, _ := detectionRuntimeRow(t, fixture.database, fixture.manifest.ID); status != "ENABLED" {
		t.Fatalf("runtime status = %q, want ENABLED", status)
	}

	if err := fixture.database.Exec(
		"UPDATE detection_runtime SET status = 'SHADOW' WHERE detection_id = ?", fixture.manifest.ID,
	).Error; err != nil {
		t.Fatalf("switch the runtime row to SHADOW: %v", err)
	}
	second, err := fixture.run(t)
	if err != nil {
		t.Fatalf("second RunWindow() error = %v, want nil", err)
	}
	if second.Mode != RunModeShadow {
		t.Errorf("second mode = %q, want SHADOW", second.Mode)
	}
	if second.AlertsCreated != 0 {
		t.Errorf("second alerts created = %d, want 0", second.AlertsCreated)
	}
	if got := countRows(t, fixture.database, &alertTableRow{}); got != 1 {
		t.Errorf("alerts = %d, want the first run's alert only", got)
	}
	if got := countRows(t, fixture.database, &proposalRow{}); got != 1 {
		t.Errorf("detection_proposals = %d, want the second run's proposal", got)
	}
	if status, version := detectionRuntimeRow(t, fixture.database, fixture.manifest.ID); status != "SHADOW" || version != 1 {
		t.Errorf("runtime status/version = %q/%d, want SHADOW/1", status, version)
	}
}

// blockingHook keeps AlertCreated inside the transaction until its context ends.
type blockingHook struct{}

func (blockingHook) AlertCreated(ctx context.Context, _ *gorm.DB, _ alerts.NewAlert) (alerts.CaseOutcome, error) {
	<-ctx.Done()
	return alerts.CaseOutcome{}, ctx.Err()
}

func (blockingHook) EvidenceAdded(context.Context, *gorm.DB, string, time.Time, int) error {
	return nil
}

func TestRunWindowRecordsApplyFailureAfterDeadline(t *testing.T) {
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		return []Proposal{proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute))}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"),
		enableDetection, [2]string{"timeout: 30s", "timeout: 1s"})
	fixture.runner.Alerts.Hooks = blockingHook{}
	fixture.markReady(t, "auth_events")

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want the failure recorded", err)
	}
	if result.Status != RunStatusFailed || result.Error != "apply alerts failed" {
		t.Fatalf("RunWindow() result = %+v, want FAILED with apply alerts failed", result)
	}
	if result.RunID == "" {
		t.Error("result run id is empty, want the FAILED row")
	}
	runs := loadRuns(t, fixture.database)
	if len(runs) != 1 {
		t.Fatalf("detection_runs rows = %d, want exactly 1", len(runs))
	}
	if runs[0].Status != string(RunStatusFailed) || runs[0].Mode != string(RunModeShadow) {
		t.Errorf("run row = %+v, want FAILED and SHADOW", runs[0])
	}
	if runs[0].Error == nil || *runs[0].Error != "apply alerts failed" {
		t.Errorf("run row error = %v, want apply alerts failed", runs[0].Error)
	}
	if got := countRows(t, fixture.database, &alertTableRow{}); got != 0 {
		t.Errorf("alerts = %d, want 0", got)
	}
}

func TestRunWindowAppliesProposalsInIdentityHashOrder(t *testing.T) {
	hook := &recordingHook{}
	var reverse bool
	logic := stubDetection(func(_ context.Context, window Window) ([]Proposal, error) {
		alice := proposalAt("alice", "web01", "alice-1", window.Start.Add(time.Minute))
		bob := proposalAt("bob", "dc01", "bob-1", window.Start.Add(2*time.Minute))
		if reverse {
			return []Proposal{bob, alice}, nil
		}
		return []Proposal{alice, bob}, nil
	})
	fixture := newRunnerFixture(t, logic, configFilesWriting("auth_events"), enableDetection)
	fixture.runner.Alerts.Hooks = hook
	fixture.markReady(t, "auth_events")

	aliceIdentity, err := ComputeIdentity(fixture.manifest.ID, fixture.manifest.Alerting, identitySubject("alice", "web01", ""))
	if err != nil {
		t.Fatalf("compute the alice identity: %v", err)
	}
	bobIdentity, err := ComputeIdentity(fixture.manifest.ID, fixture.manifest.Alerting, identitySubject("bob", "dc01", ""))
	if err != nil {
		t.Fatalf("compute the bob identity: %v", err)
	}
	// Hand the runner the descending order, so only a stable sort makes the
	// hook see ascending hashes.
	reverse = aliceIdentity.Hash < bobIdentity.Hash

	result, err := fixture.run(t)
	if err != nil {
		t.Fatalf("RunWindow() error = %v, want nil", err)
	}
	if result.AlertsCreated != 2 {
		t.Fatalf("alerts created = %d, want 2", result.AlertsCreated)
	}
	if len(hook.created) != 2 {
		t.Fatalf("AlertCreated calls = %d, want 2", len(hook.created))
	}
	smaller, larger := aliceIdentity.Hash, bobIdentity.Hash
	if smaller > larger {
		smaller, larger = larger, smaller
	}
	if hook.created[0].IdentityHash != smaller || hook.created[1].IdentityHash != larger {
		t.Errorf("hook order = %q, %q; want ascending %q, %q",
			hook.created[0].IdentityHash, hook.created[1].IdentityHash, smaller, larger)
	}
}
