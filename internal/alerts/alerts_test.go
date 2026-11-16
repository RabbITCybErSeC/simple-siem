package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/outbox"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
	"gorm.io/gorm"
)

const (
	testDetectionID  = "detection-apply"
	testIdentityHash = "identity-1"
)

// outboxEventRow reads the columns the guardrail test asserts on.
type outboxEventRow struct {
	Type        string `gorm:"column:type"`
	Version     int    `gorm:"column:version"`
	Actor       []byte `gorm:"column:actor"`
	SubjectType string `gorm:"column:subject_type"`
	SubjectID   string `gorm:"column:subject_id"`
	Payload     []byte `gorm:"column:payload"`
}

// evidenceCall is one recorded EvidenceAdded call.
type evidenceCall struct {
	AlertID     string
	LastEventAt time.Time
	Added       int
}

// recordingHook records hook calls and returns the configured results.
type recordingHook struct {
	created        []NewAlert
	evidence       []evidenceCall
	createdOutcome CaseOutcome
	createdError   error
}

func (hook *recordingHook) AlertCreated(_ context.Context, _ *gorm.DB, alert NewAlert) (CaseOutcome, error) {
	hook.created = append(hook.created, alert)
	return hook.createdOutcome, hook.createdError
}

func (hook *recordingHook) EvidenceAdded(_ context.Context, _ *gorm.DB, alertID string, lastEventAt time.Time, added int) error {
	hook.evidence = append(hook.evidence, evidenceCall{AlertID: alertID, LastEventAt: lastEventAt, Added: added})
	return nil
}

func TestApplyRejectsInvalidProposals(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	valid := newProposal(runID, testEventTime)

	cases := []struct {
		name   string
		mutate func(*Policy, *Proposal)
	}{
		{"no evidence", func(_ *Policy, proposal *Proposal) { proposal.Evidence = nil }},
		{"empty detection id", func(_ *Policy, proposal *Proposal) { proposal.DetectionID = "" }},
		{"empty identity hash", func(_ *Policy, proposal *Proposal) { proposal.IdentityHash = "" }},
		{"empty run id", func(_ *Policy, proposal *Proposal) { proposal.DetectionRunID = "" }},
		{"unknown mode", func(policy *Policy, _ *Proposal) { policy.Mode = Mode("OTHER") }},
		{"unknown severity", func(_ *Policy, proposal *Proposal) { proposal.Severity = Severity("CRITICAL") }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			policy := mergePolicy()
			proposal := valid
			testCase.mutate(&policy, &proposal)

			service := &Service{}
			err := db.Transaction(func(tx *gorm.DB) error {
				_, err := service.Apply(context.Background(), tx, policy, proposal)
				return err
			})
			if !errors.Is(err, ErrInvalidProposal) {
				t.Fatalf("Apply error = %v, want ErrInvalidProposal", err)
			}
			if got := countRows(t, db, &alertRow{}); got != 0 {
				t.Errorf("alerts rows = %d, want 0", got)
			}
		})
	}
}

func TestApplyCreatesAlert(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	eventTimes := make([]time.Time, 13)
	for index := range eventTimes {
		eventTimes[index] = testEventTime.Add(time.Duration(index) * 2 * time.Minute)
	}
	proposal := newProposal(runID, eventTimes...)
	service := &Service{}

	outcome := applyProposal(t, db, service, mergePolicy(), proposal)
	if outcome.Action != ActionCreated {
		t.Fatalf("action = %q, want CREATED", outcome.Action)
	}
	if outcome.AlertID == "" {
		t.Fatal("alert id is empty, want the created alert")
	}
	if outcome.NewEvidence != len(eventTimes) {
		t.Errorf("new evidence = %d, want %d", outcome.NewEvidence, len(eventTimes))
	}
	if outcome.GuardrailTripped {
		t.Error("guardrail tripped, want false without a hook")
	}

	alert := loadAlert(t, db, outcome.AlertID)
	if alert.DetectionID != proposal.DetectionID {
		t.Errorf("detection id = %q, want %q", alert.DetectionID, proposal.DetectionID)
	}
	if alert.DetectionVersion != proposal.DetectionVersion {
		t.Errorf("detection version = %q, want %q", alert.DetectionVersion, proposal.DetectionVersion)
	}
	if alert.IdentityHash != proposal.IdentityHash {
		t.Errorf("identity hash = %q, want %q", alert.IdentityHash, proposal.IdentityHash)
	}
	if alert.IdentitySchemaVersion != proposal.IdentitySchemaVersion {
		t.Errorf("identity schema version = %d, want %d", alert.IdentitySchemaVersion, proposal.IdentitySchemaVersion)
	}
	if !reflect.DeepEqual(alert.Identity, proposal.Identity) {
		t.Errorf("identity = %v, want %v", alert.Identity, proposal.Identity)
	}
	if !reflect.DeepEqual(alert.Subject, proposal.Subject) {
		t.Errorf("subject = %+v, want %+v", alert.Subject, proposal.Subject)
	}
	if alert.Summary != proposal.Summary {
		t.Errorf("summary = %q, want %q", alert.Summary, proposal.Summary)
	}
	if !reflect.DeepEqual(alert.Details, proposal.Details) {
		t.Errorf("details = %v, want %v", alert.Details, proposal.Details)
	}
	if alert.Severity != string(proposal.Severity) {
		t.Errorf("severity = %q, want %q", alert.Severity, proposal.Severity)
	}
	if alert.Status != "OPEN" {
		t.Errorf("status = %q, want OPEN", alert.Status)
	}
	if !alert.Coalescing {
		t.Error("coalescing = false, want true")
	}
	if alert.OccurrenceCount != 1 {
		t.Errorf("occurrence count = %d, want 1", alert.OccurrenceCount)
	}
	if alert.EvidenceCount != len(eventTimes) {
		t.Errorf("evidence count = %d, want %d", alert.EvidenceCount, len(eventTimes))
	}
	if alert.PreviousAlertID != nil {
		t.Errorf("previous alert id = %q, want nil", *alert.PreviousAlertID)
	}
	if alert.Version != 1 {
		t.Errorf("version = %d, want 1", alert.Version)
	}
	if !alert.FirstEventAt.UTC().Equal(eventTimes[0].UTC()) {
		t.Errorf("first event at = %v, want %v", alert.FirstEventAt, eventTimes[0])
	}
	if !alert.LastEventAt.UTC().Equal(eventTimes[len(eventTimes)-1].UTC()) {
		t.Errorf("last event at = %v, want %v", alert.LastEventAt, eventTimes[len(eventTimes)-1])
	}

	if got := countRows(t, db, &evidenceRow{}); got != int64(len(eventTimes)) {
		t.Errorf("evidence rows = %d, want %d", got, len(eventTimes))
	}
	occurrences := loadOccurrences(t, db, alert.ID)
	if len(occurrences) != 1 {
		t.Fatalf("occurrences = %d, want 1", len(occurrences))
	}
	occurrence := occurrences[0]
	if occurrence.DetectionRunID != runID {
		t.Errorf("occurrence run id = %q, want %q", occurrence.DetectionRunID, runID)
	}
	if occurrence.NewEvidenceCount != len(eventTimes) {
		t.Errorf("occurrence new evidence = %d, want %d", occurrence.NewEvidenceCount, len(eventTimes))
	}
	if !occurrence.FirstEventAt.UTC().Equal(eventTimes[0].UTC()) {
		t.Errorf("occurrence first event at = %v, want %v", occurrence.FirstEventAt, eventTimes[0])
	}
	if !occurrence.LastEventAt.UTC().Equal(eventTimes[len(eventTimes)-1].UTC()) {
		t.Errorf("occurrence last event at = %v, want %v", occurrence.LastEventAt, eventTimes[len(eventTimes)-1])
	}

	events := storedAuditEvents(t, db, "simple_siem.alert.created")
	if len(events) != 1 {
		t.Fatalf("alert.created audit events = %d, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "ALERT" {
		t.Errorf("audit category = %q, want ALERT", event.EventCategory)
	}
	if event.EventOutcome != "SUCCESS" {
		t.Errorf("audit outcome = %q, want SUCCESS", event.EventOutcome)
	}
	if event.ActorType != "SYSTEM" {
		t.Errorf("audit actor type = %q, want SYSTEM", event.ActorType)
	}
	if event.TargetType != "ALERT" {
		t.Errorf("audit target type = %q, want ALERT", event.TargetType)
	}
	if event.TargetID != alert.ID {
		t.Errorf("audit target id = %q, want %q", event.TargetID, alert.ID)
	}
	if event.Action != "create" {
		t.Errorf("audit action = %q, want create", event.Action)
	}
	if event.Changes["detectionId"] != proposal.DetectionID {
		t.Errorf("audit detection id = %v, want %q", event.Changes["detectionId"], proposal.DetectionID)
	}
	if event.Changes["detectionVersion"] != proposal.DetectionVersion {
		t.Errorf("audit detection version = %v, want %q", event.Changes["detectionVersion"], proposal.DetectionVersion)
	}
	if event.Changes["identityHash"] != proposal.IdentityHash {
		t.Errorf("audit identity hash = %v, want %q", event.Changes["identityHash"], proposal.IdentityHash)
	}
	if event.Changes["severity"] != string(proposal.Severity) {
		t.Errorf("audit severity = %v, want %q", event.Changes["severity"], proposal.Severity)
	}
	if event.Changes["evidenceCount"] != float64(len(eventTimes)) {
		t.Errorf("audit evidence count = %v, want %d", event.Changes["evidenceCount"], len(eventTimes))
	}
	if value, present := event.Changes["previousAlertId"]; !present || value != nil {
		t.Errorf("audit previous alert id = %v (present %t), want nil", value, present)
	}
	encoded, err := json.Marshal(event.Changes)
	if err != nil {
		t.Fatalf("encode audit changes: %v", err)
	}
	if strings.Contains(string(encoded), "alice") || strings.Contains(string(encoded), "web01") {
		t.Errorf("audit changes %s hold identity values or the subject", encoded)
	}
	if _, present := event.Changes["subject"]; present {
		t.Error("audit changes hold the subject")
	}
}

func TestApplyReprocessingIsNoop(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	proposal := newProposal(runID, testEventTime, testEventTime.Add(2*time.Minute))
	service := &Service{}

	created := applyProposal(t, db, service, mergePolicy(), proposal)
	before := loadAlert(t, db, created.AlertID)
	occurrencesBefore := len(loadOccurrences(t, db, created.AlertID))
	auditsBefore := len(storedAuditEvents(t, db, "simple_siem.alert.created"))

	outcome := applyProposal(t, db, service, mergePolicy(), proposal)
	if outcome.Action != ActionNoop {
		t.Fatalf("action = %q, want NOOP", outcome.Action)
	}
	if outcome.AlertID != "" {
		t.Errorf("alert id = %q, want empty for NOOP", outcome.AlertID)
	}
	if outcome.NewEvidence != 0 {
		t.Errorf("new evidence = %d, want 0", outcome.NewEvidence)
	}

	after := loadAlert(t, db, created.AlertID)
	if after.Version != before.Version {
		t.Errorf("version = %d, want %d", after.Version, before.Version)
	}
	if after.EvidenceCount != before.EvidenceCount {
		t.Errorf("evidence count = %d, want %d", after.EvidenceCount, before.EvidenceCount)
	}
	if after.OccurrenceCount != before.OccurrenceCount {
		t.Errorf("occurrence count = %d, want %d", after.OccurrenceCount, before.OccurrenceCount)
	}
	if !after.LastEventAt.UTC().Equal(before.LastEventAt.UTC()) {
		t.Errorf("last event at = %v, want %v", after.LastEventAt, before.LastEventAt)
	}
	if got := len(loadOccurrences(t, db, created.AlertID)); got != occurrencesBefore {
		t.Errorf("occurrences = %d, want %d", got, occurrencesBefore)
	}
	if got := len(storedAuditEvents(t, db, "simple_siem.alert.created")); got != auditsBefore {
		t.Errorf("audit events = %d, want %d", got, auditsBefore)
	}
}

func TestApplyCountsDuplicateSourceKeyOnce(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	first := testEventTime
	proposal := newProposal(runID, first, first, first.Add(2*time.Minute))
	service := &Service{}

	outcome := applyProposal(t, db, service, mergePolicy(), proposal)
	if outcome.Action != ActionCreated {
		t.Fatalf("action = %q, want CREATED", outcome.Action)
	}
	if outcome.NewEvidence != 2 {
		t.Errorf("new evidence = %d, want 2", outcome.NewEvidence)
	}
	alert := loadAlert(t, db, outcome.AlertID)
	if alert.EvidenceCount != 2 {
		t.Errorf("evidence count = %d, want 2", alert.EvidenceCount)
	}
	if got := countRows(t, db, &evidenceRow{}); got != 2 {
		t.Errorf("evidence rows = %d, want 2", got)
	}
}

func TestApplySlidingWindowsMergeOneBurst(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	eventTimes := make([]time.Time, 20)
	for index := range eventTimes {
		eventTimes[index] = testEventTime.Add(time.Duration(index) * 2 * time.Minute)
	}
	service := &Service{}
	policy := mergePolicy()

	actions := make([]Action, 0, 9)
	alertID := ""
	for step := 1; step <= 9; step++ {
		windowEnd := testEventTime.Add(time.Duration(step*5) * time.Minute)
		windowStart := windowEnd.Add(-time.Hour)
		var windowTimes []time.Time
		for _, eventTime := range eventTimes {
			if !eventTime.Before(windowStart) && eventTime.Before(windowEnd) {
				windowTimes = append(windowTimes, eventTime)
			}
		}
		outcome := applyProposal(t, db, service, policy, newProposal(runID, windowTimes...))
		actions = append(actions, outcome.Action)
		if alertID == "" {
			alertID = outcome.AlertID
		}
	}

	wantActions := []Action{
		ActionCreated,
		ActionMerged, ActionMerged, ActionMerged, ActionMerged,
		ActionMerged, ActionMerged, ActionMerged,
		ActionNoop,
	}
	if !reflect.DeepEqual(actions, wantActions) {
		t.Fatalf("actions = %v, want %v", actions, wantActions)
	}
	if got := countRows(t, db, &alertRow{}); got != 1 {
		t.Errorf("alerts = %d, want 1", got)
	}
	alert := loadAlert(t, db, alertID)
	if alert.EvidenceCount != 20 {
		t.Errorf("evidence count = %d, want 20", alert.EvidenceCount)
	}
	if alert.OccurrenceCount != 8 {
		t.Errorf("occurrence count = %d, want 8", alert.OccurrenceCount)
	}
	if got := countRows(t, db, &evidenceRow{}); got != 20 {
		t.Errorf("evidence rows = %d, want 20", got)
	}
	if got := len(loadOccurrences(t, db, alertID)); got != 8 {
		t.Errorf("occurrences = %d, want 8", got)
	}
}

func TestApplySplitsWhenGapExceedsWindow(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	service := &Service{}

	first := applyProposal(t, db, service, mergePolicy(), newProposal(runID, testEventTime))
	second := applyProposal(t, db, service, mergePolicy(), newProposal(runID, testEventTime.Add(3*time.Hour)))
	if first.Action != ActionCreated || second.Action != ActionCreated {
		t.Fatalf("actions = %q and %q, want CREATED twice", first.Action, second.Action)
	}
	if first.AlertID == second.AlertID {
		t.Fatal("split reused the old alert id, want a new alert")
	}

	oldAlert := loadAlert(t, db, first.AlertID)
	if oldAlert.Status != "OPEN" {
		t.Errorf("old alert status = %q, want OPEN", oldAlert.Status)
	}
	if oldAlert.Coalescing {
		t.Error("old alert coalescing = true, want false")
	}
	if oldAlert.Version != 2 {
		t.Errorf("old alert version = %d, want 2", oldAlert.Version)
	}
	if !oldAlert.LastEventAt.UTC().Equal(testEventTime.UTC()) {
		t.Errorf("old alert last event at = %v, want %v", oldAlert.LastEventAt, testEventTime)
	}

	newAlert := loadAlert(t, db, second.AlertID)
	if !newAlert.Coalescing {
		t.Error("new alert coalescing = false, want true")
	}
	if newAlert.PreviousAlertID == nil || *newAlert.PreviousAlertID != first.AlertID {
		t.Errorf("new alert previous id = %v, want %q", newAlert.PreviousAlertID, first.AlertID)
	}
	if got := countRows(t, db, &alertRow{}); got != 2 {
		t.Errorf("alerts = %d, want 2", got)
	}
}

func TestApplyCapsAlertSpan(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	service := &Service{}
	policy := Policy{Mode: ModeMerge, CoalesceWindow: 2 * time.Hour, MaxAlertSpan: 24 * time.Hour}

	for hour := 0; hour < 30; hour++ {
		applyProposal(t, db, service, policy, newProposal(runID, testEventTime.Add(time.Duration(hour)*time.Hour)))
	}

	alerts := loadAlerts(t, db)
	if len(alerts) != 2 {
		t.Fatalf("alerts = %d, want 2", len(alerts))
	}
	for _, alert := range alerts {
		if alert.LastEventAt.Sub(alert.FirstEventAt) > policy.MaxAlertSpan {
			t.Errorf("alert %q spans %v, over the %v cap", alert.ID, alert.LastEventAt.Sub(alert.FirstEventAt), policy.MaxAlertSpan)
		}
	}
	if alerts[0].Coalescing {
		t.Error("first alert coalescing = true, want false after the split")
	}
	if !alerts[1].Coalescing {
		t.Error("second alert coalescing = false, want true")
	}
	if alerts[1].PreviousAlertID == nil || *alerts[1].PreviousAlertID != alerts[0].ID {
		t.Errorf("second alert previous id = %v, want %q", alerts[1].PreviousAlertID, alerts[0].ID)
	}
}

func TestApplyOutOfOrderEvidenceMerges(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	service := &Service{}
	firstTime := testEventTime
	lastTime := testEventTime.Add(time.Hour)

	created := applyProposal(t, db, service, mergePolicy(), newProposal(runID, firstTime, lastTime))
	outcome := applyProposal(t, db, service, mergePolicy(), newProposal(runID, firstTime.Add(-30*time.Minute)))
	if outcome.Action != ActionMerged {
		t.Fatalf("action = %q, want MERGED", outcome.Action)
	}
	alert := loadAlert(t, db, created.AlertID)
	if !alert.FirstEventAt.UTC().Equal(firstTime.Add(-30 * time.Minute).UTC()) {
		t.Errorf("first event at = %v, want %v", alert.FirstEventAt, firstTime.Add(-30*time.Minute))
	}
	if !alert.LastEventAt.UTC().Equal(lastTime.UTC()) {
		t.Errorf("last event at = %v, want %v", alert.LastEventAt, lastTime)
	}
	if alert.Version != 2 {
		t.Errorf("version = %d, want 2", alert.Version)
	}
}

func TestApplyUniqueMergesAcrossGap(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	service := &Service{}
	policy := Policy{Mode: ModeUnique, CoalesceWindow: 2 * time.Hour, MaxAlertSpan: 24 * time.Hour}

	created := applyProposal(t, db, service, policy, newProposal(runID, testEventTime))
	later := testEventTime.Add(72 * time.Hour)
	outcome := applyProposal(t, db, service, policy, newProposal(runID, later))
	if outcome.Action != ActionMerged {
		t.Fatalf("action = %q, want MERGED", outcome.Action)
	}
	if outcome.AlertID != created.AlertID {
		t.Errorf("alert id = %q, want %q", outcome.AlertID, created.AlertID)
	}
	alert := loadAlert(t, db, created.AlertID)
	if alert.EvidenceCount != 2 {
		t.Errorf("evidence count = %d, want 2", alert.EvidenceCount)
	}
	if alert.OccurrenceCount != 2 {
		t.Errorf("occurrence count = %d, want 2", alert.OccurrenceCount)
	}
	if !alert.LastEventAt.UTC().Equal(later.UTC()) {
		t.Errorf("last event at = %v, want %v", alert.LastEventAt, later)
	}
	if got := countRows(t, db, &alertRow{}); got != 1 {
		t.Errorf("alerts = %d, want 1", got)
	}
}

func TestApplyAlwaysNewCreatesSeparateAlerts(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	service := &Service{}
	policy := Policy{Mode: ModeAlwaysNew, CoalesceWindow: 2 * time.Hour, MaxAlertSpan: 24 * time.Hour}

	firstProposal := newProposal(runID, testEventTime)
	first := applyProposal(t, db, service, policy, firstProposal)
	second := applyProposal(t, db, service, policy, newProposal(runID, testEventTime.Add(time.Hour)))
	if first.Action != ActionCreated || second.Action != ActionCreated {
		t.Fatalf("actions = %q and %q, want CREATED twice", first.Action, second.Action)
	}
	if first.AlertID == second.AlertID {
		t.Fatal("ALWAYS_NEW reused an alert, want one per proposal")
	}
	alerts := loadAlerts(t, db)
	if len(alerts) != 2 {
		t.Fatalf("alerts = %d, want 2", len(alerts))
	}
	for _, alert := range alerts {
		if alert.Coalescing {
			t.Errorf("alert %q coalescing = true, want false", alert.ID)
		}
	}

	repeat := applyProposal(t, db, service, policy, firstProposal)
	if repeat.Action != ActionNoop {
		t.Errorf("repeat action = %q, want NOOP", repeat.Action)
	}
	if got := countRows(t, db, &alertRow{}); got != 2 {
		t.Errorf("alerts after repeat = %d, want 2", got)
	}
}

func TestApplyAlwaysNewDoesNotLinkAnOpenPredecessor(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	hook := &recordingHook{}
	service := &Service{Hooks: hook}
	policy := Policy{Mode: ModeAlwaysNew, CoalesceWindow: 2 * time.Hour, MaxAlertSpan: 24 * time.Hour}

	predecessor := applyProposal(t, db, service, policy, newProposal(runID, testEventTime))
	successor := applyProposal(t, db, service, policy, newProposal(runID, testEventTime.Add(5*time.Minute)))
	if predecessor.Action != ActionCreated || successor.Action != ActionCreated {
		t.Fatalf("actions = %q and %q, want CREATED twice", predecessor.Action, successor.Action)
	}
	if predecessor.AlertID == successor.AlertID {
		t.Fatal("ALWAYS_NEW reused an alert, want one per proposal")
	}

	first := loadAlert(t, db, predecessor.AlertID)
	if first.Status != "OPEN" {
		t.Fatalf("predecessor status = %q, want OPEN", first.Status)
	}
	second := loadAlert(t, db, successor.AlertID)
	if second.PreviousAlertID != nil {
		t.Errorf("new alert previous id = %q, want nil with an open predecessor", *second.PreviousAlertID)
	}
	if len(hook.created) != 2 {
		t.Fatalf("AlertCreated calls = %d, want 2", len(hook.created))
	}
	if hook.created[1].PreviousAlertID != nil {
		t.Errorf("hook previous alert id = %q, want nil with an open predecessor", *hook.created[1].PreviousAlertID)
	}
}

func TestApplySplitLinksTheSplitAlert(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	service := &Service{}
	policy := Policy{Mode: ModeMerge, CoalesceWindow: 15 * time.Minute, MaxAlertSpan: 24 * time.Hour}

	closedAlert := applyProposal(t, db, service, policy, newProposal(runID, testEventTime))
	closeAlert(t, db, closedAlert.AlertID)
	openAlert := applyProposal(t, db, service, policy, newProposal(runID, testEventTime.Add(2*time.Hour)))
	if openAlert.Action != ActionCreated {
		t.Fatalf("open alert action = %q, want CREATED", openAlert.Action)
	}
	open := loadAlert(t, db, openAlert.AlertID)
	if !open.Coalescing {
		t.Fatal("open alert coalescing = false, want true")
	}
	if open.PreviousAlertID == nil || *open.PreviousAlertID != closedAlert.AlertID {
		t.Fatalf("open alert previous id = %v, want the closed alert %q", open.PreviousAlertID, closedAlert.AlertID)
	}

	split := applyProposal(t, db, service, policy, newProposal(runID, testEventTime.Add(4*time.Hour)))
	if split.Action != ActionCreated {
		t.Fatalf("split action = %q, want CREATED", split.Action)
	}
	splitOpen := loadAlert(t, db, openAlert.AlertID)
	if splitOpen.Coalescing {
		t.Error("split alert coalescing = true, want false")
	}
	if splitOpen.Status != "OPEN" {
		t.Errorf("split alert status = %q, want OPEN", splitOpen.Status)
	}
	newAlert := loadAlert(t, db, split.AlertID)
	if newAlert.PreviousAlertID == nil || *newAlert.PreviousAlertID != openAlert.AlertID {
		t.Errorf("new alert previous id = %v, want the split alert %q, not the closed alert %q",
			newAlert.PreviousAlertID, openAlert.AlertID, closedAlert.AlertID)
	}
}

func TestApplyRecurrenceAfterClosure(t *testing.T) {
	for _, mode := range []Mode{ModeMerge, ModeAlwaysNew} {
		t.Run(string(mode), func(t *testing.T) {
			db := databasetest.New(t)
			runID := insertRun(t, db, testDetectionID)
			service := &Service{}
			policy := Policy{Mode: mode, CoalesceWindow: 2 * time.Hour, MaxAlertSpan: 24 * time.Hour}

			created := applyProposal(t, db, service, policy, newProposal(runID, testEventTime))
			closeAlert(t, db, created.AlertID)
			closedBefore := loadAlert(t, db, created.AlertID)

			noop := applyProposal(t, db, service, policy, newProposal(runID, testEventTime))
			if noop.Action != ActionNoop {
				t.Errorf("re-applying the closed alert's evidence = %q, want NOOP", noop.Action)
			}
			closedAfterNoop := loadAlert(t, db, created.AlertID)
			if closedAfterNoop.Version != closedBefore.Version {
				t.Errorf("closed alert version = %d, want %d", closedAfterNoop.Version, closedBefore.Version)
			}

			recurrence := applyProposal(t, db, service, policy, newProposal(runID, testEventTime.Add(time.Hour)))
			if recurrence.Action != ActionCreated {
				t.Fatalf("recurrence action = %q, want CREATED", recurrence.Action)
			}
			reopened := loadAlert(t, db, recurrence.AlertID)
			if reopened.PreviousAlertID == nil || *reopened.PreviousAlertID != created.AlertID {
				t.Errorf("recurrence previous id = %v, want %q", reopened.PreviousAlertID, created.AlertID)
			}
			closedAfter := loadAlert(t, db, created.AlertID)
			if closedAfter.Status != "CLOSED" {
				t.Errorf("closed alert status = %q, want CLOSED", closedAfter.Status)
			}
			if closedAfter.Version != closedBefore.Version {
				t.Errorf("closed alert version = %d, want %d", closedAfter.Version, closedBefore.Version)
			}
		})
	}
}

func TestApplySerializesConcurrentProposals(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	proposal := newProposal(runID, testEventTime)
	service := &Service{}
	policy := mergePolicy()

	type result struct {
		outcome Outcome
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			var outcome Outcome
			err := db.Transaction(func(tx *gorm.DB) error {
				var applyErr error
				outcome, applyErr = service.Apply(context.Background(), tx, policy, proposal)
				return applyErr
			})
			results <- result{outcome: outcome, err: err}
		}()
	}
	close(start)

	created, noop := 0, 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("Apply: %v", result.err)
		}
		switch result.outcome.Action {
		case ActionCreated:
			created++
		case ActionNoop:
			noop++
		default:
			t.Fatalf("action = %q, want CREATED or NOOP", result.outcome.Action)
		}
	}
	if created != 1 || noop != 1 {
		t.Fatalf("created = %d, noop = %d, want one of each", created, noop)
	}
	if got := countRows(t, db, &alertRow{}); got != 1 {
		t.Errorf("alerts = %d, want 1", got)
	}
	if got := countRows(t, db, &evidenceRow{}); got != 1 {
		t.Errorf("evidence rows = %d, want 1", got)
	}
	if got := countRows(t, db, &occurrenceRow{}); got != 1 {
		t.Errorf("occurrences = %d, want 1", got)
	}
}

func TestApplyCallsHooks(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	hook := &recordingHook{}
	service := &Service{Hooks: hook}
	policy := mergePolicy()
	proposal := newProposal(runID, testEventTime)

	created := applyProposal(t, db, service, policy, proposal)
	if created.Action != ActionCreated {
		t.Fatalf("action = %q, want CREATED", created.Action)
	}
	alert := loadAlert(t, db, created.AlertID)
	if len(hook.created) != 1 {
		t.Fatalf("AlertCreated calls = %d, want 1", len(hook.created))
	}
	newAlert := hook.created[0]
	if newAlert.ID != alert.ID {
		t.Errorf("hook alert id = %q, want %q", newAlert.ID, alert.ID)
	}
	if newAlert.DetectionID != proposal.DetectionID {
		t.Errorf("hook detection id = %q, want %q", newAlert.DetectionID, proposal.DetectionID)
	}
	if newAlert.DetectionVersion != proposal.DetectionVersion {
		t.Errorf("hook detection version = %q, want %q", newAlert.DetectionVersion, proposal.DetectionVersion)
	}
	if newAlert.Title != proposal.Summary {
		t.Errorf("hook title = %q, want %q", newAlert.Title, proposal.Summary)
	}
	if newAlert.Severity != proposal.Severity {
		t.Errorf("hook severity = %q, want %q", newAlert.Severity, proposal.Severity)
	}
	if newAlert.IdentityHash != proposal.IdentityHash {
		t.Errorf("hook identity hash = %q, want %q", newAlert.IdentityHash, proposal.IdentityHash)
	}
	if !newAlert.FirstEventAt.UTC().Equal(testEventTime.UTC()) {
		t.Errorf("hook first event at = %v, want %v", newAlert.FirstEventAt, testEventTime)
	}
	if !newAlert.LastEventAt.UTC().Equal(testEventTime.UTC()) {
		t.Errorf("hook last event at = %v, want %v", newAlert.LastEventAt, testEventTime)
	}
	if newAlert.PreviousAlertID != nil {
		t.Errorf("hook previous alert id = %q, want nil", *newAlert.PreviousAlertID)
	}

	mergeTime := testEventTime.Add(10 * time.Minute)
	merged := applyProposal(t, db, service, policy, newProposal(runID, mergeTime, mergeTime.Add(time.Minute), mergeTime.Add(2*time.Minute)))
	if merged.Action != ActionMerged {
		t.Fatalf("merge action = %q, want MERGED", merged.Action)
	}
	if len(hook.evidence) != 1 {
		t.Fatalf("EvidenceAdded calls = %d, want 1", len(hook.evidence))
	}
	mergeCall := hook.evidence[0]
	alertAfterMerge := loadAlert(t, db, alert.ID)
	if mergeCall.AlertID != alert.ID {
		t.Errorf("EvidenceAdded alert id = %q, want %q", mergeCall.AlertID, alert.ID)
	}
	if mergeCall.Added != 3 {
		t.Errorf("EvidenceAdded added = %d, want 3", mergeCall.Added)
	}
	if !mergeCall.LastEventAt.UTC().Equal(alertAfterMerge.LastEventAt.UTC()) {
		t.Errorf("EvidenceAdded last event at = %v, want %v", mergeCall.LastEventAt, alertAfterMerge.LastEventAt)
	}

	split := applyProposal(t, db, service, policy, newProposal(runID, testEventTime.Add(5*time.Hour)))
	if split.Action != ActionCreated {
		t.Fatalf("split action = %q, want CREATED", split.Action)
	}
	if len(hook.created) != 2 {
		t.Fatalf("AlertCreated calls = %d, want 2", len(hook.created))
	}
	if hook.created[1].PreviousAlertID == nil || *hook.created[1].PreviousAlertID != alert.ID {
		t.Errorf("split hook previous id = %v, want %q", hook.created[1].PreviousAlertID, alert.ID)
	}
}

func TestApplyHookErrorRollsBack(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	sentinel := errors.New("case write failed")
	hook := &recordingHook{createdError: sentinel}
	service := &Service{Hooks: hook}

	err := db.Transaction(func(tx *gorm.DB) error {
		_, err := service.Apply(context.Background(), tx, mergePolicy(), newProposal(runID, testEventTime))
		return err
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Apply error = %v, want %v", err, sentinel)
	}

	rows := []struct {
		name  string
		model any
	}{
		{"alerts", &alertRow{}},
		{"alert_evidence", &evidenceRow{}},
		{"alert_occurrences", &occurrenceRow{}},
	}
	for _, row := range rows {
		if got := countRows(t, db, row.model); got != 0 {
			t.Errorf("%s rows = %d, want 0", row.name, got)
		}
	}
	if got := len(storedAuditEvents(t, db, "simple_siem.alert.created")); got != 0 {
		t.Errorf("alert.created audit events = %d, want 0", got)
	}
}

func TestApplyGuardrailSwitchesDetection(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	if err := db.Transaction(func(tx *gorm.DB) error {
		return EnsureRuntime(tx, testDetectionID, "ENABLED")
	}); err != nil {
		t.Fatalf("EnsureRuntime: %v", err)
	}
	hook := &recordingHook{createdOutcome: CaseOutcome{GuardrailTripped: true}}
	service := &Service{Hooks: hook}

	outcome := applyProposal(t, db, service, mergePolicy(), newProposal(runID, testEventTime))
	if !outcome.GuardrailTripped {
		t.Error("guardrail tripped = false, want true")
	}
	if got := countRows(t, db, &alertRow{}); got != 1 {
		t.Errorf("alerts = %d, want 1", got)
	}

	runtime := loadRuntime(t, db, testDetectionID)
	if runtime.Status != "SHADOW" {
		t.Errorf("runtime status = %q, want SHADOW", runtime.Status)
	}
	if runtime.Reason == nil || *runtime.Reason != "case_rate_exceeded" {
		t.Errorf("runtime reason = %v, want case_rate_exceeded", runtime.Reason)
	}
	if runtime.Version != 2 {
		t.Errorf("runtime version = %d, want 2", runtime.Version)
	}

	events := storedAuditEvents(t, db, "simple_siem.detection.status_changed")
	if len(events) != 1 {
		t.Fatalf("status change audit events = %d, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "DETECTION" {
		t.Errorf("audit category = %q, want DETECTION", event.EventCategory)
	}
	if event.EventOutcome != "SUCCESS" {
		t.Errorf("audit outcome = %q, want SUCCESS", event.EventOutcome)
	}
	if event.ActorType != "SYSTEM" {
		t.Errorf("audit actor type = %q, want SYSTEM", event.ActorType)
	}
	if event.TargetType != "DETECTION" || event.TargetID != testDetectionID {
		t.Errorf("audit target = %q/%q, want DETECTION/%q", event.TargetType, event.TargetID, testDetectionID)
	}
	if event.Action != "update" {
		t.Errorf("audit action = %q, want update", event.Action)
	}
	if event.Changes["from"] != "ENABLED" || event.Changes["to"] != "SHADOW" || event.Changes["reason"] != "case_rate_exceeded" {
		t.Errorf("audit changes = %v, want from ENABLED to SHADOW for case_rate_exceeded", event.Changes)
	}

	outboxEvents := storedOutboxEvents(t, db)
	if len(outboxEvents) != 1 {
		t.Fatalf("outbox rows = %d, want 1", len(outboxEvents))
	}
	outboxEvent := outboxEvents[0]
	if outboxEvent.Type != outbox.TypeDetectionStatusChanged {
		t.Errorf("outbox type = %q, want %q", outboxEvent.Type, outbox.TypeDetectionStatusChanged)
	}
	if outboxEvent.Version != 1 {
		t.Errorf("outbox version = %d, want 1", outboxEvent.Version)
	}
	if outboxEvent.SubjectType != "detection" || outboxEvent.SubjectID != testDetectionID {
		t.Errorf("outbox subject = %q/%q, want detection/%q", outboxEvent.SubjectType, outboxEvent.SubjectID, testDetectionID)
	}
	var actor outbox.Actor
	if err := json.Unmarshal(outboxEvent.Actor, &actor); err != nil {
		t.Fatalf("decode outbox actor: %v", err)
	}
	if actor != (outbox.Actor{Type: outbox.ActorSystem, ID: "detection-engine"}) {
		t.Errorf("outbox actor = %+v, want the detection engine", actor)
	}
	var payload map[string]any
	if err := json.Unmarshal(outboxEvent.Payload, &payload); err != nil {
		t.Fatalf("decode outbox payload: %v", err)
	}
	if payload["detectionId"] != testDetectionID || payload["from"] != "ENABLED" ||
		payload["to"] != "SHADOW" || payload["reason"] != "case_rate_exceeded" {
		t.Errorf("outbox payload = %v, want the status change", payload)
	}
}

func TestApplyGuardrailLeavesShadowDetection(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	if err := db.Transaction(func(tx *gorm.DB) error {
		return EnsureRuntime(tx, testDetectionID, "SHADOW")
	}); err != nil {
		t.Fatalf("EnsureRuntime: %v", err)
	}
	before := loadRuntime(t, db, testDetectionID)
	hook := &recordingHook{createdOutcome: CaseOutcome{GuardrailTripped: true}}
	service := &Service{Hooks: hook}

	outcome := applyProposal(t, db, service, mergePolicy(), newProposal(runID, testEventTime))
	if !outcome.GuardrailTripped {
		t.Error("guardrail tripped = false, want true")
	}
	after := loadRuntime(t, db, testDetectionID)
	if after.Status != "SHADOW" {
		t.Errorf("runtime status = %q, want SHADOW", after.Status)
	}
	if after.Version != before.Version {
		t.Errorf("runtime version = %d, want %d", after.Version, before.Version)
	}
	if after.Reason != nil {
		t.Errorf("runtime reason = %q, want nil", *after.Reason)
	}
	if got := len(storedAuditEvents(t, db, "simple_siem.detection.status_changed")); got != 0 {
		t.Errorf("status change audit events = %d, want 0", got)
	}
	if got := countOutboxEvents(t, db); got != 0 {
		t.Errorf("outbox rows = %d, want 0", got)
	}
	if got := countRows(t, db, &alertRow{}); got != 1 {
		t.Errorf("alerts = %d, want 1", got)
	}
}

func TestApplyGuardrailRollsBackWithTransaction(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	if err := db.Transaction(func(tx *gorm.DB) error {
		return EnsureRuntime(tx, testDetectionID, "ENABLED")
	}); err != nil {
		t.Fatalf("EnsureRuntime: %v", err)
	}
	hook := &recordingHook{createdOutcome: CaseOutcome{GuardrailTripped: true}}
	service := &Service{Hooks: hook}
	sentinel := errors.New("caller rolled back")

	err := db.Transaction(func(tx *gorm.DB) error {
		if _, err := service.Apply(context.Background(), tx, mergePolicy(), newProposal(runID, testEventTime)); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("transaction error = %v, want %v", err, sentinel)
	}

	runtime := loadRuntime(t, db, testDetectionID)
	if runtime.Status != "ENABLED" {
		t.Errorf("runtime status = %q, want ENABLED", runtime.Status)
	}
	if runtime.Version != 1 {
		t.Errorf("runtime version = %d, want 1", runtime.Version)
	}
	if got := countRows(t, db, &alertRow{}); got != 0 {
		t.Errorf("alerts = %d, want 0", got)
	}
	if got := len(storedAuditEvents(t, db, "simple_siem.detection.status_changed")); got != 0 {
		t.Errorf("status change audit events = %d, want 0", got)
	}
	if got := countOutboxEvents(t, db); got != 0 {
		t.Errorf("outbox rows = %d, want 0", got)
	}
}

func TestEnsureRuntimeKeepsFirstStatus(t *testing.T) {
	db := databasetest.New(t)

	for _, status := range []string{"ENABLED", "SHADOW"} {
		if err := db.Transaction(func(tx *gorm.DB) error {
			return EnsureRuntime(tx, testDetectionID, status)
		}); err != nil {
			t.Fatalf("EnsureRuntime(%q): %v", status, err)
		}
	}

	status, err := Status(db, testDetectionID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status != "ENABLED" {
		t.Errorf("status = %q, want ENABLED", status)
	}
	runtime := loadRuntime(t, db, testDetectionID)
	if runtime.Version != 1 {
		t.Errorf("runtime version = %d, want 1", runtime.Version)
	}
}

func TestStatusUnknownDetectionFails(t *testing.T) {
	db := databasetest.New(t)

	if _, err := Status(db, "missing-detection"); err == nil {
		t.Fatal("Status of an unknown detection returned nil error")
	}
}

func mergePolicy() Policy {
	return Policy{Mode: ModeMerge, CoalesceWindow: 2 * time.Hour, MaxAlertSpan: 24 * time.Hour}
}

func newProposal(runID string, eventTimes ...time.Time) Proposal {
	userName := "alice"
	evidence := make([]Evidence, len(eventTimes))
	for index, eventTime := range eventTimes {
		evidence[index] = Evidence{
			SourceKey: dataset.SourceKey{
				FetcherInstanceID: "fetcher-1",
				Index:             "auth-*",
				DocumentID:        fmt.Sprintf("doc-%d", eventTime.UnixNano()),
			},
			EventTime: eventTime,
		}
	}
	return Proposal{
		DetectionID:           testDetectionID,
		DetectionVersion:      "2026.11.14",
		DetectionRunID:        runID,
		IdentityHash:          testIdentityHash,
		IdentitySchemaVersion: 1,
		Identity:              map[string]*string{"user.name": &userName, "host.name": nil},
		Subject: udm.Event{
			Metadata:  udm.Metadata{EventTimestamp: testEventTime, VendorName: "linux"},
			Principal: udm.Noun{Hostname: "web01"},
		},
		Summary:  "brute force",
		Details:  map[string]string{"failures": "13"},
		Severity: SeverityHigh,
		Evidence: evidence,
	}
}

func applyProposal(t *testing.T, db *gorm.DB, service *Service, policy Policy, proposal Proposal) Outcome {
	t.Helper()
	var outcome Outcome
	err := db.Transaction(func(tx *gorm.DB) error {
		var applyErr error
		outcome, applyErr = service.Apply(context.Background(), tx, policy, proposal)
		return applyErr
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return outcome
}

func countRows(t *testing.T, db *gorm.DB, model any) int64 {
	t.Helper()
	var count int64
	if err := db.Model(model).Count(&count).Error; err != nil {
		t.Fatalf("count %T rows: %v", model, err)
	}
	return count
}

func countOutboxEvents(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var count int64
	if err := db.Raw("SELECT count(*) FROM event_outbox").Scan(&count).Error; err != nil {
		t.Fatalf("count outbox rows: %v", err)
	}
	return count
}

func loadAlert(t *testing.T, db *gorm.DB, id string) alertRow {
	t.Helper()
	var alert alertRow
	if err := db.First(&alert, "id = ?", id).Error; err != nil {
		t.Fatalf("load alert %q: %v", id, err)
	}
	return alert
}

func closeAlert(t *testing.T, db *gorm.DB, alertID string) {
	t.Helper()
	if err := db.Exec("UPDATE alerts SET status = 'CLOSED' WHERE id = ?", alertID).Error; err != nil {
		t.Fatalf("close alert %q: %v", alertID, err)
	}
}

func loadAlerts(t *testing.T, db *gorm.DB) []alertRow {
	t.Helper()
	var alerts []alertRow
	if err := db.Order("first_event_at, id").Find(&alerts).Error; err != nil {
		t.Fatalf("load alerts: %v", err)
	}
	return alerts
}

func loadOccurrences(t *testing.T, db *gorm.DB, alertID string) []occurrenceRow {
	t.Helper()
	var occurrences []occurrenceRow
	if err := db.Where("alert_id = ?", alertID).Order("observed_at, id").Find(&occurrences).Error; err != nil {
		t.Fatalf("load occurrences of alert %q: %v", alertID, err)
	}
	return occurrences
}

func loadRuntime(t *testing.T, db *gorm.DB, detectionID string) runtimeRow {
	t.Helper()
	var runtime runtimeRow
	if err := db.First(&runtime, "detection_id = ?", detectionID).Error; err != nil {
		t.Fatalf("load detection runtime %q: %v", detectionID, err)
	}
	return runtime
}

func storedAuditEvents(t *testing.T, db *gorm.DB, eventName string) []audit.Event {
	t.Helper()
	events, _, err := audit.List(context.Background(), db, audit.Filter{EventName: eventName}, 1, 100)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	return events
}

func storedOutboxEvents(t *testing.T, db *gorm.DB) []outboxEventRow {
	t.Helper()
	var rows []outboxEventRow
	err := db.Raw(`
		SELECT type, version, actor, subject_type, subject_id, payload
		FROM event_outbox
		ORDER BY occurred_at, id`).Scan(&rows).Error
	if err != nil {
		t.Fatalf("load outbox rows: %v", err)
	}
	return rows
}

func TestApplySplitsBackfillBeforeSpan(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	service := &Service{}
	policy := Policy{Mode: ModeMerge, CoalesceWindow: 15 * time.Minute, MaxAlertSpan: time.Hour}

	created := applyProposal(t, db, service, policy,
		newProposal(runID, testEventTime, testEventTime.Add(30*time.Minute)))
	if created.Action != ActionCreated {
		t.Fatalf("first action = %q, want CREATED", created.Action)
	}

	backfill := applyProposal(t, db, service, policy,
		newProposal(runID, testEventTime.Add(-2*time.Hour), testEventTime.Add(-115*time.Minute)))
	if backfill.Action != ActionCreated {
		t.Fatalf("backfill action = %q, want CREATED (a split)", backfill.Action)
	}
	oldAlert := loadAlert(t, db, created.AlertID)
	if oldAlert.Coalescing {
		t.Error("old alert coalescing = true, want false")
	}
	if oldAlert.Status != "OPEN" {
		t.Errorf("old alert status = %q, want OPEN", oldAlert.Status)
	}
	newAlert := loadAlert(t, db, backfill.AlertID)
	if newAlert.PreviousAlertID == nil || *newAlert.PreviousAlertID != created.AlertID {
		t.Errorf("backfill previous id = %v, want %q", newAlert.PreviousAlertID, created.AlertID)
	}
	if got := countRows(t, db, &alertRow{}); got != 2 {
		t.Errorf("alerts = %d, want 2", got)
	}
}

func TestApplyMergesNearBackfill(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	service := &Service{}
	policy := Policy{Mode: ModeMerge, CoalesceWindow: 15 * time.Minute, MaxAlertSpan: time.Hour}

	created := applyProposal(t, db, service, policy,
		newProposal(runID, testEventTime, testEventTime.Add(30*time.Minute)))
	merged := applyProposal(t, db, service, policy, newProposal(runID, testEventTime.Add(-10*time.Minute)))
	if merged.Action != ActionMerged {
		t.Fatalf("near backfill action = %q, want MERGED", merged.Action)
	}
	alert := loadAlert(t, db, created.AlertID)
	if !alert.FirstEventAt.UTC().Equal(testEventTime.Add(-10 * time.Minute).UTC()) {
		t.Errorf("first event at = %v, want %v", alert.FirstEventAt, testEventTime.Add(-10*time.Minute))
	}
	if !alert.LastEventAt.UTC().Equal(testEventTime.Add(30 * time.Minute).UTC()) {
		t.Errorf("last event at = %v, want %v", alert.LastEventAt, testEventTime.Add(30*time.Minute))
	}
}

func TestApplyMergeCountsInsertedEvidence(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	service := &Service{}
	policy := Policy{Mode: ModeUnique, CoalesceWindow: 2 * time.Hour, MaxAlertSpan: time.Hour}

	first := newProposal(runID, testEventTime)
	created := applyProposal(t, db, service, policy, first)
	if created.Action != ActionCreated {
		t.Fatalf("first action = %q, want CREATED", created.Action)
	}

	later := testEventTime.Add(4 * time.Hour)
	proposal := newProposal(runID, later)
	proposal.Evidence = []Evidence{
		{SourceKey: first.Evidence[0].SourceKey, EventTime: later},
		{SourceKey: dataset.SourceKey{FetcherInstanceID: "fetcher-1", Index: "auth-*", DocumentID: "fresh"}, EventTime: later},
	}
	outcome := applyProposal(t, db, service, policy, proposal)
	if outcome.Action != ActionMerged {
		t.Fatalf("merge action = %q, want MERGED", outcome.Action)
	}
	if outcome.NewEvidence != 1 {
		t.Errorf("new evidence = %d, want the one row actually inserted", outcome.NewEvidence)
	}
	alert := loadAlert(t, db, created.AlertID)
	if alert.EvidenceCount != 2 {
		t.Errorf("evidence count = %d, want 2", alert.EvidenceCount)
	}
	if got := countRows(t, db, &evidenceRow{}); got != 2 {
		t.Errorf("evidence rows = %d, want 2", got)
	}
	occurrences := loadOccurrences(t, db, created.AlertID)
	if len(occurrences) != 2 {
		t.Fatalf("occurrences = %d, want 2", len(occurrences))
	}
	if occurrences[1].NewEvidenceCount != 1 {
		t.Errorf("occurrence new evidence = %d, want 1", occurrences[1].NewEvidenceCount)
	}
}

func TestApplyMergeWithOnlyConflictsIsNoop(t *testing.T) {
	db := databasetest.New(t)
	runID := insertRun(t, db, testDetectionID)
	hook := &recordingHook{}
	service := &Service{Hooks: hook}
	policy := Policy{Mode: ModeUnique, CoalesceWindow: 2 * time.Hour, MaxAlertSpan: time.Hour}

	first := newProposal(runID, testEventTime)
	created := applyProposal(t, db, service, policy, first)
	before := loadAlert(t, db, created.AlertID)
	occurrencesBefore := len(loadOccurrences(t, db, created.AlertID))

	later := testEventTime.Add(4 * time.Hour)
	conflict := newProposal(runID, later)
	conflict.Evidence = []Evidence{{SourceKey: first.Evidence[0].SourceKey, EventTime: later}}
	outcome := applyProposal(t, db, service, policy, conflict)
	if outcome.Action != ActionNoop {
		t.Fatalf("action = %q, want NOOP when the insert added no evidence", outcome.Action)
	}
	if outcome.NewEvidence != 0 {
		t.Errorf("new evidence = %d, want 0", outcome.NewEvidence)
	}
	after := loadAlert(t, db, created.AlertID)
	if after.EvidenceCount != before.EvidenceCount || after.OccurrenceCount != before.OccurrenceCount || after.Version != before.Version {
		t.Errorf("alert after conflict = evidence %d, occurrences %d, version %d; want %d, %d, %d",
			after.EvidenceCount, after.OccurrenceCount, after.Version,
			before.EvidenceCount, before.OccurrenceCount, before.Version)
	}
	if got := len(loadOccurrences(t, db, created.AlertID)); got != occurrencesBefore {
		t.Errorf("occurrences = %d, want %d", got, occurrencesBefore)
	}
	if len(hook.evidence) != 0 {
		t.Errorf("EvidenceAdded calls = %d, want 0", len(hook.evidence))
	}
}
