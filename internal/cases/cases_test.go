package cases

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/alerts"
	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/outbox"
	"gorm.io/gorm"
)

const testPublicURL = "https://siem.example.com"

var (
	testNow          = time.Date(2026, 11, 15, 10, 15, 0, 0, time.UTC)
	testFirstEventAt = testNow.Add(-10 * time.Minute)
	testLastEventAt  = testNow.Add(-5 * time.Minute)
)

func TestAlertCreatedOpensCase(t *testing.T) {
	service, db := newTestService(t, 50)
	alertID := insertAlert(t, db, "brute-force", "Brute force", alerts.SeverityHigh)

	runAlertCreated(t, service, db, alerts.NewAlert{
		ID:           alertID,
		DetectionID:  "brute-force",
		Title:        "  Brute force  ",
		Severity:     alerts.SeverityHigh,
		FirstEventAt: testFirstEventAt,
		LastEventAt:  testLastEventAt,
	})

	stored := loadCaseForAlert(t, db, alertID)
	if stored.Title != "Brute force" {
		t.Errorf("case title = %q, want the trimmed %q", stored.Title, "Brute force")
	}
	if stored.Severity != string(alerts.SeverityHigh) {
		t.Errorf("case severity = %q, want %q", stored.Severity, alerts.SeverityHigh)
	}
	if stored.Status != StatusOpen {
		t.Errorf("case status = %q, want %q", stored.Status, StatusOpen)
	}
	if stored.DetectionID != "brute-force" {
		t.Errorf("case detection = %q, want %q", stored.DetectionID, "brute-force")
	}
	if !stored.FirstEventAt.Equal(testFirstEventAt) || !stored.LastEventAt.Equal(testLastEventAt) {
		t.Errorf("case events = %v to %v, want %v to %v",
			stored.FirstEventAt, stored.LastEventAt, testFirstEventAt, testLastEventAt)
	}
	if stored.AssigneeUserID != nil {
		t.Errorf("case assignee = %q, want none", *stored.AssigneeUserID)
	}

	var sequence int64
	if err := db.Raw("SELECT last_value FROM case_number_seq").Scan(&sequence).Error; err != nil {
		t.Fatalf("read case number sequence: %v", err)
	}
	if stored.CaseNumber != sequence {
		t.Errorf("case number = %d, want the sequence value %d", stored.CaseNumber, sequence)
	}

	if links := countRows(t, db, "case_alerts WHERE case_id = ? AND alert_id = ?", stored.ID, alertID); links != 1 {
		t.Errorf("case has %d links to its alert, want 1", links)
	}

	audits, total, err := audit.List(context.Background(), db,
		audit.Filter{TargetType: "CASE", TargetID: stored.ID}, 1, 100)
	if err != nil {
		t.Fatalf("read case audit events: %v", err)
	}
	if total != 2 || len(audits) != 2 {
		t.Fatalf("case has %d audit events, want 2", total)
	}
	created, ok := findAuditEvent(audits, eventCaseCreated)
	if !ok {
		t.Fatalf("no %s audit event", eventCaseCreated)
	}
	expectSystemCaseEvent(t, created, "create")
	added, ok := findAuditEvent(audits, eventCaseAlertAdded)
	if !ok {
		t.Fatalf("no %s audit event", eventCaseAlertAdded)
	}
	expectSystemCaseEvent(t, added, "add_alert")
	if want := map[string]any{"alertId": alertID}; !reflect.DeepEqual(added.Changes, want) {
		t.Errorf("alert_added changes = %v, want %v", added.Changes, want)
	}

	events := outboxEventsOfType(t, db, outbox.TypeCaseCreated)
	if len(events) != 1 {
		t.Fatalf("outbox has %d case.created rows, want 1", len(events))
	}
	event := events[0]
	if event.Version != 1 {
		t.Errorf("case.created version = %d, want 1", event.Version)
	}
	if event.SubjectType != "case" || event.SubjectID != stored.ID {
		t.Errorf("case.created subject = %s/%s, want case/%s", event.SubjectType, event.SubjectID, stored.ID)
	}
	var actor outbox.Actor
	if err := json.Unmarshal(event.Actor, &actor); err != nil {
		t.Fatalf("decode case.created actor: %v", err)
	}
	if actor != (outbox.Actor{Type: outbox.ActorSystem, ID: detectionEngineActorID}) {
		t.Errorf("case.created actor = %+v, want the detection engine", actor)
	}

	want := map[string]any{
		"caseId":      stored.ID,
		"caseNumber":  float64(stored.CaseNumber),
		"title":       "Brute force",
		"severity":    string(alerts.SeverityHigh),
		"detectionId": "brute-force",
		"alertId":     alertID,
		"link":        testPublicURL + "/cases/" + strconv.FormatInt(stored.CaseNumber, 10),
	}
	if payload := decodeObject(t, event.Payload); !reflect.DeepEqual(payload, want) {
		t.Errorf("case.created payload = %v, want %v", payload, want)
	}
}

func TestAlertCreatedRollsBackWithTransaction(t *testing.T) {
	service, db := newTestService(t, 50)
	alertID := insertAlert(t, db, "brute-force", "Brute force", alerts.SeverityHigh)
	rollback := errors.New("roll back the alert")

	err := db.Transaction(func(tx *gorm.DB) error {
		if _, err := service.AlertCreated(context.Background(), tx, newAlert(alertID, "brute-force", "Brute force")); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("transaction error = %v, want %v", err, rollback)
	}
	expectNoCaseWrites(t, db, "after the rollback")
}

func TestAlertCreatedNormalizesTitle(t *testing.T) {
	service, db := newTestService(t, 50)
	tests := []struct {
		name  string
		title string
		want  string
	}{
		{"empty", "", "Alert from detection-1"},
		{"blank", "   ", "Alert from detection-1"},
		{"over 500 runes", strings.Repeat("é", 501), strings.Repeat("é", 500)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, stored := openAlertCase(t, service, db, "detection-1", test.title)
			if stored.Title != test.want {
				t.Errorf("case title = %q (%d runes), want %q (%d runes)",
					stored.Title, len([]rune(stored.Title)), test.want, len([]rune(test.want)))
			}
		})
	}
}

func TestAlertCreatedRejectsInvalidSeverity(t *testing.T) {
	service, db := newTestService(t, 50)
	alertID := insertAlert(t, db, "detection-1", "summary", alerts.SeverityHigh)

	err := db.Transaction(func(tx *gorm.DB) error {
		alert := newAlert(alertID, "detection-1", "Brute force")
		alert.Severity = alerts.Severity("CRITICAL")
		_, err := service.AlertCreated(context.Background(), tx, alert)
		return err
	})
	if !errors.Is(err, ErrInvalidSeverity) {
		t.Fatalf("AlertCreated error = %v, want ErrInvalidSeverity", err)
	}
	expectNoCaseWrites(t, db, "after an invalid severity")
}

func TestAlertCreatedAssignsOnCallInRotation(t *testing.T) {
	service, db := newTestService(t, 50)
	firstUser := createUser(t, db, "first@example.com", "ANALYST")
	secondUser := createUser(t, db, "second@example.com", "ANALYST")
	rotation := []string{firstUser, secondUser}
	slices.Sort(rotation)
	want := []string{rotation[0], rotation[1], rotation[0]}

	opened := make([]caseRow, len(want))
	for index, assignee := range want {
		_, _, stored := openAlertCase(t, service, db, "brute-force", "Brute force")
		opened[index] = stored
		if stored.AssigneeUserID == nil {
			t.Fatalf("case %d has no assignee, want %q", index+1, assignee)
		}
		if *stored.AssigneeUserID != assignee {
			t.Errorf("case %d assignee = %q, want %q", index+1, *stored.AssigneeUserID, assignee)
		}
		if stored.Status != StatusOpen {
			t.Errorf("case %d status = %q, want %q", index+1, stored.Status, StatusOpen)
		}

		audits, total, err := audit.List(context.Background(), db,
			audit.Filter{TargetType: "CASE", TargetID: stored.ID}, 1, 100)
		if err != nil {
			t.Fatalf("read case %d audit events: %v", index+1, err)
		}
		if total != 3 {
			t.Fatalf("case %d has %d audit events, want 3", index+1, total)
		}
		assigned, ok := findAuditEvent(audits, eventCaseAssigned)
		if !ok {
			t.Fatalf("case %d has no %s audit event", index+1, eventCaseAssigned)
		}
		expectSystemCaseEvent(t, assigned, "assign")
		wantChanges := map[string]any{"assigneeId": assignee, "onCall": true}
		if !reflect.DeepEqual(assigned.Changes, wantChanges) {
			t.Errorf("case %d assigned changes = %v, want %v", index+1, assigned.Changes, wantChanges)
		}
	}

	if lastUserID := loadRotation(t, db); lastUserID == nil {
		t.Errorf("rotation last user is unset, want %q", want[len(want)-1])
	} else if *lastUserID != want[len(want)-1] {
		t.Errorf("rotation last user = %q, want %q", *lastUserID, want[len(want)-1])
	}

	events := outboxEventsOfType(t, db, outbox.TypeCaseAssigned)
	if len(events) != len(want) {
		t.Fatalf("outbox has %d case.assigned rows, want %d", len(events), len(want))
	}
	for index, event := range events {
		wantPayload := map[string]any{
			"caseId":     opened[index].ID,
			"caseNumber": float64(opened[index].CaseNumber),
			"assigneeId": want[index],
			"onCall":     true,
			"link":       testPublicURL + "/cases/" + strconv.FormatInt(opened[index].CaseNumber, 10),
		}
		if payload := decodeObject(t, event.Payload); !reflect.DeepEqual(payload, wantPayload) {
			t.Errorf("case.assigned %d payload = %v, want %v", index+1, payload, wantPayload)
		}
	}
}

func TestAlertCreatedLeavesCaseUnassignedWithoutOnCall(t *testing.T) {
	service, db := newTestService(t, 50)

	_, _, stored := openAlertCase(t, service, db, "brute-force", "Brute force")

	if stored.AssigneeUserID != nil {
		t.Errorf("case assignee = %q, want none", *stored.AssigneeUserID)
	}
	if events := outboxEventsOfType(t, db, outbox.TypeCaseAssigned); len(events) != 0 {
		t.Errorf("outbox has %d case.assigned rows, want 0", len(events))
	}
	if lastUserID := loadRotation(t, db); lastUserID != nil {
		t.Errorf("rotation last user = %q, want none", *lastUserID)
	}
}

func TestAlertCreatedSkipsOnCallUsersWhoCannotTakeTheCase(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, db *gorm.DB)
	}{
		{
			name: "user without case:write",
			prepare: func(t *testing.T, db *gorm.DB) {
				createUser(t, db, "reader@example.com", "READ_ONLY")
			},
		},
		{
			name: "disabled user",
			prepare: func(t *testing.T, db *gorm.DB) {
				userID := createUser(t, db, "disabled@example.com", "ANALYST")
				if err := db.Exec("UPDATE users SET status = 'DISABLED' WHERE id = ?", userID).Error; err != nil {
					t.Fatalf("disable user: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, db := newTestService(t, 50)
			test.prepare(t, db)

			if _, _, stored := openAlertCase(t, service, db, "brute-force", "Brute force"); stored.AssigneeUserID != nil {
				t.Errorf("case assignee = %q, want none", *stored.AssigneeUserID)
			}
		})
	}
}

func TestOnCallRotationIsSerialized(t *testing.T) {
	service, db := newTestService(t, 50)
	firstUser := createUser(t, db, "first@example.com", "ANALYST")
	secondUser := createUser(t, db, "second@example.com", "ANALYST")
	onCall := []string{firstUser, secondUser}

	detections := []string{"detection-a", "detection-b"}
	alertIDs := make([]string, len(detections))
	inputs := make([]alerts.NewAlert, len(detections))
	for index, detectionID := range detections {
		alertIDs[index] = insertAlert(t, db, detectionID, "Concurrent", alerts.SeverityHigh)
		inputs[index] = newAlert(alertIDs[index], detectionID, "Concurrent")
	}

	start := make(chan struct{})
	errs := make([]error, len(inputs))
	var wait sync.WaitGroup
	for index := range inputs {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			errs[index] = db.Transaction(func(tx *gorm.DB) error {
				_, err := service.AlertCreated(context.Background(), tx, inputs[index])
				return err
			})
		}(index)
	}
	close(start)
	wait.Wait()

	for index, err := range errs {
		if err != nil {
			t.Fatalf("AlertCreated %d: %v", index+1, err)
		}
	}
	assignees := make([]string, len(alertIDs))
	for index, alertID := range alertIDs {
		stored := loadCaseForAlert(t, db, alertID)
		if stored.AssigneeUserID == nil {
			t.Fatalf("case %d has no assignee", index+1)
		}
		if !slices.Contains(onCall, *stored.AssigneeUserID) {
			t.Errorf("case %d assignee = %q, want one of the on-call users", index+1, *stored.AssigneeUserID)
		}
		assignees[index] = *stored.AssigneeUserID
	}
	if assignees[0] == assignees[1] {
		t.Errorf("both cases went to %q, want two different on-call users", assignees[0])
	}
}

func TestGuardrailReportsFirstCrossingPerHour(t *testing.T) {
	service, db := newTestService(t, 2)

	for index := 1; index <= 2; index++ {
		outcome, _, _ := openAlertCase(t, service, db, "noisy", "Noisy")
		if outcome.GuardrailTripped {
			t.Fatalf("case %d tripped the guardrail, want no report", index)
		}
	}

	outcome, _, _ := openAlertCase(t, service, db, "noisy", "Noisy")
	if !outcome.GuardrailTripped {
		t.Fatalf("case 3 did not trip the guardrail, want the first crossing reported")
	}

	if outcome, _, _ := openAlertCase(t, service, db, "noisy", "Noisy"); outcome.GuardrailTripped {
		t.Errorf("case 4 reported the guardrail again, want only the first crossing")
	}
	if outcome, _, _ := openAlertCase(t, service, db, "quiet", "Quiet"); outcome.GuardrailTripped {
		t.Errorf("another detection tripped the guardrail, want its own count")
	}

	if count := countRows(t, db, "event_outbox WHERE type = 'detection.status_changed'"); count != 0 {
		t.Errorf("outbox has %d detection.status_changed rows, want 0", count)
	}
	if count := countRows(t, db, "audit_events WHERE event_name LIKE '%detection.status_changed%'"); count != 0 {
		t.Errorf("audit has %d detection.status_changed rows, want 0", count)
	}

	service.now = func() time.Time { return testNow.Add(time.Hour) }
	if outcome, _, _ := openAlertCase(t, service, db, "noisy", "Noisy"); outcome.GuardrailTripped {
		t.Errorf("the next hour tripped the guardrail, want a fresh count")
	}
}

func TestEvidenceAddedMovesLastEventForward(t *testing.T) {
	service, db := newTestService(t, 50)
	_, alertID, before := openAlertCase(t, service, db, "brute-force", "Brute force")

	later := testLastEventAt.Add(30 * time.Minute)
	runEvidenceAdded(t, service, db, alertID, later, 3)

	after := loadCaseForAlert(t, db, alertID)
	if !after.LastEventAt.Equal(later) {
		t.Errorf("case last event = %v, want %v", after.LastEventAt, later)
	}
	if after.Version != before.Version+1 {
		t.Errorf("case version = %d, want %d", after.Version, before.Version+1)
	}

	events := outboxEventsOfType(t, db, outbox.TypeCaseEvidenceAdded)
	if len(events) != 1 {
		t.Fatalf("outbox has %d case.evidence_added rows, want 1", len(events))
	}
	want := map[string]any{
		"caseId":     after.ID,
		"caseNumber": float64(after.CaseNumber),
		"alertId":    alertID,
		"added":      float64(3),
		"link":       testPublicURL + "/cases/" + strconv.FormatInt(after.CaseNumber, 10),
	}
	if payload := decodeObject(t, events[0].Payload); !reflect.DeepEqual(payload, want) {
		t.Errorf("case.evidence_added payload = %v, want %v", payload, want)
	}
}

func TestEvidenceAddedKeepsLastEventWhenEvidenceIsOlder(t *testing.T) {
	service, db := newTestService(t, 50)
	_, alertID, before := openAlertCase(t, service, db, "brute-force", "Brute force")

	runEvidenceAdded(t, service, db, alertID, testFirstEventAt, 1)

	after := loadCaseForAlert(t, db, alertID)
	if !after.LastEventAt.Equal(before.LastEventAt) {
		t.Errorf("case last event moved back to %v, want it to stay at %v", after.LastEventAt, before.LastEventAt)
	}
	if after.Version != before.Version+1 {
		t.Errorf("case version = %d, want %d", after.Version, before.Version+1)
	}
}

func TestEvidenceAddedChangesNothingForClosedCase(t *testing.T) {
	service, db := newTestService(t, 50)
	_, alertID, before := openAlertCase(t, service, db, "brute-force", "Brute force")
	if err := db.Exec("UPDATE cases SET status = ? WHERE id = ?", StatusClosed, before.ID).Error; err != nil {
		t.Fatalf("close case: %v", err)
	}
	eventsBefore := countRows(t, db, "event_outbox WHERE type = 'case.evidence_added'")

	runEvidenceAdded(t, service, db, alertID, testLastEventAt.Add(time.Hour), 2)

	after := loadCaseForAlert(t, db, alertID)
	if !after.LastEventAt.Equal(before.LastEventAt) || after.Version != before.Version {
		t.Errorf("closed case moved to %v version %d, want %v version %d",
			after.LastEventAt, after.Version, before.LastEventAt, before.Version)
	}
	if events := countRows(t, db, "event_outbox WHERE type = 'case.evidence_added'"); events != eventsBefore {
		t.Errorf("outbox gained %d case.evidence_added rows for a closed case, want none", events-eventsBefore)
	}
}

func TestEvidenceAddedIgnoresAlertWithoutCase(t *testing.T) {
	service, db := newTestService(t, 50)
	alertID := insertAlert(t, db, "brute-force", "Brute force", alerts.SeverityHigh)

	runEvidenceAdded(t, service, db, alertID, testLastEventAt, 1)

	if events := countRows(t, db, "event_outbox WHERE type = 'case.evidence_added'"); events != 0 {
		t.Errorf("outbox has %d case.evidence_added rows, want 0", events)
	}
}

func newTestService(t *testing.T, maxCasesPerHour int) (*Service, *gorm.DB) {
	t.Helper()
	db := databasetest.New(t)
	service := NewService(db, testPublicURL, maxCasesPerHour)
	service.now = func() time.Time { return testNow }
	return service, db
}

// openAlertCase inserts an alert and runs the hook in a transaction, as the
// alert writer does, and returns the alert id and the opened case.
func openAlertCase(t *testing.T, service *Service, db *gorm.DB, detectionID, title string) (alerts.CaseOutcome, string, caseRow) {
	t.Helper()
	alertID := insertAlert(t, db, detectionID, title, alerts.SeverityHigh)
	outcome := runAlertCreated(t, service, db, newAlert(alertID, detectionID, title))
	return outcome, alertID, loadCaseForAlert(t, db, alertID)
}

// newAlert builds the hook input for an alert inserted with insertAlert.
func newAlert(alertID, detectionID, title string) alerts.NewAlert {
	return alerts.NewAlert{
		ID:           alertID,
		DetectionID:  detectionID,
		Title:        title,
		Severity:     alerts.SeverityHigh,
		FirstEventAt: testFirstEventAt,
		LastEventAt:  testLastEventAt,
	}
}

func insertAlert(t *testing.T, db *gorm.DB, detectionID, summary string, severity alerts.Severity) string {
	t.Helper()
	var alertID string
	err := db.Raw(`
		INSERT INTO alerts (detection_id, detection_version, identity_hash, identity_schema_version,
		                    identity, subject, summary, severity, first_event_at, last_event_at, evidence_count)
		VALUES (?, '1.0.0', gen_random_uuid()::text, 1, '{}'::jsonb, '{}'::jsonb, ?, ?, ?, ?, 1)
		RETURNING id::text AS id`,
		detectionID, summary, string(severity), testFirstEventAt, testLastEventAt).Scan(&alertID).Error
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	return alertID
}

// runAlertCreated calls the hook inside a transaction, as the alert writer does.
func runAlertCreated(t *testing.T, service *Service, db *gorm.DB, alert alerts.NewAlert) alerts.CaseOutcome {
	t.Helper()
	var outcome alerts.CaseOutcome
	err := db.Transaction(func(tx *gorm.DB) error {
		var hookErr error
		outcome, hookErr = service.AlertCreated(context.Background(), tx, alert)
		return hookErr
	})
	if err != nil {
		t.Fatalf("AlertCreated(%q): %v", alert.Title, err)
	}
	return outcome
}

func runEvidenceAdded(t *testing.T, service *Service, db *gorm.DB, alertID string, lastEventAt time.Time, added int) {
	t.Helper()
	err := db.Transaction(func(tx *gorm.DB) error {
		return service.EvidenceAdded(context.Background(), tx, alertID, lastEventAt, added)
	})
	if err != nil {
		t.Fatalf("EvidenceAdded(%q): %v", alertID, err)
	}
}

func loadCaseForAlert(t *testing.T, db *gorm.DB, alertID string) caseRow {
	t.Helper()
	var stored caseRow
	err := db.Raw(`
		SELECT cases.id::text AS id, cases.case_number, cases.title, cases.status,
		       cases.severity, cases.detection_id, cases.assignee_user_id::text AS assignee_user_id,
		       cases.first_event_at, cases.last_event_at, cases.version
		FROM cases
		JOIN case_alerts ON case_alerts.case_id = cases.id
		WHERE case_alerts.alert_id = ?`, alertID).Scan(&stored).Error
	if err != nil {
		t.Fatalf("load case of alert %q: %v", alertID, err)
	}
	if stored.ID == "" {
		t.Fatalf("alert %q has no case", alertID)
	}
	return stored
}

func loadRotation(t *testing.T, db *gorm.DB) *string {
	t.Helper()
	var lastUserID *string
	if err := db.Raw(
		"SELECT last_user_id::text AS last_user_id FROM on_call_rotation WHERE id = 1",
	).Scan(&lastUserID).Error; err != nil {
		t.Fatalf("read on-call rotation: %v", err)
	}
	return lastUserID
}

func createUser(t *testing.T, db *gorm.DB, email, role string) string {
	t.Helper()
	var userID string
	err := db.Raw(`
		INSERT INTO users (email, display_name, on_call)
		VALUES (?, ?, true)
		RETURNING id::text AS id`, email, email).Scan(&userID).Error
	if err != nil {
		t.Fatalf("insert user %q: %v", email, err)
	}
	if err := db.Exec("INSERT INTO user_roles (user_id, role_name) VALUES (?, ?)", userID, role).Error; err != nil {
		t.Fatalf("assign role %q to %q: %v", role, email, err)
	}
	return userID
}

func findAuditEvent(events []audit.Event, name string) (audit.Event, bool) {
	for _, event := range events {
		if event.EventName == name {
			return event, true
		}
	}
	return audit.Event{}, false
}

// expectSystemCaseEvent checks the fields every alert-driven case event shares.
func expectSystemCaseEvent(t *testing.T, event audit.Event, action string) {
	t.Helper()
	if event.EventCategory != "CASE" {
		t.Errorf("%s category = %q, want CASE", event.EventName, event.EventCategory)
	}
	if event.EventOutcome != "SUCCESS" {
		t.Errorf("%s outcome = %q, want SUCCESS", event.EventName, event.EventOutcome)
	}
	if event.ActorType != "SYSTEM" {
		t.Errorf("%s actor type = %q, want SYSTEM", event.EventName, event.ActorType)
	}
	if event.ActorID != nil {
		t.Errorf("%s actor id = %q, want none", event.EventName, *event.ActorID)
	}
	if event.TargetType != "CASE" {
		t.Errorf("%s target type = %q, want CASE", event.EventName, event.TargetType)
	}
	if event.Action != action {
		t.Errorf("%s action = %q, want %q", event.EventName, event.Action, action)
	}
}

type storedOutboxEvent struct {
	Type        string `gorm:"column:type"`
	Version     int    `gorm:"column:version"`
	Actor       []byte `gorm:"column:actor"`
	SubjectType string `gorm:"column:subject_type"`
	SubjectID   string `gorm:"column:subject_id"`
	Payload     []byte `gorm:"column:payload"`
}

func outboxEventsOfType(t *testing.T, db *gorm.DB, eventType string) []storedOutboxEvent {
	t.Helper()
	var rows []storedOutboxEvent
	err := db.Raw(`
		SELECT type, version, actor, subject_type, subject_id, payload
		FROM event_outbox
		WHERE type = ?
		ORDER BY occurred_at, id`, eventType).Scan(&rows).Error
	if err != nil {
		t.Fatalf("read %s outbox rows: %v", eventType, err)
	}
	return rows
}

func decodeObject(t *testing.T, encoded []byte) map[string]any {
	t.Helper()
	if encoded == nil {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode %s: %v", encoded, err)
	}
	return decoded
}

// expectNoCaseWrites checks that the case service wrote nothing.
func expectNoCaseWrites(t *testing.T, db *gorm.DB, when string) {
	t.Helper()
	tables := []struct {
		name      string
		condition string
	}{
		{"cases", "cases"},
		{"case_alerts", "case_alerts"},
		{"audit_events", "audit_events WHERE target_type = 'CASE'"},
		{"event_outbox", "event_outbox"},
		{"detection_guardrails", "detection_guardrails"},
	}
	for _, table := range tables {
		if count := countRows(t, db, table.condition); count != 0 {
			t.Errorf("%s has %d rows %s, want 0", table.name, count, when)
		}
	}
}

func countRows(t *testing.T, db *gorm.DB, tableAndCondition string, arguments ...any) int64 {
	t.Helper()
	var count int64
	if err := db.Raw("SELECT count(*) FROM "+tableAndCondition, arguments...).Scan(&count).Error; err != nil {
		t.Fatalf("count %s: %v", tableAndCondition, err)
	}
	return count
}
