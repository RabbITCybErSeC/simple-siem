package cases

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

const testSessionID = "6f9619ff-8b86-d011-b42d-00cf4fc964ff"

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
	return insertAlertRecord(t, db, alertFixture{
		DetectionID:  detectionID,
		Summary:      summary,
		Severity:     severity,
		FirstEventAt: testFirstEventAt,
		LastEventAt:  testLastEventAt,
	})
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

// insertCase stores a case built from fixture and returns its identity.
type caseFixture struct {
	Title          string
	Status         string
	Severity       string
	DetectionID    string
	AssigneeID     *string
	Outcome        *string
	ClosureReason  *string
	Conclusion     *string
	FirstEventAt   time.Time
	LastEventAt    time.Time
	CreatedAt      time.Time
	ClosedAt       *time.Time
	ClosedBy       *string
	PreviousCaseID *string
}

func insertCase(t *testing.T, db *gorm.DB, fixture caseFixture) caseRow {
	t.Helper()
	if fixture.Title == "" {
		fixture.Title = "Case"
	}
	if fixture.Status == "" {
		fixture.Status = StatusOpen
	}
	if fixture.Severity == "" {
		fixture.Severity = string(alerts.SeverityHigh)
	}
	if fixture.DetectionID == "" {
		fixture.DetectionID = "brute-force"
	}
	if fixture.FirstEventAt.IsZero() {
		fixture.FirstEventAt = fixture.LastEventAt
	}
	if fixture.LastEventAt.IsZero() {
		fixture.LastEventAt = testLastEventAt
	}
	if fixture.CreatedAt.IsZero() {
		fixture.CreatedAt = testNow
	}

	var stored caseRow
	err := db.Raw(`
		INSERT INTO cases (title, status, severity, detection_id, assignee_user_id,
		                   outcome, closure_reason, conclusion, first_event_at, last_event_at,
		                   created_at, closed_at, closed_by, previous_case_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING id::text AS id, case_number, title, status, severity, detection_id,
		          assignee_user_id::text AS assignee_user_id, first_event_at, last_event_at,
		          created_at, version`,
		fixture.Title, fixture.Status, fixture.Severity, fixture.DetectionID,
		fixture.AssigneeID, fixture.Outcome, fixture.ClosureReason, fixture.Conclusion,
		fixture.FirstEventAt, fixture.LastEventAt, fixture.CreatedAt,
		fixture.ClosedAt, fixture.ClosedBy, fixture.PreviousCaseID,
	).Scan(&stored).Error
	if err != nil {
		t.Fatalf("insert case %q: %v", fixture.Title, err)
	}
	return stored
}

func stringPointer(value string) *string {
	return &value
}

func caseIDs(page CasePage) []string {
	ids := make([]string, len(page.Items))
	for index, item := range page.Items {
		ids[index] = item.ID
	}
	return ids
}

func TestListEveryFilter(t *testing.T) {
	service, db := newTestService(t, 50)
	alice := createUser(t, db, "alice@example.com", "ANALYST")
	bob := createUser(t, db, "bob@example.com", "ANALYST")

	open := insertCase(t, db, caseFixture{
		Title: "Alpha breach", Status: StatusOpen, Severity: string(alerts.SeverityHigh),
		DetectionID: "det-a", AssigneeID: &alice,
		LastEventAt: testNow.Add(-time.Hour), CreatedAt: testNow.Add(-3 * time.Hour),
	})
	inProgress := insertCase(t, db, caseFixture{
		Title: "Beta scan", Status: StatusInProgress, Severity: string(alerts.SeverityMedium),
		DetectionID: "det-b", AssigneeID: &bob, Outcome: stringPointer("MALICIOUS"),
		LastEventAt: testNow.Add(-2 * time.Hour), CreatedAt: testNow.Add(-2 * time.Hour),
	})
	closedAt := testNow.Add(-30 * time.Minute)
	closed := insertCase(t, db, caseFixture{
		Title: "Gamma login", Status: StatusClosed, Severity: string(alerts.SeverityLow),
		DetectionID: "det-a", Outcome: stringPointer("ACCEPTED"),
		LastEventAt: testNow.Add(-3 * time.Hour), CreatedAt: testNow.Add(-time.Hour),
		ClosedAt: &closedAt,
	})

	tests := []struct {
		name   string
		filter ListFilter
		want   []caseRow
	}{
		{"status", ListFilter{Statuses: []string{StatusOpen, StatusInProgress}}, []caseRow{open, inProgress}},
		{"scope mine", ListFilter{Scope: ScopeMine}, []caseRow{open}},
		{"scope unassigned", ListFilter{Scope: ScopeUnassigned}, []caseRow{closed}},
		{"assignee", ListFilter{AssigneeIDs: []string{bob}}, []caseRow{inProgress}},
		{"severity", ListFilter{Severities: []string{string(alerts.SeverityLow)}}, []caseRow{closed}},
		{"detection", ListFilter{DetectionIDs: []string{"det-a"}}, []caseRow{open, closed}},
		{"outcome", ListFilter{Outcomes: []string{"ACCEPTED"}}, []caseRow{closed}},
		{"query prefix", ListFilter{Query: "Alpha"}, []caseRow{open}},
		{"query case number", ListFilter{Query: strconv.FormatInt(closed.CaseNumber, 10)}, []caseRow{closed}},
		{
			"last event range",
			ListFilter{
				From: timePointer(testNow.Add(-90 * time.Minute)), To: timePointer(testNow),
				TimeField: TimeFieldLastEventAt,
			},
			[]caseRow{open},
		},
		{
			"created range",
			ListFilter{
				From: timePointer(testNow.Add(-150 * time.Minute)), To: timePointer(testNow.Add(-90 * time.Minute)),
				TimeField: TimeFieldCreatedAt,
			},
			[]caseRow{inProgress},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter := test.filter
			filter.Limit = MaxListLimit
			page, err := service.List(context.Background(), alice, filter)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			want := make([]string, len(test.want))
			for index, stored := range test.want {
				want[index] = stored.ID
			}
			if got := caseIDs(page); !slices.Equal(got, want) {
				t.Errorf("case ids = %v, want %v", got, want)
			}
			if page.NextCursor != nil {
				t.Errorf("next cursor = %q, want nil for one page", *page.NextCursor)
			}
		})
	}

	all, err := service.List(context.Background(), alice, ListFilter{Limit: MaxListLimit})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all.Items) != 3 {
		t.Fatalf("default list returned %d items, want 3", len(all.Items))
	}
	if got, want := caseIDs(all), []string{open.ID, inProgress.ID, closed.ID}; !slices.Equal(got, want) {
		t.Errorf("default order = %v, want last event descending %v", got, want)
	}
	if all.Items[0].Assignee == nil || all.Items[0].Assignee.DisplayName != "alice@example.com" {
		t.Errorf("assignee = %+v, want alice with her display name", all.Items[0].Assignee)
	}
	if all.Items[1].Assignee == nil || all.Items[1].Assignee.ID != bob {
		t.Errorf("assignee = %+v, want bob", all.Items[1].Assignee)
	}
	if all.Items[2].Assignee != nil {
		t.Errorf("unassigned case has assignee %+v, want null", all.Items[2].Assignee)
	}
	if all.Items[0].Outcome != nil || all.Items[2].ClosedAt == nil {
		t.Errorf("nullable fields did not survive the read: outcome %v, closedAt %v",
			all.Items[0].Outcome, all.Items[2].ClosedAt)
	}
}

func TestListSortsPaginate(t *testing.T) {
	service, db := newTestService(t, 50)
	inserted := make([]caseRow, 5)
	for index := range inserted {
		inserted[index] = insertCase(t, db, caseFixture{
			Title:       "Case " + strconv.Itoa(index+1),
			LastEventAt: testNow.Add(-time.Duration(index+1) * time.Hour),
			CreatedAt:   testNow.Add(-time.Duration(index+1) * time.Hour),
		})
	}
	wantLastEvent := []string{inserted[0].ID, inserted[1].ID, inserted[2].ID, inserted[3].ID, inserted[4].ID}
	wantCreated := []string{inserted[4].ID, inserted[3].ID, inserted[2].ID, inserted[1].ID, inserted[0].ID}

	tests := []struct {
		name string
		sort string
		want []string
	}{
		{"lastEventAt:desc", SortLastEventAtDesc, wantLastEvent},
		{"createdAt:asc", SortCreatedAtAsc, wantCreated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter := ListFilter{Sort: test.sort, Limit: 2}
			var pages [][]string
			for {
				page, err := service.List(context.Background(), "", filter)
				if err != nil {
					t.Fatalf("List: %v", err)
				}
				pages = append(pages, caseIDs(page))
				if page.NextCursor == nil {
					break
				}
				filter.Cursor = *page.NextCursor
			}
			if len(pages) != 3 {
				t.Fatalf("got %d pages, want 3 (2+2+1)", len(pages))
			}
			if got := slices.Concat(pages...); !slices.Equal(got, test.want) {
				t.Errorf("paged order = %v, want %v", got, test.want)
			}
			if len(pages[2]) != 1 {
				t.Errorf("last page holds %d items, want 1", len(pages[2]))
			}
		})
	}
}

func TestListOldestWaitingFirst(t *testing.T) {
	service, db := newTestService(t, 50)
	first := insertCase(t, db, caseFixture{Title: "09:00", CreatedAt: testNow.Add(-3 * time.Hour)})
	second := insertCase(t, db, caseFixture{Title: "10:00", CreatedAt: testNow.Add(-2 * time.Hour)})
	third := insertCase(t, db, caseFixture{Title: "11:00", CreatedAt: testNow.Add(-time.Hour)})

	filter := ListFilter{Statuses: []string{StatusOpen}, Sort: SortCreatedAtAsc, Limit: 2}
	firstPage, err := service.List(context.Background(), "", filter)
	if err != nil {
		t.Fatalf("list first page: %v", err)
	}
	if got, want := caseIDs(firstPage), []string{first.ID, second.ID}; !slices.Equal(got, want) {
		t.Errorf("first page = %v, want %v", got, want)
	}
	if firstPage.NextCursor == nil {
		t.Fatalf("first page has no next cursor")
	}

	filter.Cursor = *firstPage.NextCursor
	secondPage, err := service.List(context.Background(), "", filter)
	if err != nil {
		t.Fatalf("list second page: %v", err)
	}
	if got, want := caseIDs(secondPage), []string{third.ID}; !slices.Equal(got, want) {
		t.Errorf("second page = %v, want %v", got, want)
	}
	if secondPage.NextCursor != nil {
		t.Errorf("next cursor = %q, want nil after the last case", *secondPage.NextCursor)
	}
}

func TestListRejectsCursorFromOtherFilters(t *testing.T) {
	service, db := newTestService(t, 50)
	insertCase(t, db, caseFixture{Title: "One"})
	insertCase(t, db, caseFixture{Title: "Two", LastEventAt: testNow.Add(-2 * time.Hour)})

	page, err := service.List(context.Background(), "", ListFilter{
		Statuses: []string{StatusOpen}, Sort: SortLastEventAtDesc, Limit: 1,
	})
	if err != nil {
		t.Fatalf("list first page: %v", err)
	}
	if page.NextCursor == nil {
		t.Fatalf("first page has no next cursor")
	}

	_, err = service.List(context.Background(), "", ListFilter{
		Statuses: []string{StatusClosed}, Sort: SortLastEventAtDesc, Limit: 1, Cursor: *page.NextCursor,
	})
	if !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("reused cursor error = %v, want ErrInvalidCursor", err)
	}
}

func TestListRejectsTamperedCursor(t *testing.T) {
	service, db := newTestService(t, 50)
	insertCase(t, db, caseFixture{Title: "One", LastEventAt: testNow.Add(-time.Hour)})
	insertCase(t, db, caseFixture{Title: "Two", LastEventAt: testNow.Add(-2 * time.Hour)})

	page, err := service.List(context.Background(), "", ListFilter{Limit: 1})
	if err != nil {
		t.Fatalf("list first page: %v", err)
	}
	if page.NextCursor == nil {
		t.Fatalf("first page has no next cursor")
	}

	t.Run("flipped byte", func(t *testing.T) {
		cursor := flipFirstByte(*page.NextCursor)
		_, err := service.List(context.Background(), "", ListFilter{Limit: 1, Cursor: cursor})
		if !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("tampered cursor error = %v, want ErrInvalidCursor", err)
		}
	})

	t.Run("non UUID id", func(t *testing.T) {
		payload := decodeCursorPayload(t, *page.NextCursor)
		payload.ID = "not-a-uuid"
		cursor := encodeCursorPayload(t, payload)
		_, err := service.List(context.Background(), "", ListFilter{Limit: 1, Cursor: cursor})
		if !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("tampered cursor error = %v, want ErrInvalidCursor", err)
		}
	})
}

func TestListTimeRangeOnlyWhenSent(t *testing.T) {
	service, db := newTestService(t, 50)
	oldEvent := testNow.Add(-30 * 24 * time.Hour)
	stale := insertCase(t, db, caseFixture{
		Title: "Stale open", Status: StatusOpen,
		FirstEventAt: oldEvent, LastEventAt: oldEvent, CreatedAt: oldEvent,
	})

	withoutRange, err := service.List(context.Background(), "", ListFilter{
		Statuses: []string{StatusOpen}, Limit: MaxListLimit,
	})
	if err != nil {
		t.Fatalf("list without range: %v", err)
	}
	if got := caseIDs(withoutRange); !slices.Equal(got, []string{stale.ID}) {
		t.Errorf("open queue = %v, want the stale case %q", got, stale.ID)
	}

	withRange, err := service.List(context.Background(), "", ListFilter{
		Statuses: []string{StatusOpen}, Limit: MaxListLimit,
		From: timePointer(testNow.Add(-24 * time.Hour)), To: timePointer(testNow),
		TimeField: TimeFieldLastEventAt,
	})
	if err != nil {
		t.Fatalf("list with range: %v", err)
	}
	if len(withRange.Items) != 0 {
		t.Errorf("range returned %d cases, want none", len(withRange.Items))
	}
}

func TestListTitleMetacharactersMatchLiterally(t *testing.T) {
	service, db := newTestService(t, 50)
	percent := insertCase(t, db, caseFixture{Title: "100% CPU"})
	plain := insertCase(t, db, caseFixture{Title: "100 CPU"})
	underscore := insertCase(t, db, caseFixture{Title: "user_login"})
	other := insertCase(t, db, caseFixture{Title: "userxlogin"})

	tests := []struct {
		query string
		want  string
	}{
		{"100%", percent.ID},
		{"100 C", plain.ID},
		{"user_", underscore.ID},
		{"userx", other.ID},
	}
	for _, test := range tests {
		page, err := service.List(context.Background(), "", ListFilter{Query: test.query, Limit: MaxListLimit})
		if err != nil {
			t.Fatalf("list %q: %v", test.query, err)
		}
		if got := caseIDs(page); !slices.Equal(got, []string{test.want}) {
			t.Errorf("query %q returned %v, want only %q", test.query, got, test.want)
		}
	}
}

func TestCaseSummaryJSONShape(t *testing.T) {
	service, db := newTestService(t, 50)
	inserted := insertCase(t, db, caseFixture{Title: "Shape"})

	page, err := service.List(context.Background(), "", ListFilter{Limit: 1})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("got %d items, want 1", len(page.Items))
	}
	encoded, err := json.Marshal(page.Items[0])
	if err != nil {
		t.Fatalf("encode summary: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	want := []string{
		"assignee", "caseNumber", "closedAt", "closureReason", "createdAt",
		"firstEventAt", "id", "lastEventAt", "outcome", "severity", "status",
		"title", "version",
	}
	gotKeys := make([]string, 0, len(fields))
	for key := range fields {
		gotKeys = append(gotKeys, key)
	}
	slices.Sort(gotKeys)
	if !slices.Equal(gotKeys, want) {
		t.Errorf("summary JSON keys = %v, want %v", gotKeys, want)
	}
	if fields["id"] != inserted.ID || fields["assignee"] != nil || fields["outcome"] != nil {
		t.Errorf("summary JSON = %s, want id %q with null assignee and outcome", encoded, inserted.ID)
	}
}

func TestValidateListFilter(t *testing.T) {
	tooManyAssignees := make([]string, MaxFilterAssignees+1)
	for index := range tooManyAssignees {
		tooManyAssignees[index] = "6f9619ff-8b86-d011-b42d-00cf4fc964ff"
	}
	validAssignee := "6f9619ff-8b86-d011-b42d-00cf4fc964ff"
	from := testNow.Add(-time.Hour)
	tests := []struct {
		name      string
		filter    ListFilter
		parameter string
	}{
		{"valid", ListFilter{
			Statuses: []string{StatusOpen}, Scope: ScopeMine, AssigneeIDs: []string{validAssignee},
			Severities: []string{string(alerts.SeverityHigh)}, DetectionIDs: []string{"brute-force"},
			Outcomes: []string{"ACCEPTED"}, Query: "alpha", From: &from, To: timePointer(testNow),
			TimeField: TimeFieldCreatedAt, Sort: SortCreatedAtAsc, Limit: MaxListLimit,
		}, ""},
		{"status outside the allowlist", ListFilter{Statuses: []string{"open"}, Limit: 50}, "status"},
		{"empty status item", ListFilter{Statuses: []string{StatusOpen, ""}, Limit: 50}, "status"},
		{"scope outside the allowlist", ListFilter{Scope: "team", Limit: 50}, "scope"},
		{"too many assignees", ListFilter{AssigneeIDs: tooManyAssignees, Limit: 50}, "assignee"},
		{"assignee not a UUID", ListFilter{AssigneeIDs: []string{"alice"}, Limit: 50}, "assignee"},
		{"detection outside the pattern", ListFilter{DetectionIDs: []string{"Bad_ID"}, Limit: 50}, "detection"},
		{"query too long", ListFilter{Query: strings.Repeat("é", MaxQueryRunes+1), Limit: 50}, "q"},
		{"numeric query overflows int64", ListFilter{Query: "99999999999999999999", Limit: 50}, "q"},
		{"limit below one", ListFilter{Limit: 0}, "limit"},
		{"limit above the maximum", ListFilter{Limit: MaxListLimit + 1}, "limit"},
		{"from after to", ListFilter{From: timePointer(testNow), To: timePointer(testNow.Add(-time.Hour)), Limit: 50}, "from"},
		{"timeField outside the allowlist", ListFilter{TimeField: "updatedAt", Limit: 50}, "timeField"},
		{"sort outside the allowlist", ListFilter{Sort: "createdAt:desc", Limit: 50}, "sort"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateListFilter(test.filter)
			if test.parameter == "" {
				if err != nil {
					t.Fatalf("ValidateListFilter: %v", err)
				}
				return
			}
			expectValidationError(t, err, test.parameter)
		})
	}
}

func TestParseTime(t *testing.T) {
	monday := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		value string
		want  time.Time
		ok    bool
	}{
		{"now", testNow, true},
		{"now-15m", testNow.Add(-15 * time.Minute), true},
		{"now-2h", testNow.Add(-2 * time.Hour), true},
		{"now-7d", testNow.Add(-7 * 24 * time.Hour), true},
		{"now-3w", testNow.Add(-3 * 7 * 24 * time.Hour), true},
		{"now/d", time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), true},
		{"now/w", monday, true},
		{"2026-11-15T08:30:00Z", time.Date(2026, 11, 15, 8, 30, 0, 0, time.UTC), true},
		{"2026-11-15T08:30:00.123Z", time.Date(2026, 11, 15, 8, 30, 0, 123000000, time.UTC), true},
		{"now-0h", time.Time{}, false},
		{"now+1h", time.Time{}, false},
		{"yesterday", time.Time{}, false},
		{"2026-11-15T08:30:00+02:00", time.Time{}, false},
		{"now-99999999999w", time.Time{}, false},
		{"now-99999999999999999999m", time.Time{}, false},
		{"now-10x", time.Time{}, false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := ParseTime(test.value, testNow)
			if !test.ok {
				if err == nil {
					t.Fatalf("ParseTime(%q) = %v, want an error", test.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTime(%q): %v", test.value, err)
			}
			if !got.Equal(test.want) {
				t.Errorf("ParseTime(%q) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

func timePointer(value time.Time) *time.Time {
	return &value
}

// expectValidationError checks that err is a ValidationError naming parameter.
func expectValidationError(t *testing.T, err error, parameter string) {
	t.Helper()
	var validation ValidationError
	if !errors.As(err, &validation) || validation.Parameter != parameter {
		t.Fatalf("error = %v, want ValidationError naming %s", err, parameter)
	}
}

func TestListRejectsOversizedCursor(t *testing.T) {
	service, db := newTestService(t, 50)
	insertCase(t, db, caseFixture{Title: "One"})

	_, err := service.List(context.Background(), "", ListFilter{
		Cursor: strings.Repeat("a", MaxCursorBytes+1),
		Limit:  50,
	})
	if !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("oversized cursor error = %v, want ErrInvalidCursor", err)
	}
	expectValidationError(t, err, "cursor")
}

func flipFirstByte(cursor string) string {
	replacement := byte('A')
	if cursor[0] == 'A' {
		replacement = 'B'
	}
	return string(replacement) + cursor[1:]
}

func decodeCursorPayload(t *testing.T, cursor string) cursorPayload {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	var payload cursorPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatalf("unmarshal cursor: %v", err)
	}
	return payload
}

// alertFixture describes one alerts row to insert.
type alertFixture struct {
	DetectionID      string
	DetectionVersion string
	Summary          string
	Severity         alerts.Severity
	Status           string
	FirstEventAt     time.Time
	LastEventAt      time.Time
	EvidenceCount    int
	OccurrenceCount  int
}

func insertAlertRecord(t *testing.T, db *gorm.DB, fixture alertFixture) string {
	t.Helper()
	if fixture.DetectionVersion == "" {
		fixture.DetectionVersion = "1.0.0"
	}
	if fixture.Severity == "" {
		fixture.Severity = alerts.SeverityHigh
	}
	if fixture.Status == "" {
		fixture.Status = "OPEN"
	}
	if fixture.EvidenceCount == 0 {
		fixture.EvidenceCount = 1
	}
	if fixture.OccurrenceCount == 0 {
		fixture.OccurrenceCount = 1
	}
	if fixture.FirstEventAt.IsZero() {
		fixture.FirstEventAt = testFirstEventAt
	}
	if fixture.LastEventAt.IsZero() {
		fixture.LastEventAt = fixture.FirstEventAt
	}

	var alertID string
	err := db.Raw(`
		INSERT INTO alerts (detection_id, detection_version, identity_hash, identity_schema_version,
		                    identity, subject, summary, severity, status, first_event_at,
		                    last_event_at, evidence_count, occurrence_count)
		VALUES (?, ?, gen_random_uuid()::text, 1, '{}'::jsonb, '{}'::jsonb, ?, ?, ?, ?, ?, ?, ?)
		RETURNING id::text AS id`,
		fixture.DetectionID, fixture.DetectionVersion, fixture.Summary,
		string(fixture.Severity), fixture.Status, fixture.FirstEventAt, fixture.LastEventAt,
		fixture.EvidenceCount, fixture.OccurrenceCount,
	).Scan(&alertID).Error
	if err != nil {
		t.Fatalf("insert alert %q: %v", fixture.Summary, err)
	}
	return alertID
}

func linkCaseAlert(t *testing.T, db *gorm.DB, caseID, alertID string) {
	t.Helper()
	if err := db.Exec(
		"INSERT INTO case_alerts (case_id, alert_id) VALUES (?, ?)", caseID, alertID,
	).Error; err != nil {
		t.Fatalf("link alert %q to case %q: %v", alertID, caseID, err)
	}
}

// insertEvidence stores one alert_evidence row and returns its source key hash.
func insertEvidence(t *testing.T, db *gorm.DB, alertID, documentID string, eventTime time.Time) []byte {
	t.Helper()
	hash := sha256.Sum256([]byte(documentID + eventTime.Format(time.RFC3339Nano)))
	err := db.Exec(`
		INSERT INTO alert_evidence (alert_id, source_key_hash, fetcher_instance_id,
		                            source_index, document_id, event_time)
		VALUES (?, ?, 'fetcher-1', 'logs', ?, ?)`,
		alertID, hash[:], documentID, eventTime).Error
	if err != nil {
		t.Fatalf("insert evidence %q: %v", documentID, err)
	}
	return hash[:]
}

// createTestDataset registers a dataset and the partitions the cache rows need.
func createTestDataset(t *testing.T, db *gorm.DB, name string) {
	t.Helper()
	err := db.Exec(`
		INSERT INTO datasets (name, pipeline_id, retention, allowed_lateness)
		VALUES (?, 'test-pipeline', interval '30 days', interval '0')
		ON CONFLICT (name) DO NOTHING`, name).Error
	if err != nil {
		t.Fatalf("insert dataset %q: %v", name, err)
	}
	listPartition := "dataset_events_" + name
	statement := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS "%s" PARTITION OF dataset_events FOR VALUES IN ('%s') PARTITION BY RANGE (event_time)`,
		listPartition, name,
	)
	if err := db.Exec(statement).Error; err != nil {
		t.Fatalf("create dataset %q partition: %v", name, err)
	}
	dayPartition := listPartition + "_day"
	statement = fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS "%s" PARTITION OF "%s" FOR VALUES FROM ('2026-11-01') TO ('2026-12-01')`,
		dayPartition, listPartition,
	)
	if err := db.Exec(statement).Error; err != nil {
		t.Fatalf("create day partition of %q: %v", name, err)
	}
}

func insertDatasetEvent(t *testing.T, db *gorm.DB, dataset string, eventTime time.Time, hash []byte, event string) {
	t.Helper()
	err := db.Exec(`
		INSERT INTO dataset_events (dataset, event_time, source_key_hash, fetcher_instance_id,
		                            source_index, document_id, event_type, event, pipeline_run_id)
		VALUES (?, ?, ?, 'fetcher-1', 'logs', 'doc-1', 'USER_LOGIN', ?, 'run-1')`,
		dataset, eventTime, hash, []byte(event)).Error
	if err != nil {
		t.Fatalf("insert dataset event in %q: %v", dataset, err)
	}
}

// insertCaseAudit stores one case audit row with a chosen time and changes.
func insertCaseAudit(t *testing.T, db *gorm.DB, caseID, eventName, actorType string, actorID *string, at time.Time, changes map[string]any) string {
	t.Helper()
	var encoded []byte
	if changes != nil {
		var err error
		encoded, err = json.Marshal(changes)
		if err != nil {
			t.Fatalf("encode changes: %v", err)
		}
	}
	var auditID string
	err := db.Raw(`
		INSERT INTO audit_events (event_name, event_category, event_outcome, actor_type,
		                          actor_id, target_type, target_id, action, changes, created_at)
		VALUES (?, 'CASE', 'SUCCESS', ?, ?, 'CASE', ?, 'test', ?, ?)
		RETURNING id::text AS id`,
		eventName, actorType, actorID, caseID, encoded, at).Scan(&auditID).Error
	if err != nil {
		t.Fatalf("insert %s audit event: %v", eventName, err)
	}
	return auditID
}

func timelineAll(t *testing.T, service *Service, caseID, kind string, limit int) []TimelineEntry {
	t.Helper()
	all := make([]TimelineEntry, 0)
	cursor := ""
	for pageNumber := 1; pageNumber <= 100; pageNumber++ {
		page, err := service.Timeline(context.Background(), caseID, kind, limit, cursor)
		if err != nil {
			t.Fatalf("timeline page %d: %v", pageNumber, err)
		}
		all = append(all, page.Items...)
		if page.NextCursor == nil {
			return all
		}
		if len(page.Items) == 0 {
			t.Fatalf("timeline page %d is empty but carries a next cursor", pageNumber)
		}
		cursor = *page.NextCursor
	}
	t.Fatalf("timeline did not finish within 100 pages")
	return nil
}

func TestGetDetailByIDAndNumber(t *testing.T) {
	service, db := newTestService(t, 50)
	analyst := createUser(t, db, "analyst@example.com", "ANALYST")

	previous := insertCase(t, db, caseFixture{
		Title: "Previous", LastEventAt: testNow.Add(-24 * time.Hour), CreatedAt: testNow.Add(-24 * time.Hour),
	})
	closedAt := testNow.Add(-time.Minute)
	main := insertCase(t, db, caseFixture{
		Title: "Main", Status: StatusClosed, Severity: string(alerts.SeverityMedium),
		AssigneeID: &analyst, Outcome: stringPointer("ACCEPTED"),
		ClosureReason: stringPointer("DUPLICATE"), Conclusion: stringPointer("merged into 1"),
		ClosedAt: &closedAt, ClosedBy: &analyst, PreviousCaseID: &previous.ID,
	})
	firstChild := insertCase(t, db, caseFixture{Title: "Child one", PreviousCaseID: &main.ID})
	secondChild := insertCase(t, db, caseFixture{Title: "Child two", PreviousCaseID: &main.ID})

	for index := 1; index <= 2; index++ {
		alertID := insertAlertRecord(t, db, alertFixture{DetectionID: "det-1", Summary: "Alert " + strconv.Itoa(index)})
		linkCaseAlert(t, db, main.ID, alertID)
	}

	byID, err := service.Get(context.Background(), main.ID)
	if err != nil {
		t.Fatalf("Get by id: %v", err)
	}
	byNumber, err := service.Get(context.Background(), strconv.FormatInt(main.CaseNumber, 10))
	if err != nil {
		t.Fatalf("Get by number: %v", err)
	}
	for name, detail := range map[string]CaseDetail{"id": byID, "number": byNumber} {
		if detail.ID != main.ID || detail.CaseNumber != main.CaseNumber {
			t.Errorf("%s detail = %s/%d, want %s/%d",
				name, detail.ID, detail.CaseNumber, main.ID, main.CaseNumber)
		}
		if detail.Status != StatusClosed || detail.Outcome == nil || *detail.Outcome != "ACCEPTED" {
			t.Errorf("%s status/outcome = %q/%v, want CLOSED/ACCEPTED", name, detail.Status, detail.Outcome)
		}
		if detail.Assignee == nil || detail.Assignee.ID != analyst {
			t.Errorf("%s assignee = %+v, want %q", name, detail.Assignee, analyst)
		}
		if detail.ClosedBy == nil || detail.ClosedBy.ID != analyst {
			t.Errorf("%s closed by = %+v, want %q", name, detail.ClosedBy, analyst)
		}
		if detail.Conclusion == nil || *detail.Conclusion != "merged into 1" {
			t.Errorf("%s conclusion = %v, want the stored text", name, detail.Conclusion)
		}
		if detail.AlertCount != 2 {
			t.Errorf("%s alert count = %d, want 2", name, detail.AlertCount)
		}
		wantLinked := []LinkedCase{
			{ID: previous.ID, CaseNumber: previous.CaseNumber, Title: "Previous"},
			{ID: firstChild.ID, CaseNumber: firstChild.CaseNumber, Title: "Child one"},
			{ID: secondChild.ID, CaseNumber: secondChild.CaseNumber, Title: "Child two"},
		}
		if len(detail.LinkedCases) != len(wantLinked) {
			t.Fatalf("%s linked cases = %+v, want %d entries", name, detail.LinkedCases, len(wantLinked))
		}
		for index, want := range wantLinked {
			got := detail.LinkedCases[index]
			if got.ID != want.ID || got.CaseNumber != want.CaseNumber || got.Title != want.Title || got.Status == "" {
				t.Errorf("%s linked case %d = %+v, want %+v", name, index, got, want)
			}
		}
		if detail.MergedInto != nil {
			t.Errorf("%s merged into = %+v, want null", name, detail.MergedInto)
		}
		if detail.LastActivityAt.IsZero() {
			t.Errorf("%s last activity is zero", name)
		}
	}
}

func TestGetDetailNotFound(t *testing.T) {
	service, _ := newTestService(t, 50)

	for _, ref := range []string{
		"00000000-0000-0000-0000-000000000000",
		"abc",
		"99999999999999999999",
	} {
		t.Run(ref, func(t *testing.T) {
			_, err := service.Get(context.Background(), ref)
			if !errors.Is(err, ErrCaseNotFound) {
				t.Fatalf("Get(%q) error = %v, want ErrCaseNotFound", ref, err)
			}
		})
	}
}

func TestListAlertsOrderAndCursor(t *testing.T) {
	service, db := newTestService(t, 50)
	detail := insertCase(t, db, caseFixture{Title: "With alerts"})

	third := insertAlertRecord(t, db, alertFixture{
		DetectionID: "det-c", Summary: "Alert three", Severity: alerts.SeverityLow,
		FirstEventAt: testNow.Add(-time.Hour), LastEventAt: testNow.Add(-50 * time.Minute),
	})
	first := insertAlertRecord(t, db, alertFixture{
		DetectionID: "det-a", DetectionVersion: "1.2.3", Summary: "Alert one",
		Severity: alerts.SeverityHigh, FirstEventAt: testNow.Add(-3 * time.Hour),
		LastEventAt: testNow.Add(-2 * time.Hour), EvidenceCount: 4, OccurrenceCount: 7,
	})
	second := insertAlertRecord(t, db, alertFixture{
		DetectionID: "det-b", Summary: "Alert two", Severity: alerts.SeverityMedium,
		FirstEventAt: testNow.Add(-2 * time.Hour), LastEventAt: testNow.Add(-90 * time.Minute),
	})
	linkCaseAlert(t, db, detail.ID, third)
	linkCaseAlert(t, db, detail.ID, first)
	linkCaseAlert(t, db, detail.ID, second)
	if err := db.Exec(
		"UPDATE case_alerts SET outcome = 'MALICIOUS', closure_reason = 'CONFIRMED_THREAT' WHERE case_id = ? AND alert_id = ?",
		detail.ID, second,
	).Error; err != nil {
		t.Fatalf("set alert disposition: %v", err)
	}

	page, err := service.ListAlerts(context.Background(), detail.ID, 2, "")
	if err != nil {
		t.Fatalf("ListAlerts first page: %v", err)
	}
	if len(page.Items) != 2 || page.NextCursor == nil {
		t.Fatalf("first page has %d items and cursor %v, want 2 and one", len(page.Items), page.NextCursor)
	}
	if page.Items[0].ID != first || page.Items[1].ID != second {
		t.Errorf("first page alerts = %s, %s, want %s, %s",
			page.Items[0].ID, page.Items[1].ID, first, second)
	}
	items := page.Items[0]
	if items.Title != "Alert one" || items.Severity != string(alerts.SeverityHigh) ||
		items.Status != "OPEN" || items.DetectionID != "det-a" ||
		items.DetectionVersion != "1.2.3" || items.EvidenceCount != 4 ||
		items.OccurrenceCount != 7 || items.Outcome != nil {
		t.Errorf("alert fields = %+v, want the stored alert", items)
	}
	if !items.FirstEventAt.Equal(testNow.Add(-3 * time.Hour)) {
		t.Errorf("first event = %v, want %v", items.FirstEventAt, testNow.Add(-3*time.Hour))
	}
	if page.Items[1].Outcome == nil || *page.Items[1].Outcome != "MALICIOUS" ||
		page.Items[1].ClosureReason == nil || *page.Items[1].ClosureReason != "CONFIRMED_THREAT" {
		t.Errorf("disposition = %v/%v, want MALICIOUS/CONFIRMED_THREAT",
			page.Items[1].Outcome, page.Items[1].ClosureReason)
	}

	secondPage, err := service.ListAlerts(context.Background(), detail.ID, 2, *page.NextCursor)
	if err != nil {
		t.Fatalf("ListAlerts second page: %v", err)
	}
	if len(secondPage.Items) != 1 || secondPage.Items[0].ID != third {
		t.Errorf("second page = %+v, want only alert %s", secondPage.Items, third)
	}
	if secondPage.NextCursor != nil {
		t.Errorf("second page cursor = %q, want nil", *secondPage.NextCursor)
	}

	if _, err := service.ListAlerts(context.Background(), "00000000-0000-0000-0000-000000000000", 50, ""); !errors.Is(err, ErrCaseNotFound) {
		t.Fatalf("unknown case error = %v, want ErrCaseNotFound", err)
	}
}

func TestTimelineEvidenceUDM(t *testing.T) {
	service, db := newTestService(t, 50)
	_, alertID, detail := openAlertCase(t, service, db, "brute-force", "Brute force")
	createTestDataset(t, db, "aaa_logs")
	createTestDataset(t, db, "zzz_logs")

	firstEventAt := testNow.Add(-2 * time.Hour)
	firstHash := insertEvidence(t, db, alertID, "evt-1", firstEventAt)
	insertDatasetEvent(t, db, "zzz_logs", firstEventAt, firstHash,
		`{"metadata":{"event_type":"USER_LOGIN"},"marker":"zzz"}`)
	insertDatasetEvent(t, db, "aaa_logs", firstEventAt, firstHash,
		`{"metadata":{"event_type":"USER_LOGIN"},"marker":"aaa"}`)

	secondEventAt := testNow.Add(-time.Hour)
	insertEvidence(t, db, alertID, "evt-2", secondEventAt)

	entries := timelineAll(t, service, detail.ID, KindEvidence, 50)
	if len(entries) != 2 {
		t.Fatalf("evidence entries = %d, want 2", len(entries))
	}
	if entries[0].Kind != KindEvidence || entries[0].SourceID != "evt-1" ||
		entries[0].AlertID != alertID || !entries[0].At.Equal(firstEventAt) {
		t.Errorf("first evidence = %+v, want evt-1 at %v", entries[0], firstEventAt)
	}
	if !strings.HasPrefix(entries[0].ID, "ev_"+alertID+"_") {
		t.Errorf("evidence id = %q, want the %q prefix", entries[0].ID, "ev_"+alertID+"_")
	}
	var cached map[string]any
	if err := json.Unmarshal(entries[0].UDM, &cached); err != nil {
		t.Fatalf("decode cached UDM: %v", err)
	}
	if cached["marker"] != "aaa" {
		t.Errorf("UDM marker = %v, want aaa from the first dataset", cached["marker"])
	}

	if entries[1].SourceID != "evt-2" || !entries[1].At.Equal(secondEventAt) {
		t.Errorf("second evidence = %+v, want evt-2 at %v", entries[1], secondEventAt)
	}
	if string(entries[1].UDM) != "null" {
		t.Errorf("expired UDM = %s, want null", entries[1].UDM)
	}

	encoded, err := json.Marshal(entries[1])
	if err != nil {
		t.Fatalf("encode evidence entry: %v", err)
	}
	if !strings.Contains(string(encoded), `"udm":null`) {
		t.Errorf("evidence JSON = %s, want udm null", encoded)
	}
	if strings.Contains(string(encoded), `"actor"`) || strings.Contains(string(encoded), `"action"`) {
		t.Errorf("evidence JSON = %s, want no activity fields", encoded)
	}
}

func TestTimelineActivityOnly(t *testing.T) {
	service, db := newTestService(t, 50)
	analyst := createUser(t, db, "analyst@example.com", "ANALYST")
	detail := insertCase(t, db, caseFixture{Title: "Activity"})
	alertID := insertAlertRecord(t, db, alertFixture{DetectionID: "det-1", Summary: "Alert"})

	insertCaseAudit(t, db, detail.ID, eventCaseCreated, "SYSTEM", nil, testNow.Add(-3*time.Hour), nil)
	insertCaseAudit(t, db, detail.ID, eventCaseAlertAdded, "SYSTEM", nil, testNow.Add(-2*time.Hour),
		map[string]any{"alertId": alertID})
	insertCaseAudit(t, db, detail.ID, eventCaseAssigned, "USER", &analyst, testNow.Add(-time.Hour),
		map[string]any{"assigneeId": analyst})

	entries := timelineAll(t, service, detail.ID, KindActivity, 50)
	if len(entries) != 3 {
		t.Fatalf("activity entries = %d, want 3", len(entries))
	}
	wantActions := []string{"CASE_CREATED", "ALERT_ADDED", "ASSIGNED"}
	for index, want := range wantActions {
		if entries[index].Action != want || entries[index].Kind != KindActivity {
			t.Errorf("entry %d = %s/%s, want ACTIVITY/%s", index, entries[index].Kind, entries[index].Action, want)
		}
	}
	if string(entries[0].Actor) != "null" || string(entries[1].Actor) != "null" {
		t.Errorf("system actors = %s and %s, want null", entries[0].Actor, entries[1].Actor)
	}
	var actor CaseAssignee
	if err := json.Unmarshal(entries[2].Actor, &actor); err != nil {
		t.Fatalf("decode assigned actor: %v", err)
	}
	if actor.ID != analyst || actor.DisplayName != "analyst@example.com" {
		t.Errorf("assigned actor = %+v, want the analyst", actor)
	}
	if len(entries[0].Details) != 0 {
		t.Errorf("CASE_CREATED details = %v, want {}", entries[0].Details)
	}
	if entries[1].Details["alertId"] != alertID {
		t.Errorf("ALERT_ADDED details = %v, want alertId %q", entries[1].Details, alertID)
	}
	assignee, ok := entries[2].Details["assignee"].(map[string]any)
	if !ok || assignee["id"] != analyst || assignee["displayName"] != "analyst@example.com" {
		t.Errorf("ASSIGNED details = %v, want the assignee", entries[2].Details)
	}

	encoded, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatalf("encode activity entry: %v", err)
	}
	if !strings.Contains(string(encoded), `"actor":null`) {
		t.Errorf("system activity JSON = %s, want actor null", encoded)
	}
	if strings.Contains(string(encoded), `"udm"`) || strings.Contains(string(encoded), `"sourceId"`) {
		t.Errorf("activity JSON = %s, want no evidence fields", encoded)
	}
}

func TestTimelineActivityDetailsFromAllowlist(t *testing.T) {
	service, db := newTestService(t, 50)
	analyst := createUser(t, db, "analyst@example.com", "ANALYST")
	detail := insertCase(t, db, caseFixture{Title: "Allowlist"})

	insertCaseAudit(t, db, detail.ID, eventCaseAssigned, "USER", &analyst, testNow.Add(-2*time.Hour),
		map[string]any{"assigneeId": analyst, "secret": "x"})
	insertCaseAudit(t, db, detail.ID, "simple_siem.case.unknown", "SYSTEM", nil, testNow.Add(-90*time.Minute),
		map[string]any{"other": "value"})
	insertCaseAudit(t, db, detail.ID, eventCaseStatusChanged, "USER", &analyst, testNow.Add(-time.Hour),
		map[string]any{"from": StatusOpen, "to": StatusInProgress, "extra": "x"})

	entries := timelineAll(t, service, detail.ID, "", 50)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want the unknown audit event skipped", len(entries))
	}
	if entries[0].Action != "ASSIGNED" || len(entries[0].Details) != 1 {
		t.Fatalf("ASSIGNED entry = %+v, want only the assignee detail", entries[0])
	}
	if _, leaked := entries[0].Details["secret"]; leaked {
		t.Errorf("ASSIGNED details leaked a field: %v", entries[0].Details)
	}
	if entries[1].Action != "STATUS_CHANGED" || len(entries[1].Details) != 2 ||
		entries[1].Details["from"] != StatusOpen || entries[1].Details["to"] != StatusInProgress {
		t.Errorf("STATUS_CHANGED details = %v, want only from and to", entries[1].Details)
	}
}

func TestTimelineMixedKindsPaginate(t *testing.T) {
	service, db := newTestService(t, 50)
	detail := insertCase(t, db, caseFixture{Title: "Mixed"})
	alertID := insertAlertRecord(t, db, alertFixture{DetectionID: "det-1", Summary: "Alert"})
	linkCaseAlert(t, db, detail.ID, alertID)
	insertEvidence(t, db, alertID, "evt-1", testNow.Add(-4*time.Hour))
	insertEvidence(t, db, alertID, "evt-2", testNow.Add(-2*time.Hour))
	analyst := createUser(t, db, "analyst@example.com", "ANALYST")
	insertCaseAudit(t, db, detail.ID, eventCaseAssigned, "USER", &analyst, testNow.Add(-3*time.Hour),
		map[string]any{"assigneeId": analyst})
	insertCaseAudit(t, db, detail.ID, eventCaseStatusChanged, "USER", &analyst, testNow.Add(-time.Hour),
		map[string]any{"from": StatusOpen, "to": StatusInProgress})

	entries := timelineAll(t, service, detail.ID, "", 1)
	if len(entries) != 4 {
		t.Fatalf("mixed entries = %d, want 4", len(entries))
	}
	wantKinds := []string{KindEvidence, KindActivity, KindEvidence, KindActivity}
	wantTimes := []time.Time{
		testNow.Add(-4 * time.Hour), testNow.Add(-3 * time.Hour),
		testNow.Add(-2 * time.Hour), testNow.Add(-time.Hour),
	}
	seen := map[string]bool{}
	for index, entry := range entries {
		if entry.Kind != wantKinds[index] || !entry.At.Equal(wantTimes[index]) {
			t.Errorf("entry %d = %s at %v, want %s at %v",
				index, entry.Kind, entry.At, wantKinds[index], wantTimes[index])
		}
		if seen[entry.ID] {
			t.Errorf("entry %q repeated", entry.ID)
		}
		seen[entry.ID] = true
	}
}

func TestTimelineRejectsInvalidKind(t *testing.T) {
	service, db := newTestService(t, 50)
	detail := insertCase(t, db, caseFixture{Title: "Kind"})

	_, err := service.Timeline(context.Background(), detail.ID, "NOTE", 50, "")
	expectValidationError(t, err, "kind")
	if _, err := service.Timeline(context.Background(), "00000000-0000-0000-0000-000000000000", "", 50, ""); !errors.Is(err, ErrCaseNotFound) {
		t.Fatalf("unknown case error = %v, want ErrCaseNotFound", err)
	}
}

func encodeCursorPayload(t *testing.T, payload cursorPayload) string {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}
func TestAssignMovesOpenCaseToInProgress(t *testing.T) {
	service, db := newTestService(t, 50)
	analyst := createUser(t, db, "analyst@example.com", "ANALYST")
	stored := insertCase(t, db, caseFixture{Title: "Assign me"})
	actor := Actor{
		UserID: analyst, SessionID: testSessionID, RequestID: "request-1",
		IP: net.ParseIP("192.0.2.10"),
	}

	updated, err := service.Assign(context.Background(), actor, stored.ID, &analyst, stored.Version)
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if updated.Status != StatusInProgress {
		t.Errorf("status = %q, want %q", updated.Status, StatusInProgress)
	}
	if updated.Assignee == nil || updated.Assignee.ID != analyst {
		t.Errorf("assignee = %+v, want %q", updated.Assignee, analyst)
	}
	if updated.Version != stored.Version+1 {
		t.Errorf("version = %d, want %d", updated.Version, stored.Version+1)
	}

	audits, _, err := audit.List(context.Background(), db,
		audit.Filter{TargetType: "CASE", TargetID: stored.ID}, 1, 100)
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	assigned, ok := findAuditEvent(audits, eventCaseAssigned)
	if !ok {
		t.Fatalf("no %s audit event", eventCaseAssigned)
	}
	if assigned.ActorType != "USER" || assigned.ActorID == nil || *assigned.ActorID != analyst {
		t.Errorf("assigned actor = %s/%v, want USER/%q", assigned.ActorType, assigned.ActorID, analyst)
	}
	if assigned.ActorSessionID == nil || *assigned.ActorSessionID != testSessionID {
		t.Errorf("assigned session = %v, want the session id", assigned.ActorSessionID)
	}
	if assigned.RequestID != "request-1" {
		t.Errorf("assigned request id = %q, want request-1", assigned.RequestID)
	}
	if assigned.SourceIP == nil || assigned.SourceIP.String() != "192.0.2.10" {
		t.Errorf("assigned source ip = %v, want 192.0.2.10", assigned.SourceIP)
	}
	if !reflect.DeepEqual(assigned.Changes, map[string]any{"assigneeId": analyst}) {
		t.Errorf("assigned changes = %v, want the assignee", assigned.Changes)
	}
	statusChanged, ok := findAuditEvent(audits, eventCaseStatusChanged)
	if !ok {
		t.Fatalf("no %s audit event", eventCaseStatusChanged)
	}
	if !reflect.DeepEqual(statusChanged.Changes, map[string]any{"from": StatusOpen, "to": StatusInProgress}) {
		t.Errorf("status changes = %v, want OPEN to IN_PROGRESS", statusChanged.Changes)
	}

	entries := timelineAll(t, service, stored.ID, KindActivity, 50)
	if len(entries) != 2 {
		t.Fatalf("timeline has %d activity entries, want 2", len(entries))
	}
	actions := make([]string, 0, len(entries))
	for index, entry := range entries {
		var timelineActor CaseAssignee
		if err := json.Unmarshal(entry.Actor, &timelineActor); err != nil {
			t.Fatalf("decode entry %d actor: %v", index, err)
		}
		if timelineActor.ID != analyst {
			t.Errorf("entry %d actor = %+v, want the analyst", index, timelineActor)
		}
		actions = append(actions, entry.Action)
	}
	slices.Sort(actions)
	if !slices.Equal(actions, []string{"ASSIGNED", "STATUS_CHANGED"}) {
		t.Errorf("timeline actions = %v, want ASSIGNED and STATUS_CHANGED", actions)
	}

	assignedEvents := outboxEventsOfType(t, db, outbox.TypeCaseAssigned)
	if len(assignedEvents) != 1 {
		t.Fatalf("outbox has %d case.assigned rows, want 1", len(assignedEvents))
	}
	wantAssigned := map[string]any{
		"caseId":     stored.ID,
		"caseNumber": float64(stored.CaseNumber),
		"assigneeId": analyst,
		"onCall":     false,
		"link":       testPublicURL + "/cases/" + strconv.FormatInt(stored.CaseNumber, 10),
	}
	if payload := decodeObject(t, assignedEvents[0].Payload); !reflect.DeepEqual(payload, wantAssigned) {
		t.Errorf("case.assigned payload = %v, want %v", payload, wantAssigned)
	}
	var eventActor outbox.Actor
	if err := json.Unmarshal(assignedEvents[0].Actor, &eventActor); err != nil {
		t.Fatalf("decode case.assigned actor: %v", err)
	}
	if eventActor != (outbox.Actor{Type: outbox.ActorUser, ID: analyst}) {
		t.Errorf("case.assigned actor = %+v, want the analyst", eventActor)
	}

	statusEvents := outboxEventsOfType(t, db, outbox.TypeCaseStatusChanged)
	if len(statusEvents) != 1 {
		t.Fatalf("outbox has %d case.status_changed rows, want 1", len(statusEvents))
	}
	wantStatus := map[string]any{
		"caseId":     stored.ID,
		"caseNumber": float64(stored.CaseNumber),
		"from":       StatusOpen,
		"to":         StatusInProgress,
		"link":       testPublicURL + "/cases/" + strconv.FormatInt(stored.CaseNumber, 10),
	}
	if payload := decodeObject(t, statusEvents[0].Payload); !reflect.DeepEqual(payload, wantStatus) {
		t.Errorf("case.status_changed payload = %v, want %v", payload, wantStatus)
	}
}

func TestUnassignKeepsInProgress(t *testing.T) {
	service, db := newTestService(t, 50)
	analyst := createUser(t, db, "analyst@example.com", "ANALYST")
	stored := insertCase(t, db, caseFixture{
		Title: "Unassign me", Status: StatusInProgress, AssigneeID: &analyst,
	})

	updated, err := service.Assign(context.Background(), testActor(analyst), stored.ID, nil, stored.Version)
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if updated.Status != StatusInProgress {
		t.Errorf("status = %q, want it to stay %q", updated.Status, StatusInProgress)
	}
	if updated.Assignee != nil {
		t.Errorf("assignee = %+v, want none", updated.Assignee)
	}
	if updated.Version != stored.Version+1 {
		t.Errorf("version = %d, want %d", updated.Version, stored.Version+1)
	}

	events := outboxEventsOfType(t, db, outbox.TypeCaseAssigned)
	if len(events) != 1 {
		t.Fatalf("outbox has %d case.assigned rows, want 1", len(events))
	}
	payload := decodeObject(t, events[0].Payload)
	if payload["assigneeId"] != nil {
		t.Errorf("case.assigned assigneeId = %v, want null", payload["assigneeId"])
	}
	if payload["onCall"] != false {
		t.Errorf("case.assigned onCall = %v, want false", payload["onCall"])
	}
	if count := len(outboxEventsOfType(t, db, outbox.TypeCaseStatusChanged)); count != 0 {
		t.Errorf("outbox has %d case.status_changed rows, want 0", count)
	}

	audits, _, err := audit.List(context.Background(), db,
		audit.Filter{TargetType: "CASE", TargetID: stored.ID}, 1, 100)
	if err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	unassigned, ok := findAuditEvent(audits, eventCaseUnassigned)
	if !ok {
		t.Fatalf("no %s audit event", eventCaseUnassigned)
	}
	if len(unassigned.Changes) != 0 {
		t.Errorf("unassigned changes = %v, want {}", unassigned.Changes)
	}
	if len(audits) != 1 {
		t.Errorf("audit has %d events, want only the unassign", len(audits))
	}
}

func TestAssignRejectsStaleVersion(t *testing.T) {
	service, db := newTestService(t, 50)
	analyst := createUser(t, db, "analyst@example.com", "ANALYST")
	stored := insertCase(t, db, caseFixture{Title: "Stale"})
	if err := db.Exec("UPDATE cases SET version = 3 WHERE id = ?", stored.ID).Error; err != nil {
		t.Fatalf("bump version: %v", err)
	}

	_, err := service.Assign(context.Background(), testActor(analyst), stored.ID, &analyst, 1)
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("error = %v, want ErrVersionConflict", err)
	}
	after := loadCaseByID(t, db, stored.ID)
	if after.AssigneeUserID != nil || after.Version != 3 {
		t.Errorf("case changed to assignee %v version %d, want none and 3", after.AssigneeUserID, after.Version)
	}
	expectNoAssignWrites(t, db, stored.ID)
}

func TestAssignRejectsClosedCase(t *testing.T) {
	service, db := newTestService(t, 50)
	analyst := createUser(t, db, "analyst@example.com", "ANALYST")
	closed := testNow.Add(-time.Hour)
	stored := insertCase(t, db, caseFixture{
		Title: "Closed", Status: StatusClosed, ClosedAt: &closed,
	})

	for _, version := range []int{stored.Version, stored.Version + 5} {
		_, err := service.Assign(context.Background(), testActor(analyst), stored.ID, &analyst, version)
		if !errors.Is(err, ErrCaseClosed) {
			t.Fatalf("Assign version %d error = %v, want ErrCaseClosed", version, err)
		}
	}
	after := loadCaseByID(t, db, stored.ID)
	if after.AssigneeUserID != nil || after.Version != stored.Version {
		t.Errorf("closed case changed to assignee %v version %d", after.AssigneeUserID, after.Version)
	}
	expectNoAssignWrites(t, db, stored.ID)
}

func TestAssignRejectsInvalidAssignee(t *testing.T) {
	disabled := func(t *testing.T, db *gorm.DB) *string {
		userID := createUser(t, db, "disabled@example.com", "ANALYST")
		if err := db.Exec("UPDATE users SET status = 'DISABLED' WHERE id = ?", userID).Error; err != nil {
			t.Fatalf("disable user: %v", err)
		}
		return &userID
	}
	withoutRead := func(t *testing.T, db *gorm.DB) *string {
		userID := createUser(t, db, "service@example.com", "SERVICE")
		return &userID
	}
	unknown := func(t *testing.T, db *gorm.DB) *string {
		userID := "00000000-0000-0000-0000-000000000001"
		return &userID
	}
	tests := []struct {
		name     string
		assignee func(*testing.T, *gorm.DB) *string
	}{
		{"disabled", disabled},
		{"without case:read", withoutRead},
		{"unknown", unknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, db := newTestService(t, 50)
			actorID := createUser(t, db, "actor@example.com", "ANALYST")
			stored := insertCase(t, db, caseFixture{Title: "Invalid assignee"})

			_, err := service.Assign(context.Background(), testActor(actorID), stored.ID, test.assignee(t, db), stored.Version)
			if !errors.Is(err, ErrInvalidAssignee) {
				t.Fatalf("error = %v, want ErrInvalidAssignee", err)
			}
			expectValidationError(t, err, "assigneeId")

			after := loadCaseByID(t, db, stored.ID)
			if after.AssigneeUserID != nil || after.Version != stored.Version {
				t.Errorf("case changed to assignee %v version %d, want none and %d",
					after.AssigneeUserID, after.Version, stored.Version)
			}
			expectNoAssignWrites(t, db, stored.ID)
		})
	}
}

func TestAssignSameAssigneeIsNoOp(t *testing.T) {
	service, db := newTestService(t, 50)
	analyst := createUser(t, db, "analyst@example.com", "ANALYST")
	stored := insertCase(t, db, caseFixture{Title: "Same", AssigneeID: &analyst})

	updated, err := service.Assign(context.Background(), testActor(analyst), stored.ID, &analyst, stored.Version)
	if err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if updated.Version != stored.Version || updated.Status != StatusOpen {
		t.Errorf("detail version/status = %d/%q, want %d/%q",
			updated.Version, updated.Status, stored.Version, StatusOpen)
	}
	if updated.Assignee == nil || updated.Assignee.ID != analyst {
		t.Errorf("assignee = %+v, want the same analyst", updated.Assignee)
	}
	expectNoAssignWrites(t, db, stored.ID)
}

func testActor(userID string) Actor {
	return Actor{UserID: userID, SessionID: testSessionID, RequestID: "request-1"}
}

func loadCaseByID(t *testing.T, db *gorm.DB, caseID string) caseRow {
	t.Helper()
	var stored caseRow
	err := db.Raw(`
		SELECT id::text AS id, case_number, title, status, severity, detection_id,
		       assignee_user_id::text AS assignee_user_id, first_event_at, last_event_at, version
		FROM cases WHERE id = ?`, caseID).Scan(&stored).Error
	if err != nil {
		t.Fatalf("load case %q: %v", caseID, err)
	}
	return stored
}

// expectNoAssignWrites checks that an assign attempt wrote no audit or outbox
// rows and left the case unchanged.
func expectNoAssignWrites(t *testing.T, db *gorm.DB, caseID string) {
	t.Helper()
	if count := countRows(t, db, "audit_events WHERE target_type = 'CASE' AND target_id = ?", caseID); count != 0 {
		t.Errorf("audit has %d case events, want 0", count)
	}
	if count := countRows(t, db, "event_outbox"); count != 0 {
		t.Errorf("outbox has %d rows, want 0", count)
	}
}

func TestCountsCapped(t *testing.T) {
	service, db := newTestService(t, 50)
	actor := createUser(t, db, "actor@example.com", "ANALYST")
	insertClosedCases(t, db, 1200, testNow.Add(-2*time.Hour))

	counts, err := service.Counts(context.Background(), actor, ListFilter{
		From: timePointer(testNow.Add(-24 * time.Hour)), To: timePointer(testNow),
	}, TabAll)
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if counts.Status.Closed != CountsCap || counts.Status.All != CountsCap {
		t.Errorf("CLOSED/ALL = %d/%d, want %d/%d", counts.Status.Closed, counts.Status.All, CountsCap, CountsCap)
	}
	if counts.Scope.All != CountsCap {
		t.Errorf("scope all = %d, want %d", counts.Scope.All, CountsCap)
	}
	if counts.Cap != CountsCap {
		t.Errorf("cap = %d, want %d", counts.Cap, CountsCap)
	}
	if counts.Status.Open != 0 || counts.Status.InProgress != 0 {
		t.Errorf("OPEN/IN_PROGRESS = %d/%d, want 0/0", counts.Status.Open, counts.Status.InProgress)
	}
}

func TestCountsOpenIgnoresTimeRange(t *testing.T) {
	service, db := newTestService(t, 50)
	actor := createUser(t, db, "actor@example.com", "ANALYST")
	oldEvent := testNow.Add(-30 * 24 * time.Hour)
	insertCase(t, db, caseFixture{
		Title: "Old open", Status: StatusOpen,
		FirstEventAt: oldEvent, LastEventAt: oldEvent, CreatedAt: oldEvent,
	})
	insertCase(t, db, caseFixture{
		Title: "Closed inside", Status: StatusClosed, ClosedAt: timePointer(testNow.Add(-2 * time.Hour)),
		LastEventAt: testNow.Add(-2 * time.Hour),
	})
	insertCase(t, db, caseFixture{
		Title: "Closed outside", Status: StatusClosed, ClosedAt: timePointer(oldEvent),
		LastEventAt: oldEvent, CreatedAt: oldEvent,
	})

	filter := ListFilter{
		From: timePointer(testNow.Add(-24 * time.Hour)), To: timePointer(testNow),
		TimeField: TimeFieldLastEventAt,
	}
	counts, err := service.Counts(context.Background(), actor, filter, TabAll)
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if counts.Status.Open != 1 {
		t.Errorf("OPEN = %d, want the 30-day-old open case", counts.Status.Open)
	}
	if counts.Status.Closed != 1 {
		t.Errorf("CLOSED = %d, want only the case inside the range", counts.Status.Closed)
	}
	if counts.Status.All != 1 {
		t.Errorf("ALL = %d, want only the cases inside the range", counts.Status.All)
	}

	openScopes, err := service.Counts(context.Background(), actor, filter, TabOpen)
	if err != nil {
		t.Fatalf("Counts tab open: %v", err)
	}
	if openScopes.Scope.All != 1 || openScopes.Scope.Unassigned != 1 {
		t.Errorf("open scopes = %+v, want the old open case counted", openScopes.Scope)
	}
	closedScopes, err := service.Counts(context.Background(), actor, filter, TabClosed)
	if err != nil {
		t.Fatalf("Counts tab closed: %v", err)
	}
	if closedScopes.Scope.All != 1 {
		t.Errorf("closed scope all = %d, want only the case inside the range", closedScopes.Scope.All)
	}
}

func TestCountsScopeFollowsTab(t *testing.T) {
	service, db := newTestService(t, 50)
	alice := createUser(t, db, "alice@example.com", "ANALYST")
	insertCase(t, db, caseFixture{Title: "Open unassigned"})
	insertCase(t, db, caseFixture{Title: "Open mine", AssigneeID: &alice})
	insertCase(t, db, caseFixture{Title: "In progress mine", Status: StatusInProgress, AssigneeID: &alice})
	insertCase(t, db, caseFixture{Title: "Closed unassigned", Status: StatusClosed})
	filter := ListFilter{Scope: ScopeMine}

	tests := []struct {
		tab  string
		want ScopeCounts
	}{
		{TabOpen, ScopeCounts{Mine: 1, Unassigned: 1, All: 2}},
		{TabInProgress, ScopeCounts{Mine: 1, Unassigned: 0, All: 1}},
		{TabClosed, ScopeCounts{Mine: 0, Unassigned: 1, All: 1}},
		{TabAll, ScopeCounts{Mine: 2, Unassigned: 2, All: 4}},
	}
	for _, test := range tests {
		t.Run(test.tab, func(t *testing.T) {
			counts, err := service.Counts(context.Background(), alice, filter, test.tab)
			if err != nil {
				t.Fatalf("Counts: %v", err)
			}
			if counts.Scope != test.want {
				t.Errorf("scope = %+v, want %+v", counts.Scope, test.want)
			}
		})
	}

	_, err := service.Counts(context.Background(), alice, filter, "bogus")
	expectValidationError(t, err, "status")
}

func TestCountsArePerUserWithinCacheWindow(t *testing.T) {
	service, db := newTestService(t, 50)
	alice := createUser(t, db, "alice@example.com", "ANALYST")
	bob := createUser(t, db, "bob@example.com", "ANALYST")
	insertCase(t, db, caseFixture{Title: "Alice one", AssigneeID: &alice})
	insertCase(t, db, caseFixture{Title: "Alice two", AssigneeID: &alice})
	insertCase(t, db, caseFixture{Title: "Bob one", AssigneeID: &bob})

	filter := ListFilter{Scope: ScopeMine}
	aliceCounts, err := service.Counts(context.Background(), alice, filter, TabAll)
	if err != nil {
		t.Fatalf("Counts for alice: %v", err)
	}
	bobCounts, err := service.Counts(context.Background(), bob, filter, TabAll)
	if err != nil {
		t.Fatalf("Counts for bob: %v", err)
	}
	if aliceCounts.Scope.Mine != 2 {
		t.Errorf("alice mine = %d, want 2", aliceCounts.Scope.Mine)
	}
	if bobCounts.Scope.Mine != 1 {
		t.Errorf("bob mine = %d, want 1", bobCounts.Scope.Mine)
	}
}

func TestCountsCacheExpires(t *testing.T) {
	service, db := newTestService(t, 50)
	actor := createUser(t, db, "actor@example.com", "ANALYST")
	insertCase(t, db, caseFixture{Title: "First"})

	first, err := service.Counts(context.Background(), actor, ListFilter{}, TabAll)
	if err != nil {
		t.Fatalf("Counts: %v", err)
	}
	if first.Scope.All != 1 {
		t.Fatalf("all = %d, want 1", first.Scope.All)
	}
	insertCase(t, db, caseFixture{Title: "Second"})

	stale, err := service.Counts(context.Background(), actor, ListFilter{}, TabAll)
	if err != nil {
		t.Fatalf("Counts inside the window: %v", err)
	}
	if stale.Scope.All != 1 {
		t.Errorf("cached all = %d, want the stale 1", stale.Scope.All)
	}

	service.now = func() time.Time { return testNow.Add(countsCacheTTL + time.Second) }
	fresh, err := service.Counts(context.Background(), actor, ListFilter{}, TabAll)
	if err != nil {
		t.Fatalf("Counts after the window: %v", err)
	}
	if fresh.Scope.All != 2 {
		t.Errorf("fresh all = %d, want 2", fresh.Scope.All)
	}
}

func TestCountsCacheEntryCap(t *testing.T) {
	service := &Service{
		now:         func() time.Time { return testNow },
		countsCache: make(map[string]countsCacheEntry),
	}
	for index := 0; index < maxCountsCacheEntries; index++ {
		service.storeCounts(strconv.Itoa(index), Counts{})
	}
	if len(service.countsCache) != maxCountsCacheEntries {
		t.Fatalf("cache holds %d entries, want %d", len(service.countsCache), maxCountsCacheEntries)
	}
	service.storeCounts("overflow", Counts{})
	if len(service.countsCache) != 1 {
		t.Errorf("cache holds %d entries after the cap, want it cleared", len(service.countsCache))
	}
	if _, ok := service.countsCache["overflow"]; !ok {
		t.Errorf("the new entry is missing after the cap")
	}
}

func TestHistogramAutoInterval(t *testing.T) {
	service, db := newTestService(t, 50)
	insertCase(t, db, caseFixture{
		Title: "High late", Severity: string(alerts.SeverityHigh), LastEventAt: testNow.Add(-23 * time.Hour),
	})
	insertCase(t, db, caseFixture{
		Title: "Medium", Severity: string(alerts.SeverityMedium), LastEventAt: testNow.Add(-12 * time.Hour),
	})
	insertCase(t, db, caseFixture{
		Title: "Low", Severity: string(alerts.SeverityLow), LastEventAt: testNow.Add(-time.Hour),
	})
	insertCase(t, db, caseFixture{
		Title: "High recent", Severity: string(alerts.SeverityHigh), LastEventAt: testNow.Add(-time.Hour),
	})

	filter := ListFilter{
		From: timePointer(testNow.Add(-24 * time.Hour)), To: timePointer(testNow),
		TimeField: TimeFieldLastEventAt,
	}
	histogram, err := service.Histogram(context.Background(), "", filter)
	if err != nil {
		t.Fatalf("Histogram: %v", err)
	}
	if histogram.Interval != "30m" {
		t.Errorf("interval = %q, want 30m for 24 hours", histogram.Interval)
	}
	if len(histogram.Buckets) != 48 && len(histogram.Buckets) != 49 {
		t.Errorf("bucket count = %d, want 48 or 49", len(histogram.Buckets))
	}
	if histogram.Buckets[0].Start.After(*filter.From) {
		t.Errorf("first bucket starts at %v, want at or before %v", histogram.Buckets[0].Start, *filter.From)
	}
	if !histogram.Buckets[len(histogram.Buckets)-1].Start.Before(*filter.To) {
		t.Errorf("last bucket starts at or after to")
	}

	var high, medium, low, total int64
	emptyBuckets := 0
	for _, bucket := range histogram.Buckets {
		high += bucket.Counts.High
		medium += bucket.Counts.Medium
		low += bucket.Counts.Low
		total += bucket.Counts.High + bucket.Counts.Medium + bucket.Counts.Low
		if bucket.Counts.High == 0 && bucket.Counts.Medium == 0 && bucket.Counts.Low == 0 {
			emptyBuckets++
		}
	}
	if emptyBuckets == 0 {
		t.Errorf("no empty buckets, want zero-filled ones")
	}
	if high != 2 || medium != 1 || low != 1 {
		t.Errorf("severity totals = %d/%d/%d, want 2/1/1", high, medium, low)
	}

	listFilter := filter
	listFilter.Limit = MaxListLimit
	page, err := service.List(context.Background(), "", listFilter)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != int64(len(page.Items)) {
		t.Errorf("bucket total = %d, want the list count %d", total, len(page.Items))
	}
}

func TestHistogramRequiresRange(t *testing.T) {
	service, _ := newTestService(t, 50)

	_, err := service.Histogram(context.Background(), "", ListFilter{To: timePointer(testNow)})
	expectValidationError(t, err, "from")
	_, err = service.Histogram(context.Background(), "", ListFilter{From: timePointer(testNow.Add(-time.Hour))})
	expectValidationError(t, err, "to")
	_, err = service.Histogram(context.Background(), "", ListFilter{
		From: timePointer(testNow.Add(-1001 * 24 * time.Hour)), To: timePointer(testNow),
	})
	expectValidationError(t, err, "from")
}

func insertClosedCases(t *testing.T, db *gorm.DB, count int, lastEventAt time.Time) {
	t.Helper()
	err := db.Exec(`
		INSERT INTO cases (title, status, severity, detection_id, first_event_at,
		                   last_event_at, closed_at, created_at)
		SELECT 'Bulk ' || series, 'CLOSED', 'HIGH', 'bulk', ?, ?, ?, ?
		FROM generate_series(1, ?) AS series`,
		lastEventAt, lastEventAt, lastEventAt, testNow, count).Error
	if err != nil {
		t.Fatalf("insert %d closed cases: %v", count, err)
	}
}

func TestAssignInvalidCaseID(t *testing.T) {
	service, _ := newTestService(t, 50)
	analyst := "00000000-0000-0000-0000-000000000001"

	_, err := service.Assign(context.Background(), testActor(analyst), "not-a-uuid", &analyst, 1)
	if !errors.Is(err, ErrCaseNotFound) {
		t.Fatalf("error = %v, want ErrCaseNotFound", err)
	}
}
