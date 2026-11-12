package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/database"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"gorm.io/gorm"
)

const redactedValue = "[REDACTED]"

type storedEvent struct {
	ID            string    `gorm:"column:id"`
	CreatedAt     time.Time `gorm:"column:created_at"`
	EventName     string    `gorm:"column:event_name"`
	EventCategory string    `gorm:"column:event_category"`
	EventOutcome  string    `gorm:"column:event_outcome"`
	ActorType     string    `gorm:"column:actor_type"`
	ActorID       *string   `gorm:"column:actor_id"`
	RequestID     string    `gorm:"column:request_id"`
	TraceID       string    `gorm:"column:trace_id"`
	SourceIP      *string   `gorm:"column:source_ip"`
	TargetType    string    `gorm:"column:target_type"`
	TargetID      string    `gorm:"column:target_id"`
	Action        string    `gorm:"column:action"`
	Changes       []byte    `gorm:"column:changes"`
	Redactions    []byte    `gorm:"column:redactions"`
}

func TestRecordUsesDatabaseDefaults(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent("database-defaults")
	event.ID = "caller-supplied-id"
	event.CreatedAt = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

	if err := audit.Record(db, event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	stored := storedEventByTarget(t, db, event.TargetID)
	if stored.ID == event.ID {
		t.Errorf("stored id %q came from the event, want a database-generated UUID", stored.ID)
	}
	uuidV7 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidV7.MatchString(stored.ID) {
		t.Errorf("stored id %q is not a UUIDv7", stored.ID)
	}
	if stored.CreatedAt.Equal(event.CreatedAt) {
		t.Error("stored created_at came from the event, want the database clock")
	}
	if delta := time.Since(stored.CreatedAt); delta < -time.Minute || delta > time.Minute {
		t.Errorf("stored created_at %v is not close to now", stored.CreatedAt)
	}
}

func TestRecordWritesEventFields(t *testing.T) {
	db := databasetest.New(t)
	actorID := "actor-1"
	event := validEvent("all-fields")
	event.ActorID = &actorID
	event.RequestID = "request-1"
	event.TraceID = "trace-1"
	event.SourceIP = net.IP{192, 0, 2, 10}
	event.Changes = map[string]any{
		"before": map[string]any{"status": "OPEN"},
		"after":  map[string]any{"status": "CLOSED"},
	}

	if err := audit.Record(db, event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	stored := storedEventByTarget(t, db, event.TargetID)
	fields := []struct {
		name string
		got  string
		want string
	}{
		{"event_name", stored.EventName, event.EventName},
		{"event_category", stored.EventCategory, event.EventCategory},
		{"event_outcome", stored.EventOutcome, event.EventOutcome},
		{"actor_type", stored.ActorType, event.ActorType},
		{"request_id", stored.RequestID, event.RequestID},
		{"trace_id", stored.TraceID, event.TraceID},
		{"target_type", stored.TargetType, event.TargetType},
		{"target_id", stored.TargetID, event.TargetID},
		{"action", stored.Action, event.Action},
	}
	for _, field := range fields {
		if field.got != field.want {
			t.Errorf("stored %s = %q, want %q", field.name, field.got, field.want)
		}
	}
	if stored.ActorID == nil || *stored.ActorID != actorID {
		t.Errorf("stored actor_id = %v, want %q", stored.ActorID, actorID)
	}
	if stored.SourceIP == nil {
		t.Error("stored source_ip is NULL, want 192.0.2.10")
	} else if *stored.SourceIP != "192.0.2.10" {
		t.Errorf("stored source_ip = %q, want 192.0.2.10", *stored.SourceIP)
	}

	changes := storedChanges(t, stored)
	after, ok := changes["after"].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after object: %s", stored.Changes)
	}
	if after["status"] != "CLOSED" {
		t.Errorf("stored changes.after.status = %v, want CLOSED", after["status"])
	}

	redactions := storedRedactions(t, stored)
	if len(redactions) != 0 {
		t.Errorf("stored redactions = %v, want none", redactions)
	}
}

func TestRecordRollsBackChangeWhenAuditFails(t *testing.T) {
	db := databasetest.New(t)
	if err := db.Exec("CREATE TABLE rollback_probe (id integer PRIMARY KEY, value text NOT NULL)").Error; err != nil {
		t.Fatalf("create rollback probe table: %v", err)
	}
	baseline := countEvents(t, db, "")
	event := validEvent("audit-failure")
	event.Changes = map[string]any{"after": map[string]any{"value": func() {}}}

	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("INSERT INTO rollback_probe (id, value) VALUES (?, ?)", 1, "changed").Error; err != nil {
			return err
		}
		return audit.Record(tx, event)
	})
	if err == nil {
		t.Fatal("transaction committed although the audit event could not be inserted")
	}

	var probeCount int64
	if err := db.Raw("SELECT count(*) FROM rollback_probe").Scan(&probeCount).Error; err != nil {
		t.Fatalf("count rollback probe rows: %v", err)
	}
	if probeCount != 0 {
		t.Errorf("rollback probe kept %d rows, want 0", probeCount)
	}
	if got := countEvents(t, db, ""); got != baseline {
		t.Errorf("audit events changed from %d to %d after rollback", baseline, got)
	}
}

func TestRecordRollsBackAuditEventWhenTransactionFails(t *testing.T) {
	db := databasetest.New(t)
	target := "rolled-back-audit"
	sentinel := errors.New("transaction failed")

	err := db.Transaction(func(tx *gorm.DB) error {
		if err := audit.Record(tx, validEvent(target)); err != nil {
			return err
		}
		if got := countEvents(t, tx, "target_id = ?", target); got != 1 {
			t.Errorf("audit event visible inside the transaction: got %d, want 1", got)
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("transaction returned %v, want %v", err, sentinel)
	}
	if got := countEvents(t, db, "target_id = ?", target); got != 0 {
		t.Errorf("audit event survived rollback: got %d, want 0", got)
	}
}

func TestRecordRejectsMissingRequiredFields(t *testing.T) {
	db := databasetest.New(t)
	baseline := countEvents(t, db, "")
	cases := []struct {
		field string
		clear func(*audit.Event)
	}{
		{"eventName", func(event *audit.Event) { event.EventName = "" }},
		{"eventCategory", func(event *audit.Event) { event.EventCategory = "" }},
		{"eventOutcome", func(event *audit.Event) { event.EventOutcome = "" }},
		{"actorType", func(event *audit.Event) { event.ActorType = "" }},
		{"targetType", func(event *audit.Event) { event.TargetType = "" }},
		{"targetId", func(event *audit.Event) { event.TargetID = "" }},
		{"action", func(event *audit.Event) { event.Action = "" }},
	}

	for _, testCase := range cases {
		t.Run(testCase.field, func(t *testing.T) {
			event := validEvent("missing-" + testCase.field)
			testCase.clear(&event)

			err := audit.Record(db, event)
			if err == nil {
				t.Fatalf("Record accepted an event without %s", testCase.field)
			}
			if !strings.Contains(err.Error(), testCase.field) {
				t.Errorf("Record error %q does not name %s", err, testCase.field)
			}
			if got := countEvents(t, db, ""); got != baseline {
				t.Errorf("audit events changed from %d to %d after a rejected event", baseline, got)
			}
		})
	}
}

func TestRecordRejectsUnknownOutcome(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent("unknown-outcome")
	event.EventOutcome = "MAYBE"

	err := audit.Record(db, event)
	if err == nil {
		t.Fatal("Record accepted outcome MAYBE")
	}
	if !strings.Contains(err.Error(), "MAYBE") {
		t.Errorf("Record error %q does not name the rejected outcome", err)
	}
	if got := countEvents(t, db, "target_id = ?", event.TargetID); got != 0 {
		t.Errorf("Record inserted %d events for an invalid outcome, want 0", got)
	}
}

func TestRecordAcceptsEveryOutcome(t *testing.T) {
	db := databasetest.New(t)
	outcomes := []string{"SUCCESS", "DENIED", "VALIDATION_FAILED", "FAILED", "PARTIAL", "CANCELED", "SKIPPED"}

	for _, outcome := range outcomes {
		t.Run(outcome, func(t *testing.T) {
			event := validEvent("outcome-" + outcome)
			event.EventOutcome = outcome

			if err := audit.Record(db, event); err != nil {
				t.Fatalf("Record outcome %s: %v", outcome, err)
			}
			if got := countEvents(t, db, "target_id = ?", event.TargetID); got != 1 {
				t.Errorf("Record wrote %d events for outcome %s, want 1", got, outcome)
			}
		})
	}
}

func TestRecordDoesNotMutateCallerChanges(t *testing.T) {
	db := databasetest.New(t)
	auth := map[string]any{"apiKey": "k-123"}
	session := map[string]any{"token": "t-456"}
	event := validEvent("caller-unchanged")
	event.Changes = map[string]any{
		"after": map[string]any{
			"auth":     auth,
			"sessions": []any{session},
		},
	}

	if err := audit.Record(db, event); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if got := auth["apiKey"]; got != "k-123" {
		t.Errorf("Record mutated the caller's nested map: apiKey = %v, want k-123", got)
	}
	if got := session["token"]; got != "t-456" {
		t.Errorf("Record mutated the caller's nested slice element: token = %v, want t-456", got)
	}

	stored := storedEventByTarget(t, db, event.TargetID)
	if strings.Contains(string(stored.Changes), "k-123") || strings.Contains(string(stored.Changes), "t-456") {
		t.Errorf("stored changes contain a caller secret: %s", stored.Changes)
	}
	changes := storedChanges(t, stored)
	after, ok := changes["after"].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after object: %s", stored.Changes)
	}
	storedAuth, ok := after["auth"].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after.auth object: %s", stored.Changes)
	}
	if got := storedAuth["apiKey"]; got != redactedValue {
		t.Errorf("stored changes.after.auth.apiKey = %v, want %s", got, redactedValue)
	}
	sessions, ok := after["sessions"].([]any)
	if !ok || len(sessions) != 1 {
		t.Fatalf("stored changes has no after.sessions array: %s", stored.Changes)
	}
	storedSession, ok := sessions[0].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after.sessions[0] object: %s", stored.Changes)
	}
	if got := storedSession["token"]; got != redactedValue {
		t.Errorf("stored changes.after.sessions[0].token = %v, want %s", got, redactedValue)
	}
}

func TestRecordRedactsNestedSecrets(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent("nested-redaction")
	event.Changes = map[string]any{
		"after": map[string]any{
			"auth": map[string]any{"apiKey": "k-123"},
			"sessions": []any{
				map[string]any{"token": "t-456"},
			},
		},
	}

	if err := audit.Record(db, event); err != nil {
		t.Fatalf("Record: %v", err)
	}
	stored := storedEventByTarget(t, db, event.TargetID)
	changes := storedChanges(t, stored)
	after, ok := changes["after"].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after object: %s", stored.Changes)
	}
	auth, ok := after["auth"].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after.auth object: %s", stored.Changes)
	}
	if got := auth["apiKey"]; got != redactedValue {
		t.Errorf("stored changes.after.auth.apiKey = %v, want %s", got, redactedValue)
	}
	sessions, ok := after["sessions"].([]any)
	if !ok || len(sessions) != 1 {
		t.Fatalf("stored changes has no after.sessions array: %s", stored.Changes)
	}
	session, ok := sessions[0].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after.sessions[0] object: %s", stored.Changes)
	}
	if got := session["token"]; got != redactedValue {
		t.Errorf("stored changes.after.sessions[0].token = %v, want %s", got, redactedValue)
	}

	redactions := storedRedactions(t, stored)
	for _, path := range []string{"changes.after.auth.apiKey", "changes.after.sessions[0].token"} {
		if !slices.Contains(redactions, path) {
			t.Errorf("redactions %v do not contain %s", redactions, path)
		}
	}

	var row string
	if err := db.Raw("SELECT row_to_json(t)::text FROM audit_events t WHERE target_id = ?", event.TargetID).Scan(&row).Error; err != nil {
		t.Fatalf("read audit event row for target %q: %v", event.TargetID, err)
	}
	for _, secret := range []string{"k-123", "t-456"} {
		if strings.Contains(row, secret) {
			t.Errorf("stored audit row contains the secret %q: %s", secret, row)
		}
	}
}

func TestRecordRedactsEverySensitiveKeyPart(t *testing.T) {
	db := databasetest.New(t)
	for _, part := range []string{"password", "token", "secret", "apikey", "api_key", "authorization"} {
		t.Run(part, func(t *testing.T) {
			key := "my" + strings.ToUpper(part) + "Value"
			secret := "sensitive-value-" + part
			event := validEvent("redaction-" + part)
			event.Changes = map[string]any{"after": map[string]any{key: secret}}

			if err := audit.Record(db, event); err != nil {
				t.Fatalf("Record: %v", err)
			}
			stored := storedEventByTarget(t, db, event.TargetID)
			if strings.Contains(string(stored.Changes), secret) {
				t.Errorf("stored changes contain the secret: %s", stored.Changes)
			}

			changes := storedChanges(t, stored)
			after, ok := changes["after"].(map[string]any)
			if !ok {
				t.Fatalf("stored changes has no after object: %s", stored.Changes)
			}
			if got := after[key]; got != redactedValue {
				t.Errorf("stored changes.after.%s = %v, want %s", key, got, redactedValue)
			}

			redactions := storedRedactions(t, stored)
			path := "changes.after." + key
			if !slices.Contains(redactions, path) {
				t.Errorf("redactions %v do not contain %s", redactions, path)
			}
		})
	}
}

func TestMigrateAuditsAppliedMigration(t *testing.T) {
	db := databasetest.New(t)

	if got := countEvents(t, db, ""); got != 1 {
		t.Fatalf("fresh database has %d audit events, want exactly 1", got)
	}
	stored := storedEventByTarget(t, db, "1")
	fields := []struct {
		name string
		got  string
		want string
	}{
		{"event_name", stored.EventName, "simple_siem.database.migration_applied"},
		{"event_category", stored.EventCategory, "DATABASE"},
		{"event_outcome", stored.EventOutcome, "SUCCESS"},
		{"actor_type", stored.ActorType, "SYSTEM"},
		{"target_type", stored.TargetType, "DATABASE_MIGRATION"},
		{"target_id", stored.TargetID, "1"},
		{"action", stored.Action, "apply"},
	}
	for _, field := range fields {
		if field.got != field.want {
			t.Errorf("migration audit %s = %q, want %q", field.name, field.got, field.want)
		}
	}

	applied, err := database.Migrate(context.Background(), db)
	if err != nil {
		t.Fatalf("Migrate on an up-to-date database: %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("Migrate applied %v on an up-to-date database, want none", applied)
	}
	if got := countEvents(t, db, ""); got != 1 {
		t.Errorf("second Migrate changed the audit event count to %d, want 1", got)
	}
}

func validEvent(targetID string) audit.Event {
	return audit.Event{
		EventName:     "simple_siem.test.event",
		EventCategory: "TEST",
		EventOutcome:  "SUCCESS",
		ActorType:     "SYSTEM",
		TargetType:    "TEST_TARGET",
		TargetID:      targetID,
		Action:        "test",
	}
}

func storedEventByTarget(t *testing.T, db *gorm.DB, targetID string) storedEvent {
	t.Helper()
	var stored storedEvent
	err := db.Raw(`
		SELECT id::text AS id, created_at, event_name, event_category, event_outcome,
		       actor_type, actor_id, request_id, trace_id, host(source_ip) AS source_ip,
		       target_type, target_id, action, changes, redactions
		FROM audit_events
		WHERE target_id = ?`, targetID).Scan(&stored).Error
	if err != nil {
		t.Fatalf("read audit event for target %q: %v", targetID, err)
	}
	if stored.ID == "" {
		t.Fatalf("no audit event for target %q", targetID)
	}
	return stored
}

func countEvents(t *testing.T, db *gorm.DB, where string, args ...any) int64 {
	t.Helper()
	query := "SELECT count(*) FROM audit_events"
	if where != "" {
		query += " WHERE " + where
	}
	var count int64
	if err := db.Raw(query, args...).Scan(&count).Error; err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	return count
}

func storedChanges(t *testing.T, stored storedEvent) map[string]any {
	t.Helper()
	var changes map[string]any
	if err := json.Unmarshal(stored.Changes, &changes); err != nil {
		t.Fatalf("decode stored changes: %v", err)
	}
	return changes
}

func storedRedactions(t *testing.T, stored storedEvent) []string {
	t.Helper()
	var redactions []string
	if err := json.Unmarshal(stored.Redactions, &redactions); err != nil {
		t.Fatalf("decode stored redactions: %v", err)
	}
	return redactions
}
