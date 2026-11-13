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

func TestRecordRejectsUnmarshallableChanges(t *testing.T) {
	db := databasetest.New(t)
	baseline := countEvents(t, db, "")
	event := validEvent("unmarshallable")
	event.Changes = map[string]any{"after": map[string]any{"value": func() {}}}

	err := audit.Record(db, event)
	if err == nil {
		t.Fatal("Record accepted changes that cannot be marshalled")
	}
	if got := countEvents(t, db, ""); got != baseline {
		t.Errorf("audit events changed from %d to %d after a rejected event", baseline, got)
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
			"auth":    auth,
			"entries": []any{session},
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
	entries, ok := after["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("stored changes has no after.entries array: %s", stored.Changes)
	}
	storedSession, ok := entries[0].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after.entries[0] object: %s", stored.Changes)
	}
	if got := storedSession["token"]; got != redactedValue {
		t.Errorf("stored changes.after.entries[0].token = %v, want %s", got, redactedValue)
	}
}

func TestRecordRedactsNestedSecrets(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent("nested-redaction")
	event.Changes = map[string]any{
		"after": map[string]any{
			"auth": map[string]any{"apiKey": "k-123"},
			"entries": []any{
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
	entries, ok := after["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("stored changes has no after.entries array: %s", stored.Changes)
	}
	session, ok := entries[0].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after.entries[0] object: %s", stored.Changes)
	}
	if got := session["token"]; got != redactedValue {
		t.Errorf("stored changes.after.entries[0].token = %v, want %s", got, redactedValue)
	}

	redactions := storedRedactions(t, stored)
	for _, path := range []string{"changes.after.auth.apiKey", "changes.after.entries[0].token"} {
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

func TestRecordRedactsNestedTypedChanges(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent("typed-nested-redaction")
	event.Changes = map[string]any{
		"after": map[string]any{
			"headers": map[string]string{
				"Authorization": "Bearer header-secret",
				"Accept":        "application/json",
			},
			"accounts": []map[string]any{
				{"name": "primary", "password": "array-secret"},
			},
			"details": struct {
				SessionToken string `json:"sessionToken"`
			}{SessionToken: "struct-secret"},
		},
	}

	if err := audit.Record(db, event); err != nil {
		t.Fatalf("Record: %v", err)
	}
	stored := storedEventByTarget(t, db, event.TargetID)
	for _, secret := range []string{"header-secret", "array-secret", "struct-secret"} {
		if strings.Contains(string(stored.Changes), secret) {
			t.Errorf("stored changes contain the secret %q: %s", secret, stored.Changes)
		}
	}

	changes := storedChanges(t, stored)
	after, ok := changes["after"].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after object: %s", stored.Changes)
	}
	headers, ok := after["headers"].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after.headers object: %s", stored.Changes)
	}
	if got := headers["Authorization"]; got != redactedValue {
		t.Errorf("stored changes.after.headers.Authorization = %v, want %s", got, redactedValue)
	}
	if got := headers["Accept"]; got != "application/json" {
		t.Errorf("stored changes.after.headers.Accept = %v, want application/json", got)
	}

	accounts, ok := after["accounts"].([]any)
	if !ok || len(accounts) != 1 {
		t.Fatalf("stored changes has no after.accounts array: %s", stored.Changes)
	}
	account, ok := accounts[0].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after.accounts[0] object: %s", stored.Changes)
	}
	if got := account["password"]; got != redactedValue {
		t.Errorf("stored changes.after.accounts[0].password = %v, want %s", got, redactedValue)
	}
	if got := account["name"]; got != "primary" {
		t.Errorf("stored changes.after.accounts[0].name = %v, want primary", got)
	}

	details, ok := after["details"].(map[string]any)
	if !ok {
		t.Fatalf("stored changes has no after.details object: %s", stored.Changes)
	}
	if got := details["sessionToken"]; got != redactedValue {
		t.Errorf("stored changes.after.details.sessionToken = %v, want %s", got, redactedValue)
	}

	redactions := storedRedactions(t, stored)
	for _, path := range []string{
		"changes.after.headers.Authorization",
		"changes.after.accounts[0].password",
		"changes.after.details.sessionToken",
	} {
		if !slices.Contains(redactions, path) {
			t.Errorf("redactions %v do not contain %s", redactions, path)
		}
	}
}

func TestRecordRedactsEverySensitiveKeyPart(t *testing.T) {
	db := databasetest.New(t)
	for _, part := range []string{
		"password", "token", "secret", "apikey", "api_key", "authorization",
		"passwd", "credential", "cookie", "private_key", "privatekey", "session", "bearer",
	} {
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

func TestRecordRedactsIdentifierLookingCredentials(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent("identifier-looking-credentials")
	event.Changes = map[string]any{
		"after": map[string]any{
			"sessionId":     "session_456",
			"secret_id":     "s-1",
			"token_valid":   "t-2",
			"sessionCookie": "c-789",
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
	for _, key := range []string{"sessionId", "secret_id", "token_valid", "sessionCookie"} {
		if got := after[key]; got != redactedValue {
			t.Errorf("stored changes.after.%s = %v, want %s", key, got, redactedValue)
		}
	}

	redactions := storedRedactions(t, stored)
	want := []string{
		"changes.after.secret_id",
		"changes.after.sessionCookie",
		"changes.after.sessionId",
		"changes.after.token_valid",
	}
	if !slices.Equal(redactions, want) {
		t.Errorf("stored redactions = %v, want %v", redactions, want)
	}

	var row string
	if err := db.Raw("SELECT row_to_json(t)::text FROM audit_events t WHERE target_id = ?", event.TargetID).Scan(&row).Error; err != nil {
		t.Fatalf("read audit event row for target %q: %v", event.TargetID, err)
	}
	for _, credential := range []string{"session_456", "s-1", "t-2", "c-789"} {
		if strings.Contains(row, credential) {
			t.Errorf("stored audit row contains the credential %q: %s", credential, row)
		}
	}
}

func TestRecordKeepsReferenceKeys(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent("reference-keys")
	event.Changes = map[string]any{
		"after": map[string]any{
			"secretRef":     "env:ES_KEY",
			"secret_ref_id": "sr_1",
			"password-ref":  "vault:db",
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
	for key, want := range map[string]string{
		"secretRef":     "env:ES_KEY",
		"secret_ref_id": "sr_1",
		"password-ref":  "vault:db",
	} {
		if got := after[key]; got != want {
			t.Errorf("stored changes.after.%s = %v, want %s", key, got, want)
		}
	}
	if redactions := storedRedactions(t, stored); len(redactions) != 0 {
		t.Errorf("stored redactions = %v, want none", redactions)
	}
}

func TestMigrateAuditsAppliedMigration(t *testing.T) {
	db := databasetest.New(t)

	if got := countEvents(t, db, ""); got != 2 {
		t.Fatalf("fresh database has %d audit events, want exactly 2", got)
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
	if got := countEvents(t, db, ""); got != 2 {
		t.Errorf("second Migrate changed the audit event count to %d, want 2", got)
	}
}

func TestMigrateRestoresMissingMigrationAuditEvent(t *testing.T) {
	db := databasetest.New(t)
	if err := db.Exec("DELETE FROM audit_events WHERE target_type = ? AND target_id = ?", "DATABASE_MIGRATION", "1").Error; err != nil {
		t.Fatalf("delete migration audit event: %v", err)
	}
	if got := countEvents(t, db, "target_type = ? AND target_id = ?", "DATABASE_MIGRATION", "1"); got != 0 {
		t.Fatalf("migration 1 has %d audit events after deletion, want 0", got)
	}

	applied, err := database.Migrate(context.Background(), db)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("Migrate applied %v on an up-to-date database, want none", applied)
	}
	if got := countEvents(t, db, "target_type = ? AND target_id = ?", "DATABASE_MIGRATION", "1"); got != 1 {
		t.Errorf("migration 1 has %d audit events after Migrate, want 1", got)
	}
}

func TestMigrateDoesNotDuplicateMigrationAuditEvents(t *testing.T) {
	db := databasetest.New(t)

	for run := 1; run <= 2; run++ {
		if _, err := database.Migrate(context.Background(), db); err != nil {
			t.Fatalf("Migrate run %d: %v", run, err)
		}
	}
	for _, version := range []string{"1", "2"} {
		if got := countEvents(t, db, "target_type = ? AND target_id = ?", "DATABASE_MIGRATION", version); got != 1 {
			t.Errorf("migration %s has %d audit events after two Migrate runs, want 1", version, got)
		}
	}
	if got := countEvents(t, db, ""); got != 2 {
		t.Errorf("database has %d audit events after two Migrate runs, want 2", got)
	}
}

func TestRecordRejectsDuplicateMigrationAppliedEvent(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent("999")
	event.EventName = "simple_siem.database.migration_applied"
	event.EventCategory = "DATABASE"
	event.TargetType = "DATABASE_MIGRATION"
	event.Action = "apply"

	if err := audit.Record(db, event); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	if err := audit.Record(db, event); err == nil {
		t.Fatal("Record accepted a second migration_applied event for the same version")
	}
	if got := countEvents(t, db, "event_name = ? AND target_id = ?", event.EventName, event.TargetID); got != 1 {
		t.Errorf("stored %d migration_applied events for version %s, want 1", got, event.TargetID)
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
