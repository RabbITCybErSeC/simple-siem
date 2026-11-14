package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	ID             string    `gorm:"column:id"`
	CreatedAt      time.Time `gorm:"column:created_at"`
	EventName      string    `gorm:"column:event_name"`
	EventCategory  string    `gorm:"column:event_category"`
	EventOutcome   string    `gorm:"column:event_outcome"`
	ActorType      string    `gorm:"column:actor_type"`
	ActorID        *string   `gorm:"column:actor_id"`
	ActorSessionID *string   `gorm:"column:actor_session_id"`
	RequestID      string    `gorm:"column:request_id"`
	TraceID        string    `gorm:"column:trace_id"`
	SourceIP       *string   `gorm:"column:source_ip"`
	TargetType     string    `gorm:"column:target_type"`
	TargetID       string    `gorm:"column:target_id"`
	Action         string    `gorm:"column:action"`
	Changes        []byte    `gorm:"column:changes"`
	Redactions     []byte    `gorm:"column:redactions"`
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
	actorSessionID := "0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f"
	event := validEvent("all-fields")
	event.ActorID = &actorID
	event.ActorSessionID = &actorSessionID
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
	if stored.ActorSessionID == nil || *stored.ActorSessionID != actorSessionID {
		t.Errorf("stored actor_session_id = %v, want %q", stored.ActorSessionID, actorSessionID)
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

func TestListFiltersByEachEqualityField(t *testing.T) {
	db := databasetest.New(t)
	matchActorID := "actor-filter"
	otherActorID := "actor-filter-other"
	match := validEvent("filter-match")
	match.EventName = "simple_siem.test.filter_match"
	match.EventCategory = "FILTER"
	match.EventOutcome = "DENIED"
	match.ActorType = "USER"
	match.ActorID = &matchActorID
	match.RequestID = "request-filter"
	match.TraceID = "trace-filter"
	match.TargetType = "FILTER_TARGET"
	match.Action = "filter-action"

	other := validEvent("filter-other")
	other.EventName = "simple_siem.test.filter_other"
	other.EventCategory = "OTHER"
	other.EventOutcome = "SUCCESS"
	other.ActorType = "USER"
	other.ActorID = &otherActorID
	other.RequestID = "request-other"
	other.TraceID = "trace-other"
	other.TargetType = "OTHER_TARGET"
	other.Action = "other-action"

	for _, event := range []audit.Event{match, other} {
		if err := audit.Record(db, event); err != nil {
			t.Fatalf("Record %q: %v", event.TargetID, err)
		}
	}

	cases := []struct {
		name   string
		filter audit.Filter
	}{
		{"eventName", audit.Filter{EventName: match.EventName}},
		{"eventCategory", audit.Filter{EventCategory: match.EventCategory}},
		{"eventOutcome", audit.Filter{EventOutcome: match.EventOutcome}},
		{"actorId", audit.Filter{ActorID: matchActorID}},
		{"action", audit.Filter{Action: match.Action}},
		{"targetType", audit.Filter{TargetType: match.TargetType}},
		{"targetId", audit.Filter{TargetID: match.TargetID}},
		{"requestId", audit.Filter{RequestID: match.RequestID}},
		{"traceId", audit.Filter{TraceID: match.TraceID}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			events, total, err := audit.List(context.Background(), db, testCase.filter, 1, 50)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if total != 1 {
				t.Errorf("total = %d, want 1", total)
			}
			if len(events) != 1 || events[0].TargetID != match.TargetID {
				t.Errorf("events = %v, want only %q", targetIDs(events), match.TargetID)
			}
		})
	}
}

func TestListFiltersByActorAndTime(t *testing.T) {
	db := databasetest.New(t)
	actorA := "admin-a"
	actorB := "admin-b"
	firstDay := time.Date(2026, time.November, 12, 9, 0, 0, 0, time.UTC)
	secondDay := time.Date(2026, time.November, 13, 9, 0, 0, 0, time.UTC)
	secondDayLater := time.Date(2026, time.November, 13, 10, 0, 0, 0, time.UTC)

	before := validEvent("actor-time-before")
	before.ActorType = "USER"
	before.ActorID = &actorA
	wanted := validEvent("actor-time-wanted")
	wanted.ActorType = "USER"
	wanted.ActorID = &actorA
	otherActor := validEvent("actor-time-other")
	otherActor.ActorType = "USER"
	otherActor.ActorID = &actorB

	recordEventAt(t, db, before, firstDay)
	recordEventAt(t, db, wanted, secondDay)
	recordEventAt(t, db, otherActor, secondDayLater)

	createdAfter := secondDay
	events, total, err := audit.List(context.Background(), db, audit.Filter{
		ActorID:      actorA,
		CreatedAfter: &createdAfter,
	}, 1, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(events) != 1 || events[0].TargetID != wanted.TargetID {
		t.Errorf("events = %v, want only %q", targetIDs(events), wanted.TargetID)
	}
}

func TestListAppliesCreatedAtBounds(t *testing.T) {
	db := databasetest.New(t)
	targetType := "BOUNDS_TARGET"
	boundary := time.Date(2026, time.November, 13, 12, 0, 0, 0, time.UTC)

	recordEventAt(t, db, eventOfType(targetType, "bounds-before"), boundary.Add(-time.Second))
	recordEventAt(t, db, eventOfType(targetType, "bounds-at"), boundary)
	recordEventAt(t, db, eventOfType(targetType, "bounds-after"), boundary.Add(time.Second))

	createdAfter := boundary
	events, total, err := audit.List(context.Background(), db, audit.Filter{
		TargetType:   targetType,
		CreatedAfter: &createdAfter,
	}, 1, 50)
	if err != nil {
		t.Fatalf("List after: %v", err)
	}
	if total != 2 {
		t.Errorf("total after = %d, want 2", total)
	}
	if got, want := targetIDs(events), []string{"bounds-after", "bounds-at"}; !slices.Equal(got, want) {
		t.Errorf("events after = %v, want %v", got, want)
	}

	createdBefore := boundary
	events, total, err = audit.List(context.Background(), db, audit.Filter{
		TargetType:    targetType,
		CreatedBefore: &createdBefore,
	}, 1, 50)
	if err != nil {
		t.Fatalf("List before: %v", err)
	}
	if total != 1 {
		t.Errorf("total before = %d, want 1", total)
	}
	if got, want := targetIDs(events), []string{"bounds-before"}; !slices.Equal(got, want) {
		t.Errorf("events before = %v, want %v", got, want)
	}
}

func TestListOrdersNewestFirstWithIDTieBreak(t *testing.T) {
	db := databasetest.New(t)
	targetType := "ORDER_TARGET"
	newer := time.Date(2026, time.November, 13, 12, 0, 0, 0, time.UTC)
	older := newer.Add(-time.Hour)

	for _, targetID := range []string{"order-tie-a", "order-tie-b", "order-tie-c"} {
		recordEventAt(t, db, eventOfType(targetType, targetID), newer)
	}
	recordEventAt(t, db, eventOfType(targetType, "order-older"), older)
	recordEventAt(t, db, eventOfType(targetType, "order-oldest"), older.Add(-time.Hour))

	events, total, err := audit.List(context.Background(), db, audit.Filter{TargetType: targetType}, 1, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}

	tieIDs := []string{
		storedEventByTarget(t, db, "order-tie-a").ID,
		storedEventByTarget(t, db, "order-tie-b").ID,
		storedEventByTarget(t, db, "order-tie-c").ID,
	}
	slices.Sort(tieIDs)
	slices.Reverse(tieIDs)
	want := append(tieIDs,
		storedEventByTarget(t, db, "order-older").ID,
		storedEventByTarget(t, db, "order-oldest").ID,
	)
	got := eventIDs(events)
	if !slices.Equal(got, want) {
		t.Errorf("event ids = %v, want %v", got, want)
	}
}

func TestListPaginatesWithTotal(t *testing.T) {
	db := databasetest.New(t)
	targetType := "PAGINATION_TARGET"
	base := time.Date(2026, time.November, 13, 12, 0, 0, 0, time.UTC)
	for index := 1; index <= 5; index++ {
		targetID := fmt.Sprintf("page-%d", index)
		recordEventAt(t, db, eventOfType(targetType, targetID), base.Add(time.Duration(index)*time.Minute))
	}

	events, total, err := audit.List(context.Background(), db, audit.Filter{TargetType: targetType}, 2, 2)
	if err != nil {
		t.Fatalf("List page 2: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if got, want := targetIDs(events), []string{"page-3", "page-2"}; !slices.Equal(got, want) {
		t.Errorf("page 2 events = %v, want %v", got, want)
	}

	events, total, err = audit.List(context.Background(), db, audit.Filter{TargetType: targetType}, 3, 2)
	if err != nil {
		t.Fatalf("List page 3: %v", err)
	}
	if total != 5 {
		t.Errorf("page 3 total = %d, want 5", total)
	}
	if got, want := targetIDs(events), []string{"page-1"}; !slices.Equal(got, want) {
		t.Errorf("page 3 events = %v, want %v", got, want)
	}
}

func TestListReturnsEmptySliceAndZeroTotal(t *testing.T) {
	db := databasetest.New(t)

	events, total, err := audit.List(context.Background(), db, audit.Filter{TargetType: "NO_SUCH_TARGET"}, 1, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if events == nil {
		t.Error("List returned nil, want an empty slice")
	}
	if len(events) != 0 {
		t.Errorf("List returned %d events, want none", len(events))
	}
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
}

func TestListRejectsInvalidPagination(t *testing.T) {
	db := databasetest.New(t)
	cases := []struct {
		name     string
		page     int
		pageSize int
		wantErr  error
	}{
		{"page zero", 0, 50, audit.ErrInvalidPage},
		{"page negative", -1, 50, audit.ErrInvalidPage},
		{"page over the maximum", 100001, 50, audit.ErrInvalidPage},
		{"maximum integer page", 9223372036854775807, 50, audit.ErrInvalidPage},
		{"page size zero", 1, 0, nil},
		{"page size negative", 1, -1, nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			events, total, err := audit.List(context.Background(), db, audit.Filter{}, testCase.page, testCase.pageSize)
			if err == nil {
				t.Fatal("List accepted invalid pagination")
			}
			if testCase.wantErr != nil && !errors.Is(err, testCase.wantErr) {
				t.Errorf("List error = %v, want %v", err, testCase.wantErr)
			}
			if events != nil {
				t.Errorf("List returned %d events with invalid pagination, want none", len(events))
			}
			if total != 0 {
				t.Errorf("total = %d with invalid pagination, want 0", total)
			}
		})
	}
}

func TestListAndGetReadSourceIP(t *testing.T) {
	db := databasetest.New(t)
	addresses := map[string]net.IP{
		"ipv4": net.ParseIP("192.0.2.10"),
		"ipv6": net.ParseIP("2001:db8::10"),
	}
	for targetID, address := range addresses {
		event := eventOfType("SOURCE_IP_TARGET", targetID)
		event.SourceIP = address
		if err := audit.Record(db, event); err != nil {
			t.Fatalf("Record %q: %v", targetID, err)
		}
	}

	events, _, err := audit.List(context.Background(), db, audit.Filter{TargetType: "SOURCE_IP_TARGET"}, 1, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != len(addresses) {
		t.Fatalf("List returned %d events, want %d", len(events), len(addresses))
	}
	for _, event := range events {
		want, ok := addresses[event.TargetID]
		if !ok {
			t.Fatalf("List returned unexpected target %q", event.TargetID)
		}
		if !event.SourceIP.Equal(want) {
			t.Errorf("List source IP for %q = %v, want %v", event.TargetID, event.SourceIP, want)
		}
	}

	stored := storedEventByTarget(t, db, "ipv4")
	event, err := audit.Get(context.Background(), db, stored.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !event.SourceIP.Equal(addresses["ipv4"]) {
		t.Errorf("Get source IP = %v, want %v", event.SourceIP, addresses["ipv4"])
	}
}

func TestGetReturnsEvent(t *testing.T) {
	db := databasetest.New(t)
	actorID := "actor-get"
	sessionID := "0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f"
	event := validEvent("get-found")
	event.EventName = "simple_siem.test.get"
	event.ActorType = "USER"
	event.ActorID = &actorID
	event.ActorSessionID = &sessionID
	event.RequestID = "request-get"
	event.TraceID = "trace-get"
	event.Action = "get"
	event.Changes = map[string]any{"after": map[string]any{"password": "s3cret"}}

	if err := audit.Record(db, event); err != nil {
		t.Fatalf("Record: %v", err)
	}
	id := storedEventByTarget(t, db, event.TargetID).ID

	got, err := audit.Get(context.Background(), db, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	fields := []struct {
		name string
		got  string
		want string
	}{
		{"id", got.ID, id},
		{"event_name", got.EventName, event.EventName},
		{"event_category", got.EventCategory, event.EventCategory},
		{"event_outcome", got.EventOutcome, event.EventOutcome},
		{"actor_type", got.ActorType, event.ActorType},
		{"request_id", got.RequestID, event.RequestID},
		{"trace_id", got.TraceID, event.TraceID},
		{"target_type", got.TargetType, event.TargetType},
		{"target_id", got.TargetID, event.TargetID},
		{"action", got.Action, event.Action},
	}
	for _, field := range fields {
		if field.got != field.want {
			t.Errorf("Get %s = %q, want %q", field.name, field.got, field.want)
		}
	}
	if got.ActorID == nil || *got.ActorID != actorID {
		t.Errorf("Get actor_id = %v, want %q", got.ActorID, actorID)
	}
	if got.ActorSessionID == nil || *got.ActorSessionID != sessionID {
		t.Errorf("Get actor_session_id = %v, want %q", got.ActorSessionID, sessionID)
	}

	after, ok := got.Changes["after"].(map[string]any)
	if !ok {
		t.Fatalf("Get changes has no after object: %v", got.Changes)
	}
	if after["password"] != redactedValue {
		t.Errorf("Get changes.after.password = %v, want %s", after["password"], redactedValue)
	}
	if !slices.Contains(got.Redactions, "changes.after.password") {
		t.Errorf("Get redactions = %v, want changes.after.password", got.Redactions)
	}
}

func TestGetReturnsNotFound(t *testing.T) {
	db := databasetest.New(t)
	for _, id := range []string{
		"0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f",
		"not-a-uuid",
	} {
		t.Run(id, func(t *testing.T) {
			event, err := audit.Get(context.Background(), db, id)
			if !errors.Is(err, audit.ErrNotFound) {
				t.Fatalf("Get %q returned %v, want ErrNotFound", id, err)
			}
			if event.ID != "" {
				t.Errorf("Get %q returned event %q, want a zero event", id, event.ID)
			}
		})
	}
}

func TestMigrateAuditsAppliedMigration(t *testing.T) {
	db := databasetest.New(t)
	versions := appliedMigrationVersions(t, db)

	if got := countEvents(t, db, ""); got != int64(len(versions)) {
		t.Fatalf("fresh database has %d audit events, want exactly %d", got, len(versions))
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
	if got := countEvents(t, db, ""); got != int64(len(versions)) {
		t.Errorf("second Migrate changed the audit event count to %d, want %d", got, len(versions))
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
	versions := appliedMigrationVersions(t, db)

	for run := 1; run <= 2; run++ {
		if _, err := database.Migrate(context.Background(), db); err != nil {
			t.Fatalf("Migrate run %d: %v", run, err)
		}
	}
	for _, version := range versions {
		if got := countEvents(t, db, "target_type = ? AND target_id = ?", "DATABASE_MIGRATION", version); got != 1 {
			t.Errorf("migration %s has %d audit events after two Migrate runs, want 1", version, got)
		}
	}
	if got := countEvents(t, db, ""); got != int64(len(versions)) {
		t.Errorf("database has %d audit events after two Migrate runs, want %d", got, len(versions))
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

func eventOfType(targetType, targetID string) audit.Event {
	event := validEvent(targetID)
	event.TargetType = targetType
	return event
}

func recordEventAt(t *testing.T, db *gorm.DB, event audit.Event, createdAt time.Time) {
	t.Helper()
	if err := audit.Record(db, event); err != nil {
		t.Fatalf("Record %q: %v", event.TargetID, err)
	}
	if err := db.Exec("UPDATE audit_events SET created_at = ? WHERE target_id = ?", createdAt, event.TargetID).Error; err != nil {
		t.Fatalf("set created_at for %q: %v", event.TargetID, err)
	}
}

func targetIDs(events []audit.Event) []string {
	ids := make([]string, len(events))
	for index, event := range events {
		ids[index] = event.TargetID
	}
	return ids
}

func eventIDs(events []audit.Event) []string {
	ids := make([]string, len(events))
	for index, event := range events {
		ids[index] = event.ID
	}
	return ids
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
		       actor_type, actor_id, actor_session_id, request_id, trace_id, host(source_ip) AS source_ip,
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

func appliedMigrationVersions(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var versions []string
	err := db.Raw(`
		SELECT version_id::text
		FROM goose_db_version
		WHERE version_id > 0 AND is_applied
		ORDER BY version_id`).Scan(&versions).Error
	if err != nil {
		t.Fatalf("read applied migration versions: %v", err)
	}
	if len(versions) == 0 {
		t.Fatal("migrated database has no applied migration versions")
	}
	return versions
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
