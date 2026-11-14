package outbox_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/outbox"
	"gorm.io/gorm"
)

type storedEvent struct {
	ID           string     `gorm:"column:id"`
	Type         string     `gorm:"column:type"`
	Version      int        `gorm:"column:version"`
	Actor        []byte     `gorm:"column:actor"`
	SubjectType  string     `gorm:"column:subject_type"`
	SubjectID    string     `gorm:"column:subject_id"`
	Payload      []byte     `gorm:"column:payload"`
	OccurredAt   time.Time  `gorm:"column:occurred_at"`
	DispatchedAt *time.Time `gorm:"column:dispatched_at"`
}

func TestRecordWritesEventFields(t *testing.T) {
	cases := []struct {
		name        string
		eventType   string
		subjectType string
	}{
		{"user on call", outbox.TypeUserOnCallChanged, "user"},
		{"case created", outbox.TypeCaseCreated, "case"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			db := databasetest.New(t)
			event := validEvent()
			event.Type = testCase.eventType

			err := db.Transaction(func(tx *gorm.DB) error {
				return outbox.Record(tx, event)
			})
			if err != nil {
				t.Fatalf("Record: %v", err)
			}

			rows := storedEvents(t, db)
			if len(rows) != 1 {
				t.Fatalf("outbox has %d rows, want exactly 1", len(rows))
			}
			stored := rows[0]
			if stored.ID == "" {
				t.Error("stored id is empty, want a database-generated UUID")
			}
			if stored.Type != event.Type {
				t.Errorf("stored type = %q, want %q", stored.Type, event.Type)
			}
			if stored.Version != event.Version {
				t.Errorf("stored version = %d, want %d", stored.Version, event.Version)
			}
			var actor outbox.Actor
			if err := json.Unmarshal(stored.Actor, &actor); err != nil {
				t.Fatalf("decode stored actor: %v", err)
			}
			if actor != event.Actor {
				t.Errorf("stored actor = %+v, want %+v", actor, event.Actor)
			}
			if stored.SubjectType != testCase.subjectType {
				t.Errorf("stored subject_type = %q, want %q", stored.SubjectType, testCase.subjectType)
			}
			if stored.SubjectID != event.SubjectID {
				t.Errorf("stored subject_id = %q, want %q", stored.SubjectID, event.SubjectID)
			}
			var payload map[string]any
			if err := json.Unmarshal(stored.Payload, &payload); err != nil {
				t.Fatalf("decode stored payload: %v", err)
			}
			if !reflect.DeepEqual(payload, event.Payload) {
				t.Errorf("stored payload = %s, want %v", stored.Payload, event.Payload)
			}
			if stored.OccurredAt.IsZero() {
				t.Error("stored occurred_at is zero, want the transaction clock")
			}
			if stored.DispatchedAt != nil {
				t.Errorf("stored dispatched_at = %v, want NULL", *stored.DispatchedAt)
			}
		})
	}
}

func TestRecordRollsBackWithTransaction(t *testing.T) {
	db := databasetest.New(t)
	sentinel := errors.New("transaction failed")

	err := db.Transaction(func(tx *gorm.DB) error {
		if err := outbox.Record(tx, validEvent()); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("transaction returned %v, want %v", err, sentinel)
	}
	if got := countEvents(t, db); got != 0 {
		t.Errorf("outbox kept %d rows after rollback, want 0", got)
	}
}

func TestRecordWritesNilPayloadAsEmptyObject(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent()
	event.Payload = nil

	err := db.Transaction(func(tx *gorm.DB) error {
		return outbox.Record(tx, event)
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	var payload string
	if err := db.Raw("SELECT payload::text FROM event_outbox").Scan(&payload).Error; err != nil {
		t.Fatalf("read stored payload: %v", err)
	}
	if payload != "{}" {
		t.Errorf("stored payload = %s, want {}", payload)
	}
}

func TestRecordRejectsInvalidEvents(t *testing.T) {
	db := databasetest.New(t)
	cases := []struct {
		name   string
		field  string
		detail string
		mutate func(*outbox.Event)
	}{
		{"unknown type", "type", "", func(event *outbox.Event) { event.Type = "case.deleted" }},
		{"empty type", "type", "", func(event *outbox.Event) { event.Type = "" }},
		{"version zero", "version", "", func(event *outbox.Event) { event.Version = 0 }},
		{"unknown actor type", "actor", "", func(event *outbox.Event) { event.Actor.Type = "admin" }},
		{"empty actor id", "actor", "", func(event *outbox.Event) { event.Actor.ID = "" }},
		{"oversized actor id", "actor", "", func(event *outbox.Event) { event.Actor.ID = strings.Repeat("a", 201) }},
		{"empty subject id", "subject", "", func(event *outbox.Event) { event.SubjectID = "" }},
		{"oversized subject id", "subject", "", func(event *outbox.Event) { event.SubjectID = strings.Repeat("s", 201) }},
		{"unencodable payload", "payload", "", func(event *outbox.Event) { event.Payload = map[string]any{"bad": make(chan int)} }},
		{"oversized payload", "payload", "8192", func(event *outbox.Event) {
			event.Payload = map[string]any{"notes": strings.Repeat("x", 9000)}
		}},
		{"sensitive key in array", "apiToken", "", func(event *outbox.Event) {
			event.Payload = map[string]any{"items": []any{map[string]any{"apiToken": "x"}}}
		}},
		{"sensitive key in map", "password", "", func(event *outbox.Event) {
			event.Payload = map[string]any{"outer": map[string]any{"password": "x"}}
		}},
		{"sensitive key in typed map", "payload.headers.Authorization", "", func(event *outbox.Event) {
			event.Payload = map[string]any{"headers": map[string]string{"Authorization": "x"}}
		}},
		{"sensitive key in typed array", "payload.items[0].apiToken", "", func(event *outbox.Event) {
			event.Payload = map[string]any{"items": []map[string]any{{"apiToken": "x"}}}
		}},
		{"href key is not a reference", "payload.passwordResetHref", "", func(event *outbox.Event) {
			event.Payload = map[string]any{"passwordResetHref": "https://example.com/r"}
		}},
		{"NUL in subject id", "subject", "", func(event *outbox.Event) { event.SubjectID = "a\x00b" }},
		{"invalid UTF-8 actor id", "actor", "", func(event *outbox.Event) { event.Actor.ID = "\xff" }},
		{"NUL in payload", "payload", "", func(event *outbox.Event) {
			event.Payload = map[string]any{"name": "a\x00b"}
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			event := validEvent()
			testCase.mutate(&event)

			err := db.Transaction(func(tx *gorm.DB) error {
				return outbox.Record(tx, event)
			})
			if !errors.Is(err, outbox.ErrInvalidEvent) {
				t.Fatalf("Record error = %v, want ErrInvalidEvent", err)
			}
			if !strings.Contains(err.Error(), testCase.field) {
				t.Errorf("Record error %q does not name %q", err, testCase.field)
			}
			if testCase.detail != "" && !strings.Contains(err.Error(), testCase.detail) {
				t.Errorf("Record error %q does not mention %q", err, testCase.detail)
			}
			if got := countEvents(t, db); got != 0 {
				t.Errorf("outbox has %d rows after a rejected event, want 0", got)
			}
		})
	}
}

func TestRecordAcceptsReferenceKeys(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent()
	event.Payload = map[string]any{"sessionRef": "abc"}

	err := db.Transaction(func(tx *gorm.DB) error {
		return outbox.Record(tx, event)
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := countEvents(t, db); got != 1 {
		t.Errorf("outbox has %d rows, want 1", got)
	}
}

func TestRecordNamesFirstSensitivePathDeterministically(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent()
	event.Payload = map[string]any{"password": "x", "apiToken": "y"}

	for attempt := 1; attempt <= 20; attempt++ {
		err := db.Transaction(func(tx *gorm.DB) error {
			return outbox.Record(tx, event)
		})
		if !errors.Is(err, outbox.ErrInvalidEvent) {
			t.Fatalf("attempt %d: Record error = %v, want ErrInvalidEvent", attempt, err)
		}
		if !strings.Contains(err.Error(), "payload.apiToken") {
			t.Fatalf("attempt %d: Record error %q does not name payload.apiToken", attempt, err)
		}
	}
	if got := countEvents(t, db); got != 0 {
		t.Errorf("outbox has %d rows after rejected events, want 0", got)
	}
}

func TestRecordAcceptsEscapedBackslashBeforeU0000(t *testing.T) {
	db := databasetest.New(t)
	event := validEvent()
	event.Payload = map[string]any{"text": "\\u0000"}

	err := db.Transaction(func(tx *gorm.DB) error {
		return outbox.Record(tx, event)
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := countEvents(t, db); got != 1 {
		t.Errorf("outbox has %d rows, want 1", got)
	}
}

func TestRecordStampsOccurredAtAtWriteTime(t *testing.T) {
	db := databasetest.New(t)

	err := db.Transaction(func(tx *gorm.DB) error {
		if err := outbox.Record(tx, validEvent()); err != nil {
			return err
		}
		if err := tx.Exec("SELECT pg_sleep(0.01)").Error; err != nil {
			return err
		}
		return outbox.Record(tx, validEvent())
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	rows := storedEvents(t, db)
	if len(rows) != 2 {
		t.Fatalf("outbox has %d rows, want 2", len(rows))
	}
	if !rows[1].OccurredAt.After(rows[0].OccurredAt) {
		t.Errorf("second occurred_at %v is not after the first %v", rows[1].OccurredAt, rows[0].OccurredAt)
	}
}

func validEvent() outbox.Event {
	return outbox.Event{
		Type:      outbox.TypeCaseCreated,
		Version:   1,
		Actor:     outbox.Actor{Type: outbox.ActorUser, ID: "actor-1"},
		SubjectID: "subject-1",
		Payload:   map[string]any{"title": "example"},
	}
}

func storedEvents(t *testing.T, db *gorm.DB) []storedEvent {
	t.Helper()
	var rows []storedEvent
	err := db.Raw(`
		SELECT id::text AS id, type, version, actor, subject_type, subject_id,
		       payload, occurred_at, dispatched_at
		FROM event_outbox
		ORDER BY occurred_at, id`).Scan(&rows).Error
	if err != nil {
		t.Fatalf("read outbox rows: %v", err)
	}
	return rows
}

func countEvents(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var count int64
	if err := db.Raw("SELECT count(*) FROM event_outbox").Scan(&count).Error; err != nil {
		t.Fatalf("count outbox rows: %v", err)
	}
	return count
}
