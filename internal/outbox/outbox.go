package outbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"gorm.io/gorm"
)

// Record validates event and inserts it through the caller's transaction. It
// never opens or commits a transaction.
func Record(tx *gorm.DB, event Event) error {
	payload, err := validate(event)
	if err != nil {
		return err
	}
	// The subject type is the event type's prefix, so a row can never name a
	// subject type other than the one its event type belongs to.
	subjectType, _, _ := strings.Cut(event.Type, ".")
	row := outboxRow{
		Type:        event.Type,
		Version:     event.Version,
		Actor:       event.Actor,
		SubjectType: subjectType,
		SubjectID:   event.SubjectID,
		Payload:     payload,
	}
	if err := tx.Create(&row).Error; err != nil {
		return fmt.Errorf("record outbox event: %w", err)
	}
	return nil
}

// validate returns the encoded payload for the row.
func validate(event Event) (json.RawMessage, error) {
	if _, ok := eventTypes[event.Type]; !ok {
		return nil, fmt.Errorf("%w: type %q is not in the catalog", ErrInvalidEvent, event.Type)
	}
	if event.Version < 1 {
		return nil, fmt.Errorf("%w: version must be at least 1", ErrInvalidEvent)
	}
	if event.Actor.Type != ActorUser && event.Actor.Type != ActorSystem {
		return nil, fmt.Errorf("%w: actor type %q is not %q or %q", ErrInvalidEvent, event.Actor.Type, ActorUser, ActorSystem)
	}
	if !validID(event.Actor.ID) {
		return nil, fmt.Errorf("%w: actor id must be 1 to %d bytes of valid UTF-8 without NUL", ErrInvalidEvent, maxIDBytes)
	}
	if !validID(event.SubjectID) {
		return nil, fmt.Errorf("%w: subject id must be 1 to %d bytes of valid UTF-8 without NUL", ErrInvalidEvent, maxIDBytes)
	}
	paths, err := audit.SensitivePaths(event.Payload, "payload")
	if err != nil {
		return nil, fmt.Errorf("%w: payload cannot be encoded: %v", ErrInvalidEvent, err)
	}
	if len(paths) > 0 {
		return nil, fmt.Errorf("%w: sensitive payload path %q", ErrInvalidEvent, paths[0])
	}
	payload := event.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload cannot be encoded: %v", ErrInvalidEvent, err)
	}
	if containsNULEscape(encoded) {
		return nil, fmt.Errorf("%w: payload contains a NUL character", ErrInvalidEvent)
	}
	if len(encoded) > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: payload is %d bytes, over the %d-byte limit", ErrInvalidEvent, len(encoded), MaxPayloadBytes)
	}
	return encoded, nil
}

func validID(id string) bool {
	return len(id) >= 1 && len(id) <= maxIDBytes && utf8.ValidString(id) && !strings.ContainsRune(id, 0)
}

// containsNULEscape reports whether encoded JSON holds a \u0000 escape, which
// jsonb refuses. A backslash written as \\ is literal, so the escape only
// counts when an even number of backslashes precede its u.
func containsNULEscape(encoded []byte) bool {
	for index := 0; index < len(encoded); index++ {
		if !bytes.HasPrefix(encoded[index:], []byte(`\u0000`)) {
			continue
		}
		backslashes := 0
		for previous := index - 1; previous >= 0 && encoded[previous] == '\\'; previous-- {
			backslashes++
		}
		if backslashes%2 == 0 {
			return true
		}
	}
	return false
}
