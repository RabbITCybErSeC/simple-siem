package outbox

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"gorm.io/gorm"
)

// outboxRow is the write-side row; the database supplies ID and OccurredAt.
type outboxRow struct {
	ID          string         `gorm:"column:id;default:uuidv7();->"`
	Type        string         `gorm:"column:type"`
	Version     int            `gorm:"column:version"`
	OccurredAt  time.Time      `gorm:"column:occurred_at;default:now();autoCreateTime:false;->"`
	Actor       Actor          `gorm:"column:actor;serializer:json"`
	SubjectType string         `gorm:"column:subject_type"`
	SubjectID   string         `gorm:"column:subject_id"`
	Payload     map[string]any `gorm:"column:payload;serializer:json"`
}

func (outboxRow) TableName() string {
	return "event_outbox"
}

// Record validates event and inserts it through the caller's transaction. It
// never opens or commits a transaction.
func Record(tx *gorm.DB, event Event) error {
	if err := validate(event); err != nil {
		return err
	}
	payload := event.Payload
	if payload == nil {
		payload = map[string]any{}
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

func validate(event Event) error {
	if _, ok := eventTypes[event.Type]; !ok {
		return fmt.Errorf("%w: type %q is not in the catalog", ErrInvalidEvent, event.Type)
	}
	if event.Version < 1 {
		return fmt.Errorf("%w: version must be at least 1", ErrInvalidEvent)
	}
	if event.Actor.Type != ActorUser && event.Actor.Type != ActorSystem {
		return fmt.Errorf("%w: actor type %q is not %q or %q", ErrInvalidEvent, event.Actor.Type, ActorUser, ActorSystem)
	}
	if len(event.Actor.ID) == 0 || len(event.Actor.ID) > maxIDBytes {
		return fmt.Errorf("%w: actor id must be 1 to %d bytes", ErrInvalidEvent, maxIDBytes)
	}
	if len(event.SubjectID) == 0 || len(event.SubjectID) > maxIDBytes {
		return fmt.Errorf("%w: subject id must be 1 to %d bytes", ErrInvalidEvent, maxIDBytes)
	}
	if key, ok := findSensitiveKey(event.Payload); ok {
		return fmt.Errorf("%w: payload key %q is sensitive", ErrInvalidEvent, key)
	}
	encoded, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("%w: payload cannot be encoded: %v", ErrInvalidEvent, err)
	}
	if len(encoded) > MaxPayloadBytes {
		return fmt.Errorf("%w: payload is %d bytes, over the %d-byte limit", ErrInvalidEvent, len(encoded), MaxPayloadBytes)
	}
	return nil
}

// findSensitiveKey returns the first payload key at any depth that names a
// secret.
func findSensitiveKey(value any) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, element := range typed {
			if audit.IsSensitiveKey(key) {
				return key, true
			}
			if key, ok := findSensitiveKey(element); ok {
				return key, true
			}
		}
	case []any:
		for _, element := range typed {
			if key, ok := findSensitiveKey(element); ok {
				return key, true
			}
		}
	}
	return "", false
}
