package outbox

import (
	"encoding/json"
	"errors"
	"time"
)

// Event is one domain event as a service writes it.
type Event struct {
	Type      string // one of the catalog constants
	Version   int    // payload version, 1 or higher
	Actor     Actor
	SubjectID string
	// A nil Payload is written as {}; values must be JSON-encodable, and keys
	// that name secrets are rejected at any depth.
	Payload map[string]any
}

// Actor is the identity that caused the event: a user, or a system component.
type Actor struct {
	Type string `json:"type"` // ActorUser or ActorSystem
	ID   string `json:"id"`   // user id, or a component name such as "detection-engine"
}

const (
	ActorUser   = "user"
	ActorSystem = "system"
)

const (
	TypeCaseCreated            = "case.created"
	TypeCaseAssigned           = "case.assigned"
	TypeCaseStatusChanged      = "case.status_changed"
	TypeCaseClosed             = "case.closed"
	TypeCaseEvidenceAdded      = "case.evidence_added"
	TypeDetectionStatusChanged = "detection.status_changed"
	TypePipelineGapRecorded    = "pipeline.gap_recorded"
	TypeUserOnCallChanged      = "user.on_call_changed"
)

const (
	// MaxPayloadBytes caps an encoded payload, so a caller that puts evidence
	// or notes in by mistake fails loudly instead of sending it over a webhook.
	MaxPayloadBytes = 8192
	maxIDBytes      = 200
)

// ErrInvalidEvent is returned when an event fails validation and is not
// written.
var ErrInvalidEvent = errors.New("invalid outbox event")

var eventTypes = map[string]struct{}{
	TypeCaseCreated:            {},
	TypeCaseAssigned:           {},
	TypeCaseStatusChanged:      {},
	TypeCaseClosed:             {},
	TypeCaseEvidenceAdded:      {},
	TypeDetectionStatusChanged: {},
	TypePipelineGapRecorded:    {},
	TypeUserOnCallChanged:      {},
}

// outboxRow is the write-side row; the database supplies ID and OccurredAt.
type outboxRow struct {
	ID          string          `gorm:"column:id;default:uuidv7();->"`
	Type        string          `gorm:"column:type"`
	Version     int             `gorm:"column:version"`
	OccurredAt  time.Time       `gorm:"column:occurred_at;default:clock_timestamp();autoCreateTime:false;->"`
	Actor       Actor           `gorm:"column:actor;serializer:json"`
	SubjectType string          `gorm:"column:subject_type"`
	SubjectID   string          `gorm:"column:subject_id"`
	Payload     json.RawMessage `gorm:"column:payload"`
}

func (outboxRow) TableName() string {
	return "event_outbox"
}
