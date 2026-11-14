package outbox

import "errors"

// Event is one domain event as a service writes it.
type Event struct {
	Type      string // one of the catalog constants
	Version   int    // payload version, 1 or higher
	Actor     Actor
	SubjectID string
	// A nil Payload is written as {}; maps and slices must be map[string]any
	// and []any so the key check sees them.
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
