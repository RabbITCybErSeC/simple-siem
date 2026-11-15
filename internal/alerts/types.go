// Package alerts turns detection proposals into alerts: evidence dedupe, identity coalescing, and the case hook.
package alerts

import (
	"context"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
	"gorm.io/gorm"
)

// Mode is the coalescing mode a detection declares in alerting.mode.
type Mode string

const (
	ModeMerge     Mode = "MERGE"
	ModeUnique    Mode = "UNIQUE"
	ModeAlwaysNew Mode = "ALWAYS_NEW"
)

// Severity is an alert's severity.
type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Policy is a detection's coalescing settings.
type Policy struct {
	Mode           Mode
	CoalesceWindow time.Duration
	MaxAlertSpan   time.Duration
}

// Evidence is one dataset record behind a proposal.
type Evidence struct {
	SourceKey dataset.SourceKey
	EventTime time.Time
}

// Proposal is one detection proposal with its identity already computed.
type Proposal struct {
	DetectionID           string
	DetectionVersion      string
	DetectionRunID        string
	IdentityHash          string
	IdentitySchemaVersion int
	Identity              map[string]*string
	Subject               udm.Event
	Summary               string
	Details               map[string]string
	Severity              Severity
	Evidence              []Evidence
}

// Action is what applying a proposal did.
type Action string

const (
	ActionNoop    Action = "NOOP"
	ActionMerged  Action = "MERGED"
	ActionCreated Action = "CREATED"
)

// Outcome is the result of applying one proposal.
type Outcome struct {
	Action           Action
	AlertID          string // empty for ActionNoop
	NewEvidence      int
	GuardrailTripped bool
}

// NewAlert is what the case layer receives for each created alert. Title is
// the proposal summary. PreviousAlertID is set when the alert follows a split
// or a closed alert of the same identity, and nil otherwise. Identity values
// and the subject are not included; read the alerts row by ID when they are
// needed.
type NewAlert struct {
	ID               string
	DetectionID      string
	DetectionVersion string
	Title            string
	Severity         Severity
	IdentityHash     string
	FirstEventAt     time.Time
	LastEventAt      time.Time
	PreviousAlertID  *string
}

// CaseOutcome is the case layer's answer to AlertCreated. GuardrailTripped
// asks the alerts service to switch the detection to SHADOW (reason
// case_rate_exceeded); the alert and its case still commit. Report it once per
// crossing; a repeat is harmless because only an ENABLED detection is
// switched.
type CaseOutcome struct {
	GuardrailTripped bool
}

// CaseHooks lets the case layer join the alert transaction. internal/cases
// implements it and imports this package, never the reverse. Both methods run
// inside the caller's transaction, after the alert, its evidence, its
// occurrence, and its audit event are written, so a case row can reference
// alerts(id). Implementations write only through tx, never commit or roll it
// back, never pass tx to another goroutine, and return errors instead of
// panicking. A returned error rolls back the alert with the transaction. ctx
// carries the run's deadline. Neither method is called for a proposal whose
// evidence was all seen before, so retries need no idempotency key, and calls
// for one detection identity are serialized.
type CaseHooks interface {
	// AlertCreated is called exactly once per created alert: new, split, or recurrence.
	AlertCreated(ctx context.Context, tx *gorm.DB, alert NewAlert) (CaseOutcome, error)
	// EvidenceAdded is called exactly once per merge into an open alert, with
	// added >= 1 new evidence rows and lastEventAt the alert's last event time
	// after the merge. It is not called for the old alert of a split.
	EvidenceAdded(ctx context.Context, tx *gorm.DB, alertID string, lastEventAt time.Time, added int) error
}

// Service applies proposals. A nil Hooks writes alerts without cases.
type Service struct {
	Hooks CaseHooks
}

// alertRow is one alerts row.
type alertRow struct {
	ID                    string             `gorm:"column:id;default:uuidv7()"`
	DetectionID           string             `gorm:"column:detection_id"`
	DetectionVersion      string             `gorm:"column:detection_version"`
	IdentityHash          string             `gorm:"column:identity_hash"`
	IdentitySchemaVersion int                `gorm:"column:identity_schema_version"`
	Identity              map[string]*string `gorm:"column:identity;serializer:json"`
	Subject               udm.Event          `gorm:"column:subject;serializer:json"`
	Summary               string             `gorm:"column:summary"`
	Details               map[string]string  `gorm:"column:details;serializer:json"`
	Severity              string             `gorm:"column:severity"`
	Status                string             `gorm:"column:status;default:OPEN"`
	Coalescing            bool               `gorm:"column:coalescing"`
	FirstEventAt          time.Time          `gorm:"column:first_event_at"`
	LastEventAt           time.Time          `gorm:"column:last_event_at"`
	OccurrenceCount       int                `gorm:"column:occurrence_count;default:1"`
	EvidenceCount         int                `gorm:"column:evidence_count"`
	PreviousAlertID       *string            `gorm:"column:previous_alert_id"`
	CreatedAt             *time.Time         `gorm:"column:created_at;autoCreateTime:false;->"`
	UpdatedAt             *time.Time         `gorm:"column:updated_at;autoUpdateTime:false;->"`
	Version               int                `gorm:"column:version;default:1"`
}

func (alertRow) TableName() string {
	return "alerts"
}

// evidenceRow is one alert_evidence row.
type evidenceRow struct {
	AlertID           string     `gorm:"column:alert_id"`
	SourceKeyHash     []byte     `gorm:"column:source_key_hash"`
	FetcherInstanceID string     `gorm:"column:fetcher_instance_id"`
	SourceIndex       string     `gorm:"column:source_index"`
	DocumentID        string     `gorm:"column:document_id"`
	EventTime         time.Time  `gorm:"column:event_time"`
	ObservedAt        *time.Time `gorm:"column:observed_at;autoCreateTime:false;->"`
}

func (evidenceRow) TableName() string {
	return "alert_evidence"
}

// occurrenceRow is one alert_occurrences row.
type occurrenceRow struct {
	ID               string     `gorm:"column:id;default:uuidv7()"`
	AlertID          string     `gorm:"column:alert_id"`
	DetectionRunID   string     `gorm:"column:detection_run_id"`
	NewEvidenceCount int        `gorm:"column:new_evidence_count"`
	FirstEventAt     time.Time  `gorm:"column:first_event_at"`
	LastEventAt      time.Time  `gorm:"column:last_event_at"`
	ObservedAt       *time.Time `gorm:"column:observed_at;autoCreateTime:false;->"`
}

func (occurrenceRow) TableName() string {
	return "alert_occurrences"
}

// runtimeRow is one detection_runtime row.
type runtimeRow struct {
	DetectionID string     `gorm:"column:detection_id"`
	Status      string     `gorm:"column:status"`
	Reason      *string    `gorm:"column:reason"`
	ChangedAt   *time.Time `gorm:"column:changed_at;autoCreateTime:false;->"`
	Version     int        `gorm:"column:version;default:1"`
}

func (runtimeRow) TableName() string {
	return "detection_runtime"
}
