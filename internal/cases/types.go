// Package cases opens a case for every alert, moves a case's event time when
// its alert gains evidence, and assigns cases round-robin to on-call analysts.
package cases

import (
	"errors"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/alerts"
	"gorm.io/gorm"
)

// Case statuses; the transition table is owned by the close and assign flows.
const (
	StatusOpen       = "OPEN"
	StatusInProgress = "IN_PROGRESS"
	StatusClosed     = "CLOSED"
)

const (
	// maxTitleRunes matches the cases.title CHECK.
	maxTitleRunes = 500

	// detectionEngineActorID is the system component that writes every
	// alert-driven outbox event.
	detectionEngineActorID = "detection-engine"
)

// Audit event names of the case activity timeline.
const (
	eventCaseCreated       = "simple_siem.case.created"
	eventCaseAlertAdded    = "simple_siem.case.alert_added"
	eventCaseAssigned      = "simple_siem.case.assigned"
	eventCaseUnassigned    = "simple_siem.case.unassigned"
	eventCaseStatusChanged = "simple_siem.case.status_changed"
)

// ErrInvalidSeverity is returned for a severity the cases table would reject.
var ErrInvalidSeverity = errors.New("invalid severity")

// Service writes cases inside the caller's transaction. It implements
// alerts.CaseHooks.
type Service struct {
	database        *gorm.DB
	publicURL       string
	maxCasesPerHour int
	now             func() time.Time
}

// NewService builds the case service. publicURL is the externally reachable
// base URL that outbox links point at.
func NewService(database *gorm.DB, publicURL string, maxCasesPerHour int) *Service {
	return &Service{
		database:        database,
		publicURL:       strings.TrimSuffix(publicURL, "/"),
		maxCasesPerHour: maxCasesPerHour,
		now:             time.Now,
	}
}

// caseRow is one cases row. The database supplies ID, CaseNumber, the
// timestamps that default, and Version.
type caseRow struct {
	ID             string     `gorm:"column:id;default:uuidv7();->"`
	CaseNumber     int64      `gorm:"column:case_number;default:nextval('case_number_seq');->"`
	Title          string     `gorm:"column:title"`
	Status         string     `gorm:"column:status;default:OPEN"`
	Severity       string     `gorm:"column:severity"`
	DetectionID    string     `gorm:"column:detection_id"`
	AssigneeUserID *string    `gorm:"column:assignee_user_id"`
	Outcome        *string    `gorm:"column:outcome"`
	ClosureReason  *string    `gorm:"column:closure_reason"`
	Conclusion     *string    `gorm:"column:conclusion"`
	FirstEventAt   time.Time  `gorm:"column:first_event_at"`
	LastEventAt    time.Time  `gorm:"column:last_event_at"`
	LastActivityAt time.Time  `gorm:"column:last_activity_at;default:now();autoCreateTime:false;->"`
	PreviousCaseID *string    `gorm:"column:previous_case_id"`
	MergedInto     *string    `gorm:"column:merged_into"`
	ClosedAt       *time.Time `gorm:"column:closed_at"`
	ClosedBy       *string    `gorm:"column:closed_by"`
	CreatedAt      time.Time  `gorm:"column:created_at;default:now();autoCreateTime:false;->"`
	UpdatedAt      time.Time  `gorm:"column:updated_at;default:now();autoUpdateTime:false;->"`
	Version        int        `gorm:"column:version;default:1"`
}

func (caseRow) TableName() string {
	return "cases"
}

// caseAlertRow is one case_alerts row. The database supplies CreatedAt.
type caseAlertRow struct {
	CaseID        string    `gorm:"column:case_id"`
	AlertID       string    `gorm:"column:alert_id"`
	Outcome       *string   `gorm:"column:outcome"`
	ClosureReason *string   `gorm:"column:closure_reason"`
	CreatedAt     time.Time `gorm:"column:created_at;default:now();autoCreateTime:false;->"`
}

func (caseAlertRow) TableName() string {
	return "case_alerts"
}

// validSeverity reports whether severity is one the cases table accepts.
func validSeverity(severity alerts.Severity) bool {
	switch severity {
	case alerts.SeverityLow, alerts.SeverityMedium, alerts.SeverityHigh:
		return true
	default:
		return false
	}
}
