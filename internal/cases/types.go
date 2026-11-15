// Package cases opens a case for every alert, moves a case's event time when
// its alert gains evidence, assigns cases, and serves the case queue, detail,
// and timeline reads.
package cases

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
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

// Scope values of the case list's assignee filter.
const (
	ScopeMine       = "mine"
	ScopeUnassigned = "unassigned"
	ScopeAll        = "all"
)

// TimeField values name the column a case list's time range applies to.
const (
	TimeFieldLastEventAt  = "lastEventAt"
	TimeFieldFirstEventAt = "firstEventAt"
	TimeFieldCreatedAt    = "createdAt"
	TimeFieldClosedAt     = "closedAt"
)

// Sort values of the case list.
const (
	SortLastEventAtDesc = "lastEventAt:desc"
	SortCreatedAtAsc    = "createdAt:asc"
)

// Timeline kinds; an empty kind asks for both.
const (
	KindEvidence = "EVIDENCE"
	KindActivity = "ACTIVITY"
)

// Limits of the case reads. Group 3 validates query strings against them.
const (
	DefaultListLimit   = 50
	MaxListLimit       = 200
	MaxFilterAssignees = 50
	MaxQueryRunes      = 200
	MaxCursorBytes     = 512
	CountsCap          = 1000
)

const (
	// maxTitleRunes matches the cases.title CHECK.
	maxTitleRunes = 500

	// detectionEngineActorID is the system component that writes every
	// alert-driven outbox event.
	detectionEngineActorID = "detection-engine"

	// countsCacheTTL is how long a counts response is reused.
	countsCacheTTL = 15 * time.Second

	// maxCountsCacheEntries bounds the per-process counts cache.
	maxCountsCacheEntries = 1000

	// maxCursorIDBytes bounds the opaque timeline id a cursor may carry.
	maxCursorIDBytes = 200

	// maxHistogramBuckets is the bucket budget the auto interval targets.
	maxHistogramBuckets = 60

	// maxHistogramRangeDays bounds one histogram request.
	maxHistogramRangeDays = 1000

	// userStatusActive is the users.status value an assignee must hold.
	userStatusActive = "ACTIVE"
)

// Audit event names of the case activity timeline.
const (
	eventCaseCreated       = "simple_siem.case.created"
	eventCaseAlertAdded    = "simple_siem.case.alert_added"
	eventCaseAssigned      = "simple_siem.case.assigned"
	eventCaseUnassigned    = "simple_siem.case.unassigned"
	eventCaseStatusChanged = "simple_siem.case.status_changed"
)

var (
	// ErrInvalidSeverity is returned for a severity the cases table would reject.
	ErrInvalidSeverity = errors.New("invalid severity")

	// ErrCaseNotFound is returned when a case id or number names no case.
	ErrCaseNotFound = errors.New("case not found")

	// ErrVersionConflict is returned when the case changed after the caller
	// read it.
	ErrVersionConflict = errors.New("case was changed by someone else")

	// ErrCaseClosed is returned when an assign targets a closed case.
	ErrCaseClosed = errors.New("case is closed")
)

var (
	// ErrInvalidCursor is returned for a cursor that is malformed or was built
	// for other filters.
	ErrInvalidCursor = invalid("cursor", "invalid cursor")

	// ErrInvalidAssignee is returned for an assignee who is missing, disabled,
	// or cannot read cases.
	ErrInvalidAssignee = invalid("assigneeId", "assignee must be an active user who can read cases")
)

// ValidationError names the request parameter a rejected input belongs to.
type ValidationError struct {
	Parameter string
	Message   string
}

// Actor is the authenticated user behind a case write.
type Actor struct {
	UserID    string
	SessionID string
	RequestID string
	IP        net.IP
}

// ListFilter is the parsed filter of a case list. From and To are the resolved
// UTC times; FromExpression and ToExpression are the raw time expressions
// exactly as sent, empty when absent. The cursor hash and counts cache key
// cover the expressions, never the resolved instants, so a relative range
// pages and caches alike on every request.
type ListFilter struct {
	Statuses       []string
	Scope          string
	AssigneeIDs    []string
	Severities     []string
	DetectionIDs   []string
	Outcomes       []string
	Query          string
	FromExpression string
	ToExpression   string
	From           *time.Time
	To             *time.Time
	TimeField      string
	Sort           string
	Limit          *int
	Cursor         string
}

// cursorPayload is the JSON a keyset cursor carries.
type cursorPayload struct {
	SortValue string `json:"s"`
	ID        string `json:"i"`
	Filter    string `json:"f"`
}

// cursorKey is a decoded cursor with its sort value parsed.
type cursorKey struct {
	SortValue time.Time
	ID        string
}

// filterHashInput is the canonical encoding a list cursor's hash covers.
type filterHashInput struct {
	Statuses       []string `json:"statuses"`
	Scope          string   `json:"scope"`
	AssigneeIDs    []string `json:"assigneeIds"`
	Severities     []string `json:"severities"`
	DetectionIDs   []string `json:"detectionIds"`
	Outcomes       []string `json:"outcomes"`
	Query          string   `json:"query"`
	FromExpression string   `json:"fromExpression"`
	ToExpression   string   `json:"toExpression"`
	TimeField      string   `json:"timeField"`
	Sort           string   `json:"sort"`
	ActorUserID    string   `json:"actorUserID,omitempty"`
}

// CaseAssignee is the person a case is assigned to.
type CaseAssignee struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// CaseSummary is one item of the case list.
type CaseSummary struct {
	ID            string        `json:"id"`
	CaseNumber    int64         `json:"caseNumber"`
	Title         string        `json:"title"`
	Status        string        `json:"status"`
	Severity      string        `json:"severity"`
	Outcome       *string       `json:"outcome"`
	ClosureReason *string       `json:"closureReason"`
	Assignee      *CaseAssignee `json:"assignee"`
	FirstEventAt  time.Time     `json:"firstEventAt"`
	LastEventAt   time.Time     `json:"lastEventAt"`
	CreatedAt     time.Time     `json:"createdAt"`
	ClosedAt      *time.Time    `json:"closedAt"`
	Version       int           `json:"version"`
}

// LinkedCase is a recurrence neighbour of a case.
type LinkedCase struct {
	ID         string `json:"id"`
	CaseNumber int64  `json:"caseNumber"`
	Title      string `json:"title"`
	Status     string `json:"status"`
}

// MergedCase names the case a merged case was folded into.
type MergedCase struct {
	ID         string `json:"id"`
	CaseNumber int64  `json:"caseNumber"`
}

// CaseDetail is the case list item plus the fields of the detail route.
type CaseDetail struct {
	CaseSummary
	LastActivityAt time.Time     `json:"lastActivityAt"`
	ClosedBy       *CaseAssignee `json:"closedBy"`
	Conclusion     *string       `json:"conclusion"`
	AlertCount     int64         `json:"alertCount"`
	LinkedCases    []LinkedCase  `json:"linkedCases"`
	MergedInto     *MergedCase   `json:"mergedInto"`
}

// CasePage is one page of the case list.
type CasePage struct {
	Items      []CaseSummary `json:"items"`
	NextCursor *string       `json:"nextCursor"`
	Limit      int           `json:"limit"`
}

// summaryRow is the read-side row of a case list item.
type summaryRow struct {
	ID                  string     `gorm:"column:id"`
	CaseNumber          int64      `gorm:"column:case_number"`
	Title               string     `gorm:"column:title"`
	Status              string     `gorm:"column:status"`
	Severity            string     `gorm:"column:severity"`
	Outcome             *string    `gorm:"column:outcome"`
	ClosureReason       *string    `gorm:"column:closure_reason"`
	AssigneeUserID      *string    `gorm:"column:assignee_user_id"`
	AssigneeDisplayName *string    `gorm:"column:assignee_display_name"`
	FirstEventAt        time.Time  `gorm:"column:first_event_at"`
	LastEventAt         time.Time  `gorm:"column:last_event_at"`
	CreatedAt           time.Time  `gorm:"column:created_at"`
	ClosedAt            *time.Time `gorm:"column:closed_at"`
	Version             int        `gorm:"column:version"`
}

// detailRow is the read-side row of a case detail.
type detailRow struct {
	Summary             summaryRow `gorm:"embedded"`
	PreviousCaseID      *string    `gorm:"column:previous_case_id"`
	LastActivityAt      time.Time  `gorm:"column:last_activity_at"`
	Conclusion          *string    `gorm:"column:conclusion"`
	ClosedByID          *string    `gorm:"column:closed_by_id"`
	ClosedByDisplayName *string    `gorm:"column:closed_by_display_name"`
}

// AlertSummary is one alert of a case.
type AlertSummary struct {
	ID               string    `json:"id"`
	Title            string    `json:"title"`
	Severity         string    `json:"severity"`
	Status           string    `json:"status"`
	DetectionID      string    `json:"detectionId"`
	DetectionVersion string    `json:"detectionVersion"`
	EvidenceCount    int       `json:"evidenceCount"`
	OccurrenceCount  int       `json:"occurrenceCount"`
	FirstEventAt     time.Time `json:"firstEventAt"`
	LastEventAt      time.Time `json:"lastEventAt"`
	Outcome          *string   `json:"outcome"`
	ClosureReason    *string   `json:"closureReason"`
}

// AlertPage is one page of a case's alerts.
type AlertPage struct {
	Items      []AlertSummary `json:"items"`
	NextCursor *string        `json:"nextCursor"`
	Limit      int            `json:"limit"`
}

// alertSummaryRow is the read-side row of a case's alert.
type alertSummaryRow struct {
	ID               string    `gorm:"column:id"`
	Title            string    `gorm:"column:title"`
	Severity         string    `gorm:"column:severity"`
	Status           string    `gorm:"column:status"`
	DetectionID      string    `gorm:"column:detection_id"`
	DetectionVersion string    `gorm:"column:detection_version"`
	EvidenceCount    int       `gorm:"column:evidence_count"`
	OccurrenceCount  int       `gorm:"column:occurrence_count"`
	FirstEventAt     time.Time `gorm:"column:first_event_at"`
	LastEventAt      time.Time `gorm:"column:last_event_at"`
	Outcome          *string   `gorm:"column:outcome"`
	ClosureReason    *string   `gorm:"column:closure_reason"`
}

// TimelineEntry is one evidence or activity entry of a case's timeline. The
// fields of the other kind are omitted, so a client can switch on Kind.
type TimelineEntry struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	At       time.Time       `json:"at"`
	AlertID  string          `json:"alertId,omitempty"`
	SourceID string          `json:"sourceId,omitempty"`
	UDM      json.RawMessage `json:"udm,omitempty"`
	Actor    json.RawMessage `json:"actor,omitempty"`
	Action   string          `json:"action,omitempty"`
	Details  json.RawMessage `json:"details,omitempty"`
}

// TimelinePage is one page of a case's timeline.
type TimelinePage struct {
	Items      []TimelineEntry `json:"items"`
	NextCursor *string         `json:"nextCursor"`
	Limit      int             `json:"limit"`
}

// timelineRow is the common read-side row of both timeline kinds.
type timelineRow struct {
	ID               string    `gorm:"column:id"`
	Kind             string    `gorm:"column:kind"`
	At               time.Time `gorm:"column:at"`
	AlertID          *string   `gorm:"column:alert_id"`
	SourceID         *string   `gorm:"column:source_id"`
	UDM              []byte    `gorm:"column:udm"`
	ActorID          *string   `gorm:"column:actor_id"`
	ActorDisplayName *string   `gorm:"column:actor_display_name"`
	Action           *string   `gorm:"column:action"`
	Details          []byte    `gorm:"column:details"`
}

// StatusCounts is the status block of the counts response.
type StatusCounts struct {
	Open       int64 `json:"OPEN"`
	InProgress int64 `json:"IN_PROGRESS"`
	Closed     int64 `json:"CLOSED"`
	All        int64 `json:"ALL"`
}

// ScopeCounts is the scope block of the counts response.
type ScopeCounts struct {
	Mine       int64 `json:"mine"`
	Unassigned int64 `json:"unassigned"`
	All        int64 `json:"all"`
}

// Counts is the counts response; every value is capped at Cap.
type Counts struct {
	Status StatusCounts `json:"status"`
	Scope  ScopeCounts  `json:"scope"`
	Cap    int          `json:"cap"`
}

// countQuery is one capped count to run.
type countQuery struct {
	target *int64
	filter ListFilter
}

// SeverityCounts is the severity block of a histogram bucket.
type SeverityCounts struct {
	High   int64 `json:"HIGH"`
	Medium int64 `json:"MEDIUM"`
	Low    int64 `json:"LOW"`
}

// HistogramBucket is one interval of the case histogram.
type HistogramBucket struct {
	Start  time.Time      `json:"start"`
	Counts SeverityCounts `json:"counts"`
}

// Histogram is the histogram response.
type Histogram struct {
	Interval string            `json:"interval"`
	Buckets  []HistogramBucket `json:"buckets"`
}

// histogramInterval is one choice of the automatic histogram interval.
type histogramInterval struct {
	label    string
	duration time.Duration
	value    string
}

// histogramCountRow is one severity count of one bucket.
type histogramCountRow struct {
	BucketStart time.Time `gorm:"column:bucket_start"`
	Severity    string    `gorm:"column:severity"`
	Count       int64     `gorm:"column:count"`
}

// countsCacheEntry is one cached counts response and its expiry.
type countsCacheEntry struct {
	value     Counts
	expiresAt time.Time
}

// Service writes cases inside the caller's transaction and serves the case
// reads. It implements alerts.CaseHooks.
type Service struct {
	database        *gorm.DB
	publicURL       string
	maxCasesPerHour int
	now             func() time.Time

	countsLock  sync.Mutex
	countsCache map[string]countsCacheEntry
	// shortcut: per-process cache; shared cache or case_counts table if replicas disagree visibly (case-volume measurement).
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

// caseAlertRow is one case_alerts row. The database supplies CreatedAt.
type caseAlertRow struct {
	CaseID        string    `gorm:"column:case_id"`
	AlertID       string    `gorm:"column:alert_id"`
	Outcome       *string   `gorm:"column:outcome"`
	ClosureReason *string   `gorm:"column:closure_reason"`
	CreatedAt     time.Time `gorm:"column:created_at;default:now();autoCreateTime:false;->"`
}

func (caseRow) TableName() string {
	return "cases"
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

func (validation ValidationError) Error() string {
	return validation.Parameter + ": " + validation.Message
}

// NewService builds the case service. publicURL is the externally reachable
// base URL that outbox links point at.
func NewService(database *gorm.DB, publicURL string, maxCasesPerHour int) *Service {
	return &Service{
		database:        database,
		publicURL:       strings.TrimSuffix(publicURL, "/"),
		maxCasesPerHour: maxCasesPerHour,
		now:             time.Now,
		countsCache:     make(map[string]countsCacheEntry),
	}
}
