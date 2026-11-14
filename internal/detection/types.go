// Package detection evaluates windows of UDM records into alert proposals.
package detection

import (
	"context"
	"iter"
	"sync/atomic"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

// Detection holds the logic of one detection. It must be deterministic for a
// given window: no clock, no network, no global state, no goroutines.
type Detection interface {
	Evaluate(ctx context.Context, window Window) ([]Proposal, error)
}

// Window is one evaluation range, [Start, End) in event time, with read access
// to the datasets the manifest declares. The runner constructs it; detections
// only read Events.
type Window struct {
	Start    time.Time
	End      time.Time
	Revision int

	reader windowReader
	inputs map[string][]udm.EventType
	budget *rowBudget
}

// Proposal is "this should be an alert". The runner decides whether it becomes
// a new alert, merges into an open one, or is a no-op.
type Proposal struct {
	Subject  udm.Event
	Summary  string
	Details  map[string]string
	Severity Severity
	Evidence []Evidence
}

// Evidence is one dataset record that triggered a proposal.
type Evidence struct {
	SourceKey dataset.SourceKey
	EventTime time.Time
}

// Severity is the alert severity. Its zero value means the manifest default.
type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Registration is one compiled detection: its embedded manifest and its
// logic. The manifest version and the logic cannot drift apart because they
// ship together.
type Registration struct {
	Manifest []byte
	Logic    Detection
}

// RunStatus is the recorded outcome of one detection run.
type RunStatus string

const (
	RunStatusOK       RunStatus = "OK"
	RunStatusFailed   RunStatus = "FAILED"
	RunStatusTimedOut RunStatus = "TIMED_OUT"
)

// RunResult describes one run after it was evaluated and recorded.
type RunResult struct {
	RunID       string
	Status      RunStatus
	WindowStart time.Time
	WindowEnd   time.Time
	Revision    int
	RowsRead    int
	Proposals   int
	Error       string
}

// Identity is an alert proposal's coalescing key: the hash and the normalized
// value of every identity field in manifest order.
type Identity struct {
	Hash   string
	Values map[string]*string
}

// Fixture is one window of input records with the proposals it should produce.
type Fixture struct {
	Window   FixtureWindow
	Datasets map[string][]dataset.Record
	Expect   FixtureExpect

	reader windowReader
}

type FixtureWindow struct {
	Start time.Time
	End   time.Time
}

type FixtureExpect struct {
	Proposals []FixtureProposal `json:"proposals"`
}

// FixtureProposal lists only the identity paths, severity, and evidence count
// the fixture expects.
type FixtureProposal struct {
	Identity      map[string]*string `json:"identity"`
	Severity      Severity           `json:"severity"`
	EvidenceCount int                `json:"evidenceCount"`
}

// FixtureResult is the outcome of EvaluateFixture. Differences is empty when
// Passed is true.
type FixtureResult struct {
	Passed      bool
	Differences []string
	Proposals   []Proposal
}

// fixtureFile mirrors the fixture format on disk.
type fixtureFile struct {
	Window   fixtureWindow              `json:"window"`
	Datasets map[string][]fixtureRecord `json:"datasets"`
	Expect   FixtureExpect              `json:"expect"`
}

type fixtureWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// fixtureRecord is one input record. The event's metadata timestamp is also
// the record's event time, so the file never repeats it.
type fixtureRecord struct {
	SourceKey dataset.SourceKey `json:"sourceKey"`
	Event     udm.Event         `json:"event"`
}

// windowReader is the boundary between the runner and its two data sources:
// the dataset cache and the in-memory fixture reader.
type windowReader interface {
	ReadWindow(ctx context.Context, datasetName string, start, end time.Time, filter dataset.Filter) iter.Seq2[dataset.Record, error]
}

// rowBudget is the row allowance shared by every input of one run.
type rowBudget struct {
	maxRows int
	rows    atomic.Int64
}

func newRowBudget(maxRows int) *rowBudget {
	return &rowBudget{maxRows: maxRows}
}

func (budget *rowBudget) consume() bool {
	for {
		rows := budget.rows.Load()
		if rows >= int64(budget.maxRows) {
			return false
		}
		if budget.rows.CompareAndSwap(rows, rows+1) {
			return true
		}
	}
}

func (budget *rowBudget) count() int {
	return int(budget.rows.Load())
}

// evaluation is the outcome of one evaluation before persistence. err is set
// for every status other than RunStatusOK.
type evaluation struct {
	status    RunStatus
	proposals []Proposal
	err       error
}

// runRow is one detection_runs row.
type runRow struct {
	ID               string     `gorm:"column:id;default:uuidv7()"`
	DetectionID      string     `gorm:"column:detection_id"`
	DetectionVersion string     `gorm:"column:detection_version"`
	Status           string     `gorm:"column:status"`
	WindowStart      time.Time  `gorm:"column:window_start"`
	WindowEnd        time.Time  `gorm:"column:window_end"`
	Revision         int        `gorm:"column:revision"`
	RowsRead         int        `gorm:"column:rows_read"`
	Proposals        int        `gorm:"column:proposals"`
	Error            *string    `gorm:"column:error"`
	StartedAt        time.Time  `gorm:"column:started_at;autoCreateTime:false"`
	FinishedAt       *time.Time `gorm:"column:finished_at;autoUpdateTime:false;->"`
}

func (runRow) TableName() string {
	return "detection_runs"
}

// proposalRow is one detection_proposals row.
type proposalRow struct {
	ID             string             `gorm:"column:id;default:uuidv7()"`
	DetectionRunID string             `gorm:"column:detection_run_id"`
	IdentityHash   string             `gorm:"column:identity_hash"`
	Identity       map[string]*string `gorm:"column:identity;serializer:json"`
	Subject        udm.Event          `gorm:"column:subject;serializer:json"`
	Summary        string             `gorm:"column:summary"`
	Details        map[string]string  `gorm:"column:details;serializer:json"`
	Severity       string             `gorm:"column:severity"`
	Evidence       []proposalEvidence `gorm:"column:evidence;serializer:json"`
	CreatedAt      *time.Time         `gorm:"column:created_at;autoCreateTime:false;->"`
}

func (proposalRow) TableName() string {
	return "detection_proposals"
}

// proposalEvidence is one evidence jsonb element: the source key and event
// time of a record that triggered the proposal.
type proposalEvidence struct {
	SourceKey dataset.SourceKey `json:"sourceKey"`
	EventTime time.Time         `json:"eventTime"`
}
