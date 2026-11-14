// Package pipeline runs one configured pipeline window by window: it fetches
// source records, converts them to UDM, and writes batches into a dataset,
// leaving one run record behind.
package pipeline

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/converter"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher"
	"gorm.io/gorm"
)

// Runner executes one pipeline at a time against the configured fetchers and
// the dataset store.
type Runner struct {
	Files    config.Files
	Database *gorm.DB
	Store    dataset.Store
	// NewFetcher builds a fetcher for an instance; tests pass a fake.
	NewFetcher func(instance config.FetcherInstance) (fetcher.Fetcher, error)
	Logger     *slog.Logger
}

// RunResult is one pipeline run as the CLI prints it.
type RunResult struct {
	RunID              string
	Status             RunStatus
	WindowStart        time.Time
	WindowEnd          time.Time
	RecordsRead        int
	RecordsWritten     int
	RecordsQuarantined int
	RecordsUnmapped    int
	RecordsLate        int
	Truncated          bool
	Warnings           []string
	Error              string
}

// RunStatus is the outcome stored on a run record.
type RunStatus string

const (
	StatusRunning  RunStatus = "RUNNING"
	StatusOK       RunStatus = "OK"
	StatusPartial  RunStatus = "PARTIAL"
	StatusFailed   RunStatus = "FAILED"
	StatusTimedOut RunStatus = "TIMED_OUT"
	StatusCanceled RunStatus = "CANCELED"
	StatusSkipped  RunStatus = "SKIPPED"
)

// runRow is one pipeline_runs row.
type runRow struct {
	ID                 string          `gorm:"column:id;default:uuidv7()"`
	PipelineID         string          `gorm:"column:pipeline_id"`
	Dataset            string          `gorm:"column:dataset"`
	Status             string          `gorm:"column:status"`
	WindowStart        *time.Time      `gorm:"column:window_start"`
	WindowEnd          *time.Time      `gorm:"column:window_end"`
	GapStart           *time.Time      `gorm:"column:gap_start"`
	GapEnd             *time.Time      `gorm:"column:gap_end"`
	RecordsRead        int             `gorm:"column:records_read"`
	RecordsWritten     int             `gorm:"column:records_written"`
	RecordsQuarantined int             `gorm:"column:records_quarantined"`
	RecordsUnmapped    int             `gorm:"column:records_unmapped"`
	RecordsLate        int             `gorm:"column:records_late_beyond_retention"`
	BatchesCommitted   int             `gorm:"column:batches_committed"`
	Truncated          bool            `gorm:"column:truncated"`
	RenderedQueryHash  *string         `gorm:"column:rendered_query_hash"`
	FetchErrors        []fetchErrorRow `gorm:"column:fetch_errors;serializer:json"`
	Warnings           []string        `gorm:"column:warnings;serializer:json"`
	Error              *string         `gorm:"column:error"`
	StartedAt          time.Time       `gorm:"column:started_at;default:now();autoCreateTime:false;->"`
	FinishedAt         *time.Time      `gorm:"column:finished_at"`
	Version            int             `gorm:"column:version;default:1"`
}

func (runRow) TableName() string {
	return "pipeline_runs"
}

// fetchErrorRow is one fetch_errors element: a sanitized code, message and
// retryable flag, never payload content.
type fetchErrorRow struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// runWindow is one half-open fetch-time window, with the backlog range that
// max_catch_up skipped, if any.
type runWindow struct {
	Start time.Time
	End   time.Time
	Gap   *fetchGap
}

// fetchGap is the part of a backlog beyond max_catch_up that a run skips.
type fetchGap struct {
	Start time.Time
	End   time.Time
}

// phaseOnePipeline is one pipeline resolved to the Phase 1 runner shape.
type phaseOnePipeline struct {
	Step      config.FetcherStep
	Processor config.Processor
	Output    config.Output
	Dataset   string
}

// runBatch is the converted part of a fetch that the next commit writes.
type runBatch struct {
	records       []dataset.Record
	quarantined   []dataset.QuarantinedRecord
	counts        converter.Counts
	lastFetchTime time.Time
}

// read is the number of source records the batch has processed, whatever
// their outcome.
func (batch runBatch) read() int {
	return batch.counts.Converted + batch.counts.Quarantined +
		batch.counts.Unmapped + batch.counts.LateBeyondRetention
}

// quarantineError stops a run whose batch is too broken to store.
type quarantineError struct {
	quarantined int
	total       int
}

func (failure *quarantineError) Error() string {
	return fmt.Sprintf("quarantine ratio exceeded: %d of %d", failure.quarantined, failure.total)
}
