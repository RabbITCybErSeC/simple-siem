// Package dataset stores the pipeline output that detections read back as
// time windows.
package dataset

import (
	"context"
	"crypto/sha256"
	"errors"
	"iter"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
	"github.com/jackc/pgx/v5/pgtype"
	"gorm.io/gorm"
)

// SourceKey identifies one document in a fetcher input.
type SourceKey struct {
	FetcherInstanceID string `json:"fetcherInstanceId"`
	Index             string `json:"index"`
	DocumentID        string `json:"documentId"`
}

// Hash is SHA-256 over the three parts joined by 0x00, so no part can shift
// into another.
func (key SourceKey) Hash() []byte {
	joined := strings.Join([]string{key.FetcherInstanceID, key.Index, key.DocumentID}, "\x00")
	hash := sha256.Sum256([]byte(joined))
	return hash[:]
}

// Record is one converted source document.
type Record struct {
	Key       SourceKey
	EventTime time.Time
	Event     udm.Event
	RunID     string
}

// QuarantinedRecord is one source document that did not convert to a valid
// event. The store keeps at most 64 KB of the raw payload.
type QuarantinedRecord struct {
	Key            SourceKey
	Payload        []byte // raw source payload; the store caps it at 64 KB
	MappingID      string
	MappingVersion int
	Errors         []udm.ValidationError
}

// Batch is what one runner commit writes together.
type Batch struct {
	RunID          string
	Records        []Record
	Quarantined    []QuarantinedRecord
	FetchWatermark time.Time
}

// Dataset is the registration of one dataset and the pipeline that writes it.
type Dataset struct {
	Name            string
	PipelineID      string
	Retention       time.Duration
	AllowedLateness time.Duration
}

// Watermark is the dataset's progress. FetchWatermark is zero before the
// first batch.
type Watermark struct {
	FetchWatermark   time.Time
	DatasetWatermark time.Time
	LastRunID        string
	UpdatedAt        time.Time
}

// Filter narrows a window read; zero values do not filter.
type Filter struct{ EventTypes []udm.EventType }

// Store reads and writes dataset records. Writes take the caller's
// transaction so the runner commits records, quarantine, and run progress
// together.
type Store interface {
	RegisterDataset(ctx context.Context, transaction *gorm.DB, dataset Dataset) error
	// WriteBatch writes one batch in the caller's transaction. A caller writes
	// at most one batch per transaction: ensureDayPartitions takes its own
	// connection and the dataset advisory lock, so a second batch in the same
	// transaction would wait on a lock the caller already holds.
	WriteBatch(ctx context.Context, transaction *gorm.DB, datasetName string, batch Batch) error
	ReadWindow(ctx context.Context, datasetName string, start, end time.Time, filter Filter) iter.Seq2[Record, error]
	Watermark(ctx context.Context, datasetName string) (Watermark, error)
	Expire(ctx context.Context, transaction *gorm.DB, datasetName string, now time.Time) error
}

var (
	ErrUnknownDataset     = errors.New("unknown dataset")
	ErrDatasetOwned       = errors.New("dataset is owned by another pipeline")
	ErrInvalidDatasetName = errors.New("invalid dataset name")
	ErrInvalidRetention   = errors.New("invalid dataset retention interval")
	ErrOutsideRetention   = errors.New("event time is outside the dataset retention")
)

// datasetRow is one datasets row. Retention and lateness are PostgreSQL
// intervals; pgtype.Interval is their database/sql encoding.
type datasetRow struct {
	Name             string          `gorm:"column:name"`
	PipelineID       string          `gorm:"column:pipeline_id"`
	Retention        pgtype.Interval `gorm:"column:retention"`
	AllowedLateness  pgtype.Interval `gorm:"column:allowed_lateness"`
	FetchWatermark   *time.Time      `gorm:"column:fetch_watermark"`
	DatasetWatermark *time.Time      `gorm:"column:dataset_watermark"`
	LastRunID        *string         `gorm:"column:last_run_id"`
	CreatedAt        time.Time       `gorm:"column:created_at;default:now();autoCreateTime:false;->"`
	UpdatedAt        time.Time       `gorm:"column:updated_at;default:now();autoUpdateTime:false;->"`
	Version          int             `gorm:"column:version;default:1"`
}

func (datasetRow) TableName() string {
	return "datasets"
}

// datasetLoad is a datasets row plus the database clock read in the same
// statement. The embedded tag flattens the row; GORM skips unexported
// anonymous fields, so the row is a named exported field.
type datasetLoad struct {
	Dataset     datasetRow `gorm:"embedded"`
	DatabaseNow time.Time  `gorm:"column:database_now"`
}

// eventRow is one dataset_events row. source_key_hash is SourceKey.Hash, and
// the extracted columns are the filter pushdown columns.
type eventRow struct {
	Dataset           string    `gorm:"column:dataset"`
	EventTime         time.Time `gorm:"column:event_time"`
	SourceKeyHash     []byte    `gorm:"column:source_key_hash"`
	FetcherInstanceID string    `gorm:"column:fetcher_instance_id"`
	SourceIndex       string    `gorm:"column:source_index"`
	DocumentID        string    `gorm:"column:document_id"`
	EventType         string    `gorm:"column:event_type"`
	TargetUser        *string   `gorm:"column:target_user"`
	TargetHost        *string   `gorm:"column:target_host"`
	PrincipalIP       *string   `gorm:"column:principal_ip"`
	Event             udm.Event `gorm:"column:event;serializer:json"`
	PipelineRunID     string    `gorm:"column:pipeline_run_id"`
	WrittenAt         time.Time `gorm:"column:written_at"`
}

func (eventRow) TableName() string {
	return "dataset_events"
}

// quarantineRow is one dataset_quarantine row. The unique index on
// (dataset, source_key_hash) makes repeated failures of one document an
// upsert.
type quarantineRow struct {
	Dataset           string               `gorm:"column:dataset"`
	SourceKeyHash     []byte               `gorm:"column:source_key_hash"`
	FetcherInstanceID string               `gorm:"column:fetcher_instance_id"`
	SourceIndex       string               `gorm:"column:source_index"`
	DocumentID        string               `gorm:"column:document_id"`
	Payload           []byte               `gorm:"column:payload"`
	PayloadTruncated  bool                 `gorm:"column:payload_truncated"`
	MappingID         *string              `gorm:"column:mapping_id"`
	MappingVersion    *int                 `gorm:"column:mapping_version"`
	Errors            []validationErrorRow `gorm:"column:errors;serializer:json"`
	PipelineRunID     string               `gorm:"column:pipeline_run_id"`
}

func (quarantineRow) TableName() string {
	return "dataset_quarantine"
}

// validationErrorRow is the errors column shape: [{path, message}].
type validationErrorRow struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}
