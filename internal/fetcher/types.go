// Package fetcher defines the contract shared by all fetcher types: one call
// streams a fetch-time window to an emit callback and returns a final status.
package fetcher

import (
	"context"
	"encoding/json"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
)

// Fetcher streams one fetch-time window from a source. Implementations do not
// write to storage.
type Fetcher interface {
	// Fetch calls emit once per page, in fetch-time order, and returns the
	// final status after the last page, a limit, an error, or cancellation.
	// The returned error is non-nil exactly when the status is FAILED.
	Fetch(ctx context.Context, request FetchRequest, emit func(page []SourceRecord) error) (FetchStatus, error)
}

// FetchRequest is one window to fetch through one template.
type FetchRequest struct {
	PipelineRunID string
	Index         string // literal from the step or the instance default
	Template      config.QueryTemplate
	Values        map[string]string // template parameter values
	Window        Window            // [Start, End) on the fetch-time field
}

// Window is a half-open fetch-time interval.
type Window struct {
	Start time.Time
	End   time.Time
}

// SourceRecord is one document from the source, before conversion.
type SourceRecord struct {
	Key       dataset.SourceKey // fetcher instance id, concrete _index, _id
	FetchTime time.Time         // value of the fetch-time field (from the sort)
	FetchedAt time.Time
	Payload   json.RawMessage // _source, undecoded
}

// Status is the final outcome of a fetch.
type Status string

const (
	StatusOK      Status = "OK"
	StatusPartial Status = "PARTIAL"
	StatusFailed  Status = "FAILED"
)

// ErrorCode is a stable, machine-readable fetch error code.
type ErrorCode string

const (
	ErrorCodeResultLimitReached    ErrorCode = "RESULT_LIMIT_REACHED"
	ErrorCodeResultLimitNoProgress ErrorCode = "RESULT_LIMIT_NO_PROGRESS"
	ErrorCodeByteLimitReached      ErrorCode = "BYTE_LIMIT_REACHED"
	ErrorCodePITExpired            ErrorCode = "PIT_EXPIRED"
	ErrorCodeAuthFailed            ErrorCode = "AUTH_FAILED"
	ErrorCodeTLSFailed             ErrorCode = "TLS_FAILED"
	ErrorCodeTimeout               ErrorCode = "TIMEOUT"
	ErrorCodeCanceled              ErrorCode = "CANCELED"
	ErrorCodeBackendUnavailable    ErrorCode = "BACKEND_UNAVAILABLE"
	ErrorCodeQueryRejected         ErrorCode = "QUERY_REJECTED"
	ErrorCodeInvalidTemplate       ErrorCode = "INVALID_TEMPLATE"
	ErrorCodeIndexNotAllowed       ErrorCode = "INDEX_NOT_ALLOWED"
	ErrorCodeMalformedResponse     ErrorCode = "MALFORMED_RESPONSE"
	ErrorCodeEmitFailed            ErrorCode = "EMIT_FAILED"
)

// FetchError is one structured error in a FetchStatus.
type FetchError struct {
	Code      ErrorCode
	Message   string
	Retryable bool
}

// LastRecord is where a truncated fetch stopped.
type LastRecord struct {
	FetchTime time.Time
	Key       dataset.SourceKey
}

// FetchStatus is the final outcome of one fetch.
type FetchStatus struct {
	Status            Status
	RecordCount       int
	PageCount         int
	BytesRead         int64
	LastRecord        *LastRecord // nil when no record was emitted
	Truncated         bool
	RenderedQueryHash string
	Errors            []FetchError
}
