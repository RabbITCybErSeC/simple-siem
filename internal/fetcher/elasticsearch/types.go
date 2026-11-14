package elasticsearch

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
)

const (
	// maxControlBody bounds point-in-time open and close responses.
	maxControlBody  = 1 << 20
	pitCloseTimeout = 5 * time.Second

	searchContextMissingException = "search_context_missing_exception"
)

// Fetcher streams fetch-time windows from one Elasticsearch instance.
type Fetcher struct {
	instance      config.FetcherInstance
	client        *http.Client
	authorization string             // precomputed header value; never logged
	onPIT         func(pitID string) // test hook: observes each point in time
}

// pitResponse is Elasticsearch's reply to opening or refreshing a point in
// time.
type pitResponse struct {
	ID string `json:"id"`
}

// searchResponse is one page of a search.
type searchResponse struct {
	PITID string `json:"pit_id"`
	searchCompleteness
	Hits struct {
		Hits []searchHit `json:"hits"`
	} `json:"hits"`
}

// searchCompleteness is the part of a search or point-in-time response that
// says whether every shard answered.
type searchCompleteness struct {
	TimedOut bool        `json:"timed_out"`
	Shards   shardCounts `json:"_shards"`
}

// shardCounts is the shard summary Elasticsearch reports with a response.
type shardCounts struct {
	Total  int `json:"total"`
	Failed int `json:"failed"`
}

// searchHit is one document in a page.
type searchHit struct {
	Index  string            `json:"_index"`
	ID     string            `json:"_id"`
	Source json.RawMessage   `json:"_source"`
	Sort   []json.RawMessage `json:"sort"`
}

// errorResponse is Elasticsearch's error object. Its reason text is never
// decoded: it can echo field values.
type errorResponse struct {
	Error struct {
		Type      string       `json:"type"`
		RootCause []errorCause `json:"root_cause"`
		CausedBy  *errorCause  `json:"caused_by"`
	} `json:"error"`
}

// errorCause is one link in Elasticsearch's nested error cause chain.
type errorCause struct {
	Type     string      `json:"type"`
	CausedBy *errorCause `json:"caused_by"`
}
