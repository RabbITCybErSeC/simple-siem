// Package devdata generates reproducible development data for the SIEM.
package devdata

import (
	"math/rand/v2"
	"net/http"
	"time"
)

// Options selects one dataset. The same options always produce the same
// documents.
type Options struct {
	Seed        int64
	End         time.Time
	IndexPrefix string
	Background  int
}

// Document is one Elasticsearch document and the index it belongs to.
type Document struct {
	Index    string
	ID       string
	Scenario string
	Source   map[string]any
}

// Writer writes documents to Elasticsearch.
type Writer struct {
	URL      string
	Username string
	Password string
	Client   *http.Client
}

// bulkItem is one outcome in a bulk response.
type bulkItem struct {
	Status int        `json:"status"`
	Error  *bulkError `json:"error"`
}

type bulkError struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type bulkResponse struct {
	Errors bool                  `json:"errors"`
	Items  []map[string]bulkItem `json:"items"`
}

// generator carries the state of one deterministic dataset run.
type generator struct {
	options         Options
	end             time.Time
	scenarioRand    *rand.Rand
	backgroundRand  *rand.Rand
	sequence        int
	windowsRecordID int
	documents       []Document
}
