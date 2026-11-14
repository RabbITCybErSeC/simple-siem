// Package devdata generates reproducible development data for the SIEM.
package devdata

import "time"

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
