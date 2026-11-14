package converter

import (
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

// Mapping is one parsed converter mapping file.
type Mapping struct {
	ID          string
	Version     int
	Description string
	Match       []Condition
	Constants   map[string]string
	Fields      []FieldMapping
	Additional  []AdditionalMapping
}

// Condition is one match condition. Exactly one of Equals and In is set.
type Condition struct {
	Field  string
	Equals *string
	In     []string
}

// FieldMapping maps source paths to one UDM field.
type FieldMapping struct {
	To         string
	From       []string
	Transforms []string
	Values     map[string]string
	Default    *string
}

// AdditionalMapping maps a source path to one additional key.
type AdditionalMapping struct {
	Key        string
	From       []string
	Transforms []string
}

// Outcome is the decision for one converted payload.
type Outcome string

const (
	OutcomeConverted           Outcome = "CONVERTED"
	OutcomeQuarantined         Outcome = "QUARANTINED"
	OutcomeUnmapped            Outcome = "UNMAPPED"
	OutcomeLateBeyondRetention Outcome = "LATE_BEYOND_RETENTION"
)

// Result is the conversion decision for one source record.
type Result struct {
	Outcome        Outcome               `json:"outcome"`
	Event          udm.Event             `json:"event,omitzero"`
	MappingID      string                `json:"mapping_id,omitempty"`
	MappingVersion int                   `json:"mapping_version,omitempty"`
	Errors         []udm.ValidationError `json:"errors,omitempty"`
}

// Counts is the per-outcome tally of a batch.
type Counts struct {
	Converted           int
	Quarantined         int
	Unmapped            int
	LateBeyondRetention int
}

// Converter converts raw source payloads with an ordered set of mappings.
type Converter struct {
	mappings  []compiledMapping
	retention time.Duration
}
