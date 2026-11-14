package detection

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

var (
	ErrUndeclaredInput   = errors.New("input dataset is not declared")
	ErrRowBudgetExceeded = errors.New("row budget exceeded")
)

// Events streams the records of one declared input in (event time, source
// key) order. Reading a dataset the manifest does not declare is an error.
func (window Window) Events(ctx context.Context, datasetName string) iter.Seq2[dataset.Record, error] {
	return func(yield func(dataset.Record, error) bool) {
		eventTypes, declared := window.inputs[datasetName]
		if !declared {
			yield(dataset.Record{}, fmt.Errorf("%w: %q", ErrUndeclaredInput, datasetName))
			return
		}

		filter := dataset.Filter{EventTypes: eventTypes}
		for record, err := range window.reader.ReadWindow(ctx, datasetName, window.Start, window.End, filter) {
			if err != nil {
				yield(dataset.Record{}, err)
				return
			}
			if err := ctx.Err(); err != nil {
				yield(dataset.Record{}, err)
				return
			}
			if !window.budget.consume() {
				yield(dataset.Record{}, fmt.Errorf("%w: more than %d rows", ErrRowBudgetExceeded, window.budget.maxRows))
				return
			}
			if !yield(record, nil) {
				return
			}
		}
	}
}

// EvidenceOf turns one dataset record into the evidence of a proposal.
func EvidenceOf(record dataset.Record) Evidence {
	return Evidence{SourceKey: record.Key, EventTime: record.EventTime}
}

// declaredInputs maps each manifest input dataset to the event types it
// accepts, which is the filter every window read pushes down.
func declaredInputs(manifest config.DetectionManifest) map[string][]udm.EventType {
	inputs := make(map[string][]udm.EventType, len(manifest.Inputs))
	for _, input := range manifest.Inputs {
		eventTypes := make([]udm.EventType, len(input.EventTypes))
		for index, eventType := range input.EventTypes {
			eventTypes[index] = udm.EventType(eventType)
		}
		inputs[input.Dataset] = eventTypes
	}
	return inputs
}

// fixtureReader is the in-memory windowReader for fixtures. It applies the
// same window bounds, event-type filter, and order as the dataset store.
type fixtureReader struct {
	records map[string][]dataset.Record
}

func newFixtureReader(datasets map[string][]dataset.Record) fixtureReader {
	records := make(map[string][]dataset.Record, len(datasets))
	for name, datasetRecords := range datasets {
		sorted := slices.Clone(datasetRecords)
		slices.SortStableFunc(sorted, func(first, second dataset.Record) int {
			if !first.EventTime.Equal(second.EventTime) {
				return first.EventTime.Compare(second.EventTime)
			}
			return bytes.Compare(first.Key.Hash(), second.Key.Hash())
		})
		records[name] = sorted
	}
	return fixtureReader{records: records}
}

func (reader fixtureReader) ReadWindow(ctx context.Context, datasetName string, start, end time.Time, filter dataset.Filter) iter.Seq2[dataset.Record, error] {
	return func(yield func(dataset.Record, error) bool) {
		for _, record := range reader.records[datasetName] {
			if err := ctx.Err(); err != nil {
				yield(dataset.Record{}, err)
				return
			}
			if record.EventTime.Before(start) || !record.EventTime.Before(end) {
				continue
			}
			if len(filter.EventTypes) > 0 && !slices.Contains(filter.EventTypes, record.Event.Metadata.EventType) {
				continue
			}
			if !yield(record, nil) {
				return
			}
		}
	}
}
