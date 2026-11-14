package detection

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

func testRecord(documentID string, eventTime time.Time, eventType udm.EventType) dataset.Record {
	return dataset.Record{
		Key: dataset.SourceKey{
			FetcherInstanceID: "fixture",
			Index:             "auth",
			DocumentID:        documentID,
		},
		EventTime: eventTime,
		Event: udm.Event{Metadata: udm.Metadata{
			EventTimestamp: eventTime,
			EventType:      eventType,
		}},
	}
}

func readAll(t *testing.T, window Window, datasetName string) ([]dataset.Record, []error) {
	t.Helper()
	var records []dataset.Record
	var problems []error
	for record, err := range window.Events(context.Background(), datasetName) {
		if err != nil {
			problems = append(problems, err)
			continue
		}
		records = append(records, record)
	}
	return records, problems
}

// functionReader lets a test control the reads Window.Events makes.
type functionReader func(ctx context.Context, datasetName string, start, end time.Time, filter dataset.Filter) iter.Seq2[dataset.Record, error]

func (reader functionReader) ReadWindow(ctx context.Context, datasetName string, start, end time.Time, filter dataset.Filter) iter.Seq2[dataset.Record, error] {
	return reader(ctx, datasetName, start, end, filter)
}

func TestWindowEventsFiltersOrdersAndBounds(t *testing.T) {
	start := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	records := []dataset.Record{
		testRecord("late", start.Add(3*time.Minute), udm.EventTypeUserLogin),
		testRecord("early", start.Add(time.Minute), udm.EventTypeUserLogin),
		testRecord("before-window", start.Add(-time.Minute), udm.EventTypeUserLogin),
		testRecord("other-type", start.Add(2*time.Minute), udm.EventTypeGenericEvent),
		testRecord("at-end", start.Add(15*time.Minute), udm.EventTypeUserLogin),
		testRecord("same-time-b", start.Add(2*time.Minute), udm.EventTypeUserLogin),
		testRecord("same-time-a", start.Add(2*time.Minute), udm.EventTypeUserLogin),
	}
	window := Window{
		Start:    start,
		End:      start.Add(15 * time.Minute),
		Revision: 1,
		reader:   newFixtureReader(map[string][]dataset.Record{"auth_events": records}),
		inputs:   map[string][]udm.EventType{"auth_events": {udm.EventTypeUserLogin}},
		budget:   newRowBudget(100),
	}

	got, problems := readAll(t, window, "auth_events")
	if len(problems) > 0 {
		t.Fatalf("Window.Events() errors = %v, want none", problems)
	}

	want := []dataset.Record{
		testRecord("early", start.Add(time.Minute), udm.EventTypeUserLogin),
	}
	// The two records at the same event time are ordered by source key hash.
	atSameTime := []dataset.Record{
		testRecord("same-time-a", start.Add(2*time.Minute), udm.EventTypeUserLogin),
		testRecord("same-time-b", start.Add(2*time.Minute), udm.EventTypeUserLogin),
	}
	if bytes.Compare(atSameTime[0].Key.Hash(), atSameTime[1].Key.Hash()) > 0 {
		atSameTime[0], atSameTime[1] = atSameTime[1], atSameTime[0]
	}
	want = append(want, atSameTime...)
	want = append(want, testRecord("late", start.Add(3*time.Minute), udm.EventTypeUserLogin))

	gotIDs := make([]string, len(got))
	for index, record := range got {
		gotIDs[index] = record.Key.DocumentID
	}
	wantIDs := make([]string, len(want))
	for index, record := range want {
		wantIDs[index] = record.Key.DocumentID
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("Window.Events() ids = %v, want %v", gotIDs, wantIDs)
	}
	if count := window.budget.count(); count != len(want) {
		t.Fatalf("row budget count = %d, want %d", count, len(want))
	}
}

func TestWindowEventsRejectsUndeclaredInput(t *testing.T) {
	window := Window{
		Start:  time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC),
		End:    time.Date(2026, 5, 11, 10, 15, 0, 0, time.UTC),
		reader: newFixtureReader(nil),
		inputs: map[string][]udm.EventType{"auth_events": {udm.EventTypeUserLogin}},
		budget: newRowBudget(100),
	}

	records, problems := readAll(t, window, "edr_events")
	if len(records) > 0 {
		t.Fatalf("Window.Events() records = %v, want none", records)
	}
	if len(problems) != 1 || !errors.Is(problems[0], ErrUndeclaredInput) {
		t.Fatalf("Window.Events() errors = %v, want one ErrUndeclaredInput", problems)
	}
	if message := problems[0].Error(); !strings.Contains(message, "edr_events") {
		t.Fatalf("Window.Events() error = %q, want it to name edr_events", message)
	}
}

func TestWindowEventsSharesRowBudgetAcrossInputs(t *testing.T) {
	start := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	window := Window{
		Start:    start,
		End:      start.Add(15 * time.Minute),
		Revision: 1,
		reader: newFixtureReader(map[string][]dataset.Record{
			"auth_events": {
				testRecord("auth-1", start.Add(time.Minute), udm.EventTypeUserLogin),
				testRecord("auth-2", start.Add(2*time.Minute), udm.EventTypeUserLogin),
				testRecord("auth-3", start.Add(3*time.Minute), udm.EventTypeUserLogin),
			},
			"edr_events": {
				testRecord("edr-1", start.Add(time.Minute), udm.EventTypeUserLogin),
				testRecord("edr-2", start.Add(2*time.Minute), udm.EventTypeUserLogin),
			},
		}),
		inputs: map[string][]udm.EventType{
			"auth_events": {udm.EventTypeUserLogin},
			"edr_events":  {udm.EventTypeUserLogin},
		},
		budget: newRowBudget(4),
	}

	authRecords, authProblems := readAll(t, window, "auth_events")
	if len(authProblems) > 0 || len(authRecords) != 3 {
		t.Fatalf("first input: %d records, errors %v; want 3 records and no errors", len(authRecords), authProblems)
	}

	edrRecords, edrProblems := readAll(t, window, "edr_events")
	if len(edrRecords) != 1 {
		t.Fatalf("second input records = %d, want 1 before the shared budget stops it", len(edrRecords))
	}
	if len(edrProblems) != 1 || !errors.Is(edrProblems[0], ErrRowBudgetExceeded) {
		t.Fatalf("second input errors = %v, want one ErrRowBudgetExceeded", edrProblems)
	}
	if count := window.budget.count(); count != 4 {
		t.Fatalf("row budget count = %d, want 4", count)
	}
}

func TestWindowEventsStopsOnCanceledContext(t *testing.T) {
	start := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	reader := functionReader(func(_ context.Context, _ string, _ time.Time, _ time.Time, _ dataset.Filter) iter.Seq2[dataset.Record, error] {
		return func(yield func(dataset.Record, error) bool) {
			yield(testRecord("1", start.Add(time.Minute), udm.EventTypeUserLogin), nil)
		}
	})
	window := Window{
		Start:  start,
		End:    start.Add(15 * time.Minute),
		reader: reader,
		inputs: map[string][]udm.EventType{"auth_events": {udm.EventTypeUserLogin}},
		budget: newRowBudget(100),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var records []dataset.Record
	var problems []error
	for record, err := range window.Events(ctx, "auth_events") {
		if err != nil {
			problems = append(problems, err)
			continue
		}
		records = append(records, record)
	}
	if len(records) != 0 {
		t.Fatalf("Window.Events() records = %d, want none from a canceled context", len(records))
	}
	if len(problems) != 1 || !errors.Is(problems[0], context.Canceled) {
		t.Fatalf("Window.Events() errors = %v, want one context.Canceled", problems)
	}
}

func TestWindowEventsPassesFilterAndWindowToReader(t *testing.T) {
	start := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	end := start.Add(15 * time.Minute)
	var gotDataset string
	var gotStart, gotEnd time.Time
	var gotFilter dataset.Filter
	reader := functionReader(func(_ context.Context, datasetName string, windowStart, windowEnd time.Time, filter dataset.Filter) iter.Seq2[dataset.Record, error] {
		gotDataset, gotStart, gotEnd, gotFilter = datasetName, windowStart, windowEnd, filter
		return func(yield func(dataset.Record, error) bool) {}
	})
	window := Window{
		Start:  start,
		End:    end,
		reader: reader,
		inputs: map[string][]udm.EventType{"auth_events": {udm.EventTypeUserLogin, udm.EventTypeUserLogout}},
		budget: newRowBudget(100),
	}

	readAll(t, window, "auth_events")

	if gotDataset != "auth_events" || !gotStart.Equal(start) || !gotEnd.Equal(end) {
		t.Fatalf("reader got dataset %q window [%s, %s), want auth_events [%s, %s)", gotDataset, gotStart, gotEnd, start, end)
	}
	want := dataset.Filter{EventTypes: []udm.EventType{udm.EventTypeUserLogin, udm.EventTypeUserLogout}}
	if !reflect.DeepEqual(gotFilter, want) {
		t.Fatalf("reader filter = %v, want %v", gotFilter, want)
	}
}

func TestWindowEventsYieldsReaderErrorAndStops(t *testing.T) {
	start := time.Date(2026, 5, 11, 10, 0, 0, 0, time.UTC)
	readError := errors.New("read failed")
	reader := functionReader(func(_ context.Context, _ string, _ time.Time, _ time.Time, _ dataset.Filter) iter.Seq2[dataset.Record, error] {
		return func(yield func(dataset.Record, error) bool) {
			if !yield(testRecord("1", start.Add(time.Minute), udm.EventTypeUserLogin), nil) {
				return
			}
			if !yield(dataset.Record{}, readError) {
				return
			}
			yield(testRecord("2", start.Add(2*time.Minute), udm.EventTypeUserLogin), nil)
		}
	})
	window := Window{
		Start:  start,
		End:    start.Add(15 * time.Minute),
		reader: reader,
		inputs: map[string][]udm.EventType{"auth_events": {udm.EventTypeUserLogin}},
		budget: newRowBudget(100),
	}

	records, problems := readAll(t, window, "auth_events")
	if len(records) != 1 {
		t.Fatalf("Window.Events() records = %d, want 1 before the reader error", len(records))
	}
	if len(problems) != 1 || !errors.Is(problems[0], readError) {
		t.Fatalf("Window.Events() errors = %v, want the reader error", problems)
	}
}

func TestEvidenceOf(t *testing.T) {
	record := testRecord("doc-1", time.Date(2026, 5, 11, 10, 1, 0, 0, time.UTC), udm.EventTypeUserLogin)

	evidence := EvidenceOf(record)

	want := Evidence{SourceKey: record.Key, EventTime: record.EventTime}
	if !reflect.DeepEqual(evidence, want) {
		t.Fatalf("EvidenceOf() = %+v, want %+v", evidence, want)
	}
}
