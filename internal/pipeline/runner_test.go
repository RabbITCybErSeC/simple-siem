package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher"
	"gorm.io/gorm"
)

const validTestMapping = `id: auth
version: 1
match:
  - field: event.category
    equals: authentication
constants:
  metadata.event_type: GENERIC_EVENT
fields:
  - to: metadata.event_timestamp
    from: ["@timestamp"]
`

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// phaseOneFiles returns one valid Phase 1 pipeline with its mapping on disk.
func phaseOneFiles(t *testing.T) config.Files {
	t.Helper()
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "mappings", "auth.yaml"), validTestMapping)
	return config.Files{
		Directory: directory,
		Fetchers: map[string]config.FetcherInstance{
			"elastic-dev": {ID: "elastic-dev", Type: "elasticsearch"},
		},
		Pipelines: []config.Pipeline{{
			ID: "auth-events",
			Fetchers: []config.FetcherStep{{
				ID: "auth", Ref: "elastic-dev",
			}},
			Processors: []config.Processor{{
				ID: "to-udm", Type: "converter", From: "auth.records",
				Mappings: []string{"mappings/auth.yaml"}, Output: "udm.auth_events",
			}},
			Outputs: map[string]config.Output{
				"auth_events": {From: "udm.auth_events"},
			},
		}},
	}
}

func TestValidateFiles(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(t *testing.T, files *config.Files)
		wantErrors []string
	}{
		{name: "valid pipeline"},
		{
			name: "two fetcher steps",
			mutate: func(t *testing.T, files *config.Files) {
				files.Pipelines[0].Fetchers = append(files.Pipelines[0].Fetchers,
					config.FetcherStep{ID: "edr", Ref: "elastic-dev"})
			},
			wantErrors: []string{"auth-events", "Phase 1 runs one fetcher step, one converter, one output"},
		},
		{
			name: "two converters",
			mutate: func(t *testing.T, files *config.Files) {
				files.Pipelines[0].Processors = append(files.Pipelines[0].Processors,
					config.Processor{ID: "again", Type: "converter", From: "auth.records",
						Mappings: []string{"mappings/auth.yaml"}, Output: "udm.auth_events"})
			},
			wantErrors: []string{"auth-events", "Phase 1 runs one fetcher step, one converter, one output"},
		},
		{
			name: "converter reads another step",
			mutate: func(t *testing.T, files *config.Files) {
				files.Pipelines[0].Processors[0].From = "edr.records"
			},
			wantErrors: []string{"auth-events", "Phase 1 runs one fetcher step, one converter, one output"},
		},
		{
			name: "two outputs",
			mutate: func(t *testing.T, files *config.Files) {
				files.Pipelines[0].Outputs["other_events"] = config.Output{From: "udm.auth_events"}
			},
			wantErrors: []string{"auth-events", "Phase 1 runs one fetcher step, one converter, one output"},
		},
		{
			name: "output is not the converter output",
			mutate: func(t *testing.T, files *config.Files) {
				files.Pipelines[0].Outputs["auth_events"] = config.Output{From: "udm.other_events"}
			},
			wantErrors: []string{"auth-events", "Phase 1 runs one fetcher step, one converter, one output"},
		},
		{
			name: "unknown fetcher instance",
			mutate: func(t *testing.T, files *config.Files) {
				files.Pipelines[0].Fetchers[0].Ref = "missing"
			},
			wantErrors: []string{"auth-events", `unknown fetcher instance "missing"`},
		},
		{
			name: "unimplemented fetcher type",
			mutate: func(t *testing.T, files *config.Files) {
				instance := files.Fetchers["elastic-dev"]
				instance.Type = "splunk"
				files.Fetchers["elastic-dev"] = instance
			},
			wantErrors: []string{"auth-events", "auth", `fetcher type "splunk"`},
		},
		{
			name: "mapping outside the catalog",
			mutate: func(t *testing.T, files *config.Files) {
				writeTestFile(t, filepath.Join(files.Directory, "mappings", "bad.yaml"), `id: bad
version: 1
match:
  - field: event.category
    equals: authentication
constants:
  metadata.event_type: GENERIC_EVENT
fields:
  - to: target.user.email
    from: ["user.name"]
  - to: metadata.event_timestamp
    from: ["@timestamp"]
`)
				files.Pipelines[0].Processors[0].Mappings = []string{"mappings/bad.yaml"}
			},
			wantErrors: []string{"auth-events", "bad.yaml", "target.user.email"},
		},
		{
			name: "missing mapping file",
			mutate: func(t *testing.T, files *config.Files) {
				files.Pipelines[0].Processors[0].Mappings = []string{"mappings/missing.yaml"}
			},
			wantErrors: []string{"auth-events", "missing.yaml"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			files := phaseOneFiles(t)
			if test.mutate != nil {
				test.mutate(t, &files)
			}

			err := ValidateFiles(files)

			if len(test.wantErrors) == 0 {
				if err != nil {
					t.Fatalf("ValidateFiles() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateFiles() error = nil, want an error containing %q", test.wantErrors)
			}
			for _, wantError := range test.wantErrors {
				if !strings.Contains(err.Error(), wantError) {
					t.Errorf("ValidateFiles() error = %v, want it to contain %q", err, wantError)
				}
			}
		})
	}
}

func TestComputeWindow(t *testing.T) {
	at := func(hour, minute int) time.Time {
		return time.Date(2026, 11, 14, hour, minute, 0, 0, time.UTC)
	}
	schedule := config.Schedule{
		IngestDelay: config.Duration(time.Minute),
		Overlap:     config.Duration(time.Minute),
		MaxCatchUp:  config.Duration(6 * time.Hour),
	}

	tests := []struct {
		name            string
		now             time.Time
		fetchWatermark  time.Time
		schedule        config.Schedule
		retention       time.Duration
		lateness        time.Duration
		eventTimeSource bool
		wantStart       time.Time
		wantEnd         time.Time
		wantGap         *fetchGap
	}{
		{
			name:           "steady state",
			now:            at(10, 6),
			fetchWatermark: at(10, 0),
			schedule:       schedule,
			retention:      72 * time.Hour,
			wantStart:      at(9, 59),
			wantEnd:        at(10, 5),
		},
		{
			name:            "event-time source widens overlap to allowed lateness",
			now:             at(10, 6),
			fetchWatermark:  at(10, 0),
			schedule:        schedule,
			retention:       72 * time.Hour,
			lateness:        10 * time.Minute,
			eventTimeSource: true,
			wantStart:       at(9, 50),
			wantEnd:         at(10, 5),
		},
		{
			name:      "first run starts at max catch up",
			now:       at(10, 6),
			schedule:  schedule,
			retention: 72 * time.Hour,
			wantStart: at(4, 5),
			wantEnd:   at(10, 5),
		},
		{
			name:      "first run is bounded by retention",
			now:       at(10, 6),
			schedule:  schedule,
			retention: time.Hour,
			wantStart: at(9, 5),
			wantEnd:   at(10, 5),
		},
		{
			name:           "outage backlog records the skipped gap",
			now:            at(10, 6),
			fetchWatermark: at(0, 5),
			schedule:       schedule,
			retention:      72 * time.Hour,
			wantStart:      at(4, 5),
			wantEnd:        at(10, 5),
			wantGap:        &fetchGap{Start: at(0, 4), End: at(4, 5)},
		},
		{
			name:           "window exactly at max catch up has no gap",
			now:            at(10, 6),
			fetchWatermark: at(4, 6),
			schedule:       schedule,
			retention:      72 * time.Hour,
			wantStart:      at(4, 5),
			wantEnd:        at(10, 5),
		},
		{
			name:            "event-time lateness beyond max catch up is a gap",
			now:             at(10, 6),
			fetchWatermark:  at(10, 0),
			schedule:        config.Schedule{IngestDelay: config.Duration(time.Minute), Overlap: config.Duration(time.Minute), MaxCatchUp: config.Duration(5 * time.Minute)},
			retention:       72 * time.Hour,
			lateness:        10 * time.Minute,
			eventTimeSource: true,
			wantStart:       at(10, 0),
			wantEnd:         at(10, 5),
			wantGap:         &fetchGap{Start: at(9, 50), End: at(10, 0)},
		},
		{
			name:           "watermark at the window end rereads the overlap",
			now:            at(10, 6),
			fetchWatermark: at(10, 5),
			schedule:       schedule,
			retention:      72 * time.Hour,
			wantStart:      at(10, 4),
			wantEnd:        at(10, 5),
		},
		{
			name:           "watermark after the window end reads nothing",
			now:            at(10, 6),
			fetchWatermark: at(10, 30),
			schedule:       schedule,
			retention:      72 * time.Hour,
			wantStart:      at(10, 29),
			wantEnd:        at(10, 5),
		},
		{
			name:      "zero ingest delay ends at now",
			now:       at(10, 6),
			schedule:  config.Schedule{IngestDelay: 0, Overlap: config.Duration(time.Minute), MaxCatchUp: config.Duration(6 * time.Hour)},
			retention: 72 * time.Hour,
			wantStart: at(4, 6),
			wantEnd:   at(10, 6),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			window := computeWindow(test.now, dataset.Watermark{FetchWatermark: test.fetchWatermark},
				test.schedule, test.retention, test.lateness, test.eventTimeSource)

			if !window.Start.Equal(test.wantStart) {
				t.Errorf("Start = %s, want %s", window.Start, test.wantStart)
			}
			if !window.End.Equal(test.wantEnd) {
				t.Errorf("End = %s, want %s", window.End, test.wantEnd)
			}
			if test.wantGap == nil {
				if window.Gap != nil {
					t.Errorf("Gap = %+v, want none", *window.Gap)
				}
				return
			}
			if window.Gap == nil {
				t.Fatalf("Gap = none, want %+v", *test.wantGap)
			}
			if !window.Gap.Start.Equal(test.wantGap.Start) || !window.Gap.End.Equal(test.wantGap.End) {
				t.Errorf("Gap = {%s, %s}, want {%s, %s}",
					window.Gap.Start, window.Gap.End, test.wantGap.Start, test.wantGap.End)
			}
		})
	}
}

const (
	testPipelineID = "auth-events"
	testDataset    = "auth_events"
)

// scriptedFetcher is a fetcher whose pages and final status a test chooses.
type scriptedFetcher struct {
	pages         [][]fetcher.SourceRecord
	status        fetcher.FetchStatus
	fetchErr      error
	failAfterPage int
	block         bool
	started       chan struct{}
	calls         int
	request       fetcher.FetchRequest
}

func (fake *scriptedFetcher) Fetch(ctx context.Context, request fetcher.FetchRequest,
	emit func(page []fetcher.SourceRecord) error) (fetcher.FetchStatus, error) {
	fake.calls++
	fake.request = request
	if fake.started != nil {
		close(fake.started)
	}
	for index, page := range fake.pages {
		if err := emit(page); err != nil {
			return fetcher.FetchStatus{
				Status: fetcher.StatusFailed,
				Errors: []fetcher.FetchError{{Code: fetcher.ErrorCodeEmitFailed, Message: err.Error()}},
			}, err
		}
		if fake.failAfterPage > 0 && index+1 == fake.failAfterPage {
			return fetcher.FetchStatus{
				Status: fetcher.StatusFailed,
				Errors: []fetcher.FetchError{{Code: fetcher.ErrorCodeBackendUnavailable, Message: "backend went away"}},
			}, errors.New("backend went away")
		}
	}
	if fake.block {
		<-ctx.Done()
		return fetcher.FetchStatus{
			Status: fetcher.StatusFailed,
			Errors: []fetcher.FetchError{{Code: fetcher.ErrorCodeCanceled, Message: ctx.Err().Error()}},
		}, ctx.Err()
	}
	status := fake.status
	if status.Status == "" {
		status.Status = fetcher.StatusOK
	}
	return status, fake.fetchErr
}

// testFiles is one valid Phase 1 configuration whose files live in a temporary
// directory.
func testFiles(t *testing.T) config.Files {
	t.Helper()
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "mappings", "auth.yaml"), validTestMapping)
	retention := config.Duration(24 * time.Hour)
	lateness := config.Duration(10 * time.Minute)
	return config.Files{
		Directory: directory,
		System: config.System{
			Version: "0.1",
			Stores: config.Stores{DatasetCache: config.DatasetCacheStore{
				Type:                   "postgres",
				DefaultRetention:       retention,
				DefaultAllowedLateness: lateness,
			}},
			Runner: config.RunnerSettings{BatchSize: 5000, MaxQuarantineRatio: 0.10},
		},
		Fetchers: map[string]config.FetcherInstance{
			"elastic-dev": {
				ID:   "elastic-dev",
				Type: "elasticsearch",
				Defaults: config.FetcherDefaults{
					TimeField:      "@timestamp",
					FetchTimeField: "event.ingested",
				},
			},
		},
		QueryTemplates: map[string]config.QueryTemplate{
			"auth-events": {
				ID:          "auth-events",
				FetcherType: "elasticsearch",
				Version:     "0.1.0",
				Parameters:  map[string]config.TemplateParameter{},
				RawQuery:    map[string]any{"query": map[string]any{"match_all": map[string]any{}}},
			},
		},
		Pipelines: []config.Pipeline{{
			ID:      testPipelineID,
			Version: "0.1.0",
			Schedule: config.Schedule{
				Timeout:     config.Duration(10 * time.Second),
				IngestDelay: config.Duration(time.Minute),
				Overlap:     config.Duration(time.Minute),
				MaxCatchUp:  config.Duration(6 * time.Hour),
			},
			Fetchers: []config.FetcherStep{{
				ID:  "auth",
				Ref: "elastic-dev",
				Inputs: map[string]config.Input{
					"index":          {Literal: "auth-*"},
					"query_template": {Literal: "auth-events"},
				},
			}},
			Processors: []config.Processor{{
				ID:       "to-udm",
				Type:     "converter",
				From:     "auth.records",
				Mappings: []string{"mappings/auth.yaml"},
				Output:   "udm.auth_events",
			}},
			Outputs: map[string]config.Output{
				testDataset: {
					From:            "udm.auth_events",
					Retention:       &retention,
					AllowedLateness: &lateness,
				},
			},
		}},
	}
}

func newRunner(t *testing.T, fake fetcher.Fetcher, configure ...func(*config.Files)) (*Runner, *gorm.DB) {
	t.Helper()
	database := databasetest.New(t)
	files := testFiles(t)
	for _, change := range configure {
		change(&files)
	}
	runner := &Runner{
		Files:    files,
		Database: database,
		Store:    dataset.NewPostgresStore(database),
		NewFetcher: func(config.FetcherInstance) (fetcher.Fetcher, error) {
			return fake, nil
		},
		Logger: slog.New(slog.DiscardHandler),
	}
	return runner, database
}

func loginPayload(t *testing.T, eventTime time.Time) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"event":      map[string]any{"category": "authentication"},
		"@timestamp": eventTime.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return payload
}

func unmappedPayload(t *testing.T) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"event":      map[string]any{"category": "network"},
		"@timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return payload
}

func sourceRecord(documentID string, fetchTime time.Time, payload json.RawMessage) fetcher.SourceRecord {
	return fetcher.SourceRecord{
		Key:       dataset.SourceKey{FetcherInstanceID: "elastic-dev", Index: "auth-1", DocumentID: documentID},
		FetchTime: fetchTime,
		Payload:   payload,
	}
}

func storedCounts(t *testing.T, database *gorm.DB) (events, quarantine int) {
	t.Helper()
	if err := database.Raw("SELECT count(*) FROM dataset_events").Scan(&events).Error; err != nil {
		t.Fatalf("count dataset events: %v", err)
	}
	if err := database.Raw("SELECT count(*) FROM dataset_quarantine").Scan(&quarantine).Error; err != nil {
		t.Fatalf("count quarantine: %v", err)
	}
	return events, quarantine
}

func loadRunRow(t *testing.T, database *gorm.DB, runID string) runRow {
	t.Helper()
	var row runRow
	if err := database.Where("id = ?", runID).Take(&row).Error; err != nil {
		t.Fatalf("load run row: %v", err)
	}
	return row
}

func datasetFetchWatermark(t *testing.T, database *gorm.DB) time.Time {
	t.Helper()
	watermark, err := dataset.NewPostgresStore(database).Watermark(context.Background(), testDataset)
	if err != nil {
		t.Fatalf("read watermark: %v", err)
	}
	return watermark.FetchWatermark
}

func countRunRows(t *testing.T, database *gorm.DB) int {
	t.Helper()
	var count int
	if err := database.Raw("SELECT count(*) FROM pipeline_runs").Scan(&count).Error; err != nil {
		t.Fatalf("count run rows: %v", err)
	}
	return count
}

func registerDatasetWithWatermark(t *testing.T, database *gorm.DB, watermark time.Time) {
	t.Helper()
	ctx := context.Background()
	err := database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		return dataset.NewPostgresStore(database).RegisterDataset(ctx, transaction, dataset.Dataset{
			Name:            testDataset,
			PipelineID:      testPipelineID,
			Retention:       24 * time.Hour,
			AllowedLateness: 10 * time.Minute,
		})
	})
	if err != nil {
		t.Fatalf("register dataset: %v", err)
	}
	if err := database.Exec("UPDATE datasets SET fetch_watermark = ? WHERE name = ?", watermark, testDataset).Error; err != nil {
		t.Fatalf("set watermark: %v", err)
	}
}

func TestRunBatches(t *testing.T) {
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	eventTime := time.Now().UTC().Add(-5 * time.Minute)
	records := make([]fetcher.SourceRecord, 5)
	for index := range records {
		records[index] = sourceRecord(fmt.Sprintf("doc-%d", index+1), base.Add(time.Duration(index)*time.Minute),
			loginPayload(t, eventTime))
	}
	pages := [][]fetcher.SourceRecord{records[0:2], records[2:4], records[4:5]}

	tests := []struct {
		name          string
		status        fetcher.FetchStatus
		wantStatus    RunStatus
		wantWatermark time.Time
		wantTruncated bool
		wantBatches   int
	}{
		{
			name:          "OK advances to the window end",
			status:        fetcher.FetchStatus{Status: fetcher.StatusOK},
			wantStatus:    StatusOK,
			wantWatermark: time.Time{}, // filled from the fetch request below
			wantBatches:   3,
		},
		{
			name:          "PARTIAL advances to the last record",
			status:        fetcher.FetchStatus{Status: fetcher.StatusPartial, Truncated: true},
			wantStatus:    StatusPartial,
			wantWatermark: records[4].FetchTime,
			wantTruncated: true,
			wantBatches:   3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &scriptedFetcher{pages: pages, status: test.status}
			runner, database := newRunner(t, fake, func(files *config.Files) {
				files.System.Runner.BatchSize = 2
			})

			result, err := runner.Run(context.Background(), testPipelineID)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if result.Status != test.wantStatus {
				t.Errorf("Status = %q, want %q; error = %q", result.Status, test.wantStatus, result.Error)
			}
			if result.RecordsRead != 5 || result.RecordsWritten != 5 {
				t.Errorf("records read/written = %d/%d, want 5/5", result.RecordsRead, result.RecordsWritten)
			}
			if result.Truncated != test.wantTruncated {
				t.Errorf("Truncated = %v, want %v", result.Truncated, test.wantTruncated)
			}
			if events, quarantine := storedCounts(t, database); events != 5 || quarantine != 0 {
				t.Errorf("stored events/quarantine = %d/%d, want 5/0", events, quarantine)
			}
			row := loadRunRow(t, database, result.RunID)
			if row.BatchesCommitted != test.wantBatches {
				t.Errorf("BatchesCommitted = %d, want %d", row.BatchesCommitted, test.wantBatches)
			}
			if row.FinishedAt == nil {
				t.Error("FinishedAt = nil, want a finish time")
			}
			wantWatermark := test.wantWatermark
			if wantWatermark.IsZero() {
				wantWatermark = fake.request.Window.End
			}
			if got := datasetFetchWatermark(t, database); !got.Equal(wantWatermark) {
				t.Errorf("fetch watermark = %s, want %s", got, wantWatermark)
			}
		})
	}
}

func TestRunFailedKeepsLastCommittedBatch(t *testing.T) {
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	eventTime := time.Now().UTC().Add(-5 * time.Minute)
	records := make([]fetcher.SourceRecord, 15)
	for index := range records {
		records[index] = sourceRecord(fmt.Sprintf("doc-%d", index+1), base.Add(time.Duration(index)*time.Minute),
			loginPayload(t, eventTime))
	}
	pages := [][]fetcher.SourceRecord{records[0:5], records[5:10], records[10:15]}
	fake := &scriptedFetcher{pages: pages, failAfterPage: 2}
	runner, database := newRunner(t, fake, func(files *config.Files) {
		files.System.Runner.BatchSize = 5
	})

	result, err := runner.Run(context.Background(), testPipelineID)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusFailed {
		t.Errorf("Status = %q, want FAILED", result.Status)
	}
	if events, _ := storedCounts(t, database); events != 10 {
		t.Errorf("stored events = %d, want 10", events)
	}
	if got, want := datasetFetchWatermark(t, database), records[9].FetchTime; !got.Equal(want) {
		t.Errorf("fetch watermark = %s, want the tenth record's %s", got, want)
	}
	row := loadRunRow(t, database, result.RunID)
	if row.BatchesCommitted != 2 || row.RecordsWritten != 10 {
		t.Errorf("BatchesCommitted/RecordsWritten = %d/%d, want 2/10", row.BatchesCommitted, row.RecordsWritten)
	}
	if len(row.FetchErrors) == 0 {
		t.Error("FetchErrors = [], want the backend failure recorded")
	}
}

func TestRunFailsClosed(t *testing.T) {
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	eventTime := time.Now().UTC().Add(-5 * time.Minute)
	firstPage := make([]fetcher.SourceRecord, 200)
	for index := range firstPage {
		firstPage[index] = sourceRecord(fmt.Sprintf("good-%d", index), base.Add(time.Duration(index)*time.Second),
			loginPayload(t, eventTime))
	}
	secondPage := make([]fetcher.SourceRecord, 0, 200)
	for index := 0; index < 150; index++ {
		secondPage = append(secondPage, sourceRecord(fmt.Sprintf("mixed-good-%d", index),
			base.Add(time.Duration(200+index)*time.Second), loginPayload(t, eventTime)))
	}
	for index := 0; index < 50; index++ {
		secondPage = append(secondPage, sourceRecord(fmt.Sprintf("mixed-bad-%d", index),
			base.Add(time.Duration(350+index)*time.Second), json.RawMessage("not json")))
	}
	fake := &scriptedFetcher{pages: [][]fetcher.SourceRecord{firstPage, secondPage}}
	runner, database := newRunner(t, fake, func(files *config.Files) {
		files.System.Runner.BatchSize = 200
	})

	result, err := runner.Run(context.Background(), testPipelineID)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusFailed {
		t.Errorf("Status = %q, want FAILED", result.Status)
	}
	if want := "quarantine ratio exceeded: 50 of 200"; result.Error != want {
		t.Errorf("Error = %q, want %q", result.Error, want)
	}
	if events, quarantine := storedCounts(t, database); events != 200 || quarantine != 0 {
		t.Errorf("stored events/quarantine = %d/%d, want the 200 from the first batch", events, quarantine)
	}
	if got, want := datasetFetchWatermark(t, database), firstPage[199].FetchTime; !got.Equal(want) {
		t.Errorf("fetch watermark = %s, want the last committed record's %s", got, want)
	}
	row := loadRunRow(t, database, result.RunID)
	if row.Status != string(StatusFailed) {
		t.Errorf("row status = %q, want FAILED", row.Status)
	}
}

func TestRunQuarantineAndLateRecords(t *testing.T) {
	fetchTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	now := time.Now().UTC()
	page := []fetcher.SourceRecord{
		sourceRecord("valid", fetchTime, loginPayload(t, now.Add(-5*time.Minute))),
		sourceRecord("broken", fetchTime.Add(time.Second), json.RawMessage("not json")),
		sourceRecord("late", fetchTime.Add(2*time.Second), loginPayload(t, now.Add(-48*time.Hour))),
	}
	fake := &scriptedFetcher{pages: [][]fetcher.SourceRecord{page}}
	runner, database := newRunner(t, fake)

	result, err := runner.Run(context.Background(), testPipelineID)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusOK {
		t.Errorf("Status = %q, want OK; error = %q", result.Status, result.Error)
	}
	if result.RecordsRead != 3 || result.RecordsWritten != 1 ||
		result.RecordsQuarantined != 1 || result.RecordsLate != 1 {
		t.Errorf("counts = read %d, written %d, quarantined %d, late %d; want 3, 1, 1, 1",
			result.RecordsRead, result.RecordsWritten, result.RecordsQuarantined, result.RecordsLate)
	}
	if events, quarantine := storedCounts(t, database); events != 1 || quarantine != 1 {
		t.Errorf("stored events/quarantine = %d/%d, want 1/1", events, quarantine)
	}
}

func TestRunAllUnmappedWarning(t *testing.T) {
	fetchTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	page := make([]fetcher.SourceRecord, 150)
	for index := range page {
		page[index] = sourceRecord(fmt.Sprintf("doc-%d", index), fetchTime.Add(time.Duration(index)*time.Second),
			unmappedPayload(t))
	}
	fake := &scriptedFetcher{pages: [][]fetcher.SourceRecord{page}}
	runner, database := newRunner(t, fake, func(files *config.Files) {
		files.System.Runner.BatchSize = 100
	})

	result, err := runner.Run(context.Background(), testPipelineID)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusOK {
		t.Errorf("Status = %q, want OK", result.Status)
	}
	if result.RecordsRead != 150 || result.RecordsUnmapped != 150 {
		t.Errorf("read/unmapped = %d/%d, want 150/150", result.RecordsRead, result.RecordsUnmapped)
	}
	if len(result.Warnings) != 1 || result.Warnings[0] != "ALL_UNMAPPED" {
		t.Errorf("Warnings = %v, want [ALL_UNMAPPED]", result.Warnings)
	}
	row := loadRunRow(t, database, result.RunID)
	if len(row.Warnings) != 1 || row.Warnings[0] != "ALL_UNMAPPED" {
		t.Errorf("row warnings = %v, want [ALL_UNMAPPED]", row.Warnings)
	}
	if events, _ := storedCounts(t, database); events != 0 {
		t.Errorf("stored events = %d, want 0", events)
	}
}

func TestRunTimeout(t *testing.T) {
	fake := &scriptedFetcher{block: true}
	runner, database := newRunner(t, fake, func(files *config.Files) {
		files.Pipelines[0].Schedule.Timeout = config.Duration(50 * time.Millisecond)
	})

	result, err := runner.Run(context.Background(), testPipelineID)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusTimedOut {
		t.Errorf("Status = %q, want TIMED_OUT", result.Status)
	}
	row := loadRunRow(t, database, result.RunID)
	if row.Status != string(StatusTimedOut) || row.FinishedAt == nil {
		t.Errorf("row status/finished = %q/%v, want TIMED_OUT with a finish time", row.Status, row.FinishedAt)
	}
}

func TestRunCanceled(t *testing.T) {
	fake := &scriptedFetcher{block: true, started: make(chan struct{})}
	runner, database := newRunner(t, fake)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-fake.started
		cancel()
	}()

	result, err := runner.Run(ctx, testPipelineID)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusCanceled {
		t.Errorf("Status = %q, want CANCELED", result.Status)
	}
	row := loadRunRow(t, database, result.RunID)
	if row.Status != string(StatusCanceled) || row.FinishedAt == nil {
		t.Errorf("row status/finished = %q/%v, want CANCELED with a finish time", row.Status, row.FinishedAt)
	}
}

func TestRunConcurrentSkip(t *testing.T) {
	fake := &scriptedFetcher{}
	runner, database := newRunner(t, fake)

	ctx := context.Background()
	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatalf("connection pool: %v", err)
	}
	connection, err := sqlDatabase.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve connection: %v", err)
	}
	defer func() {
		_, _ = connection.ExecContext(ctx, advisoryUnlockStatement, testPipelineID)
		_ = connection.Close()
	}()
	var acquired bool
	if err := connection.QueryRowContext(ctx, advisoryLockStatement, testPipelineID).Scan(&acquired); err != nil {
		t.Fatalf("take the lock: %v", err)
	}
	if !acquired {
		t.Fatal("lock was not acquired")
	}

	result, err := runner.Run(ctx, testPipelineID)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusSkipped {
		t.Errorf("Status = %q, want SKIPPED", result.Status)
	}
	if fake.calls != 0 {
		t.Errorf("fetch calls = %d, want 0", fake.calls)
	}
	row := loadRunRow(t, database, result.RunID)
	if row.Status != string(StatusSkipped) || row.WindowStart != nil {
		t.Errorf("row status/window start = %q/%v, want SKIPPED without a window", row.Status, row.WindowStart)
	}
}

func TestRunRecordsGap(t *testing.T) {
	watermark := time.Now().UTC().Add(-10 * time.Hour).Truncate(time.Second)
	fake := &scriptedFetcher{}
	runner, database := newRunner(t, fake)
	registerDatasetWithWatermark(t, database, watermark)

	result, err := runner.Run(context.Background(), testPipelineID)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusOK {
		t.Errorf("Status = %q, want OK", result.Status)
	}
	if got := fake.request.Window.End.Sub(fake.request.Window.Start); got != 6*time.Hour {
		t.Errorf("window length = %s, want 6h", got)
	}
	row := loadRunRow(t, database, result.RunID)
	if row.GapStart == nil || row.GapEnd == nil {
		t.Fatalf("Gap = %v..%v, want a recorded gap", row.GapStart, row.GapEnd)
	}
	if !row.GapStart.Equal(watermark.Add(-time.Minute)) {
		t.Errorf("GapStart = %s, want %s", row.GapStart, watermark.Add(-time.Minute))
	}
	if !row.GapEnd.Equal(fake.request.Window.End.Add(-6 * time.Hour)) {
		t.Errorf("GapEnd = %s, want %s", row.GapEnd, fake.request.Window.End.Add(-6*time.Hour))
	}
	if got := datasetFetchWatermark(t, database); !got.Equal(fake.request.Window.End) {
		t.Errorf("fetch watermark = %s, want the window end %s", got, fake.request.Window.End)
	}
}

func TestRunEmptyWindow(t *testing.T) {
	watermark := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	fake := &scriptedFetcher{}
	runner, database := newRunner(t, fake)
	registerDatasetWithWatermark(t, database, watermark)

	result, err := runner.Run(context.Background(), testPipelineID)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Status != StatusOK || result.RecordsRead != 0 {
		t.Errorf("Status/read = %q/%d, want OK/0; error = %q", result.Status, result.RecordsRead, result.Error)
	}
	if fake.calls != 0 {
		t.Errorf("fetch calls = %d, want 0", fake.calls)
	}
	if got := datasetFetchWatermark(t, database); !got.Equal(watermark) {
		t.Errorf("fetch watermark = %s, want the unchanged %s", got, watermark)
	}
}

func TestRunUnknownPipeline(t *testing.T) {
	fake := &scriptedFetcher{}
	runner, database := newRunner(t, fake)

	_, err := runner.Run(context.Background(), "missing")
	if err == nil || !strings.Contains(err.Error(), `unknown pipeline "missing"`) {
		t.Fatalf("Run() error = %v, want an unknown pipeline error", err)
	}
	if count := countRunRows(t, database); count != 0 {
		t.Errorf("run rows = %d, want 0", count)
	}
}

func TestRunRequiredVariable(t *testing.T) {
	fake := &scriptedFetcher{}
	runner, database := newRunner(t, fake, func(files *config.Files) {
		files.Pipelines[0].Variables = map[string]config.Variable{
			"user": {Type: "string", Required: true},
		}
		files.Pipelines[0].Fetchers[0].Inputs["user"] = config.Input{Variable: "user"}
	})

	_, err := runner.Run(context.Background(), testPipelineID)
	if err == nil || !strings.Contains(err.Error(), `required variable "user" is not set`) {
		t.Fatalf("Run() error = %v, want the missing required variable", err)
	}
	if count := countRunRows(t, database); count != 0 {
		t.Errorf("run rows = %d, want 0", count)
	}
}
