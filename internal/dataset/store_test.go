package dataset

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type storedDataset struct {
	PipelineID      string
	Retention       time.Duration
	AllowedLateness time.Duration
	Version         int
	FetchWatermark  *time.Time
}

const (
	testRetention = 72 * time.Hour
	testLateness  = 10 * time.Minute
)

func registerTestDataset(t *testing.T, store *PostgresStore, db *gorm.DB) Dataset {
	t.Helper()
	registration := Dataset{
		Name:            "auth_events",
		PipelineID:      "auth-events",
		Retention:       testRetention,
		AllowedLateness: testLateness,
	}
	if err := registerDataset(t, store, db, registration); err != nil {
		t.Fatalf("RegisterDataset: %v", err)
	}
	return registration
}

func writeBatch(t *testing.T, store *PostgresStore, db *gorm.DB, datasetName string, batch Batch) error {
	t.Helper()
	return db.Transaction(func(transaction *gorm.DB) error {
		return store.WriteBatch(context.Background(), transaction, datasetName, batch)
	})
}

func newRecord(index int, eventTime time.Time, runID string, eventType udm.EventType) Record {
	documentID := fmt.Sprintf("doc-%d", index)
	return Record{
		Key: SourceKey{
			FetcherInstanceID: "fetcher",
			Index:             "logs",
			DocumentID:        documentID,
		},
		EventTime: eventTime,
		RunID:     runID,
		Event: udm.Event{
			Metadata: udm.Metadata{
				EventTimestamp: eventTime,
				EventType:      eventType,
				Description:    "record " + documentID,
			},
			Principal: udm.Noun{IP: []string{"203.0.113.7"}},
			Target: udm.Noun{
				Hostname: "host-1",
				User:     udm.User{UserID: "alice"},
			},
		},
	}
}

func countEventRows(t *testing.T, db *gorm.DB, datasetName string) int64 {
	t.Helper()
	var count int64
	err := db.Raw("SELECT count(*) FROM dataset_events WHERE dataset = ?", datasetName).Scan(&count).Error
	if err != nil {
		t.Fatalf("count dataset_events: %v", err)
	}
	return count
}

func countQuarantineRows(t *testing.T, db *gorm.DB, datasetName string) int64 {
	t.Helper()
	var count int64
	err := db.Raw("SELECT count(*) FROM dataset_quarantine WHERE dataset = ?", datasetName).Scan(&count).Error
	if err != nil {
		t.Fatalf("count dataset_quarantine: %v", err)
	}
	return count
}

type storedEventRow struct {
	EventTime         time.Time `gorm:"column:event_time"`
	SourceKeyHash     []byte    `gorm:"column:source_key_hash"`
	FetcherInstanceID string    `gorm:"column:fetcher_instance_id"`
	SourceIndex       string    `gorm:"column:source_index"`
	DocumentID        string    `gorm:"column:document_id"`
	EventType         string    `gorm:"column:event_type"`
	TargetUser        *string   `gorm:"column:target_user"`
	TargetHost        *string   `gorm:"column:target_host"`
	PrincipalIP       *string   `gorm:"column:principal_ip"`
	EventJSON         []byte    `gorm:"column:event"`
	PipelineRunID     string    `gorm:"column:pipeline_run_id"`
}

func readEvent(t *testing.T, db *gorm.DB, documentID string) storedEventRow {
	t.Helper()
	var row storedEventRow
	err := db.Raw(`
		SELECT event_time, source_key_hash, fetcher_instance_id, source_index,
		       document_id, event_type, target_user, target_host, principal_ip,
		       event, pipeline_run_id
		FROM dataset_events
		WHERE document_id = ?`, documentID).Scan(&row).Error
	if err != nil {
		t.Fatalf("read event %q: %v", documentID, err)
	}
	if row.DocumentID == "" {
		t.Fatalf("event %q was not stored", documentID)
	}
	return row
}

type storedQuarantineRow struct {
	Payload        []byte  `gorm:"column:payload"`
	Truncated      bool    `gorm:"column:payload_truncated"`
	MappingID      *string `gorm:"column:mapping_id"`
	MappingVersion *int    `gorm:"column:mapping_version"`
	ErrorsJSON     []byte  `gorm:"column:errors"`
	PipelineRunID  string  `gorm:"column:pipeline_run_id"`
}

func readQuarantine(t *testing.T, db *gorm.DB, documentID string) storedQuarantineRow {
	t.Helper()
	var row storedQuarantineRow
	err := db.Raw(`
		SELECT payload, payload_truncated, mapping_id, mapping_version, errors, pipeline_run_id
		FROM dataset_quarantine
		WHERE document_id = ?`, documentID).Scan(&row).Error
	if err != nil {
		t.Fatalf("read quarantined record %q: %v", documentID, err)
	}
	return row
}

type storedWatermark struct {
	FetchWatermark   *time.Time `gorm:"column:fetch_watermark"`
	DatasetWatermark *time.Time `gorm:"column:dataset_watermark"`
	LastRunID        *string    `gorm:"column:last_run_id"`
}

func readWatermark(t *testing.T, db *gorm.DB, datasetName string) storedWatermark {
	t.Helper()
	var watermark storedWatermark
	err := db.Raw(`
		SELECT fetch_watermark, dataset_watermark, last_run_id
		FROM datasets
		WHERE name = ?`, datasetName).Scan(&watermark).Error
	if err != nil {
		t.Fatalf("read watermarks for %q: %v", datasetName, err)
	}
	return watermark
}

func assertWatermark(t *testing.T, watermark storedWatermark, fetch, dataset time.Time, runID string) {
	t.Helper()
	if watermark.FetchWatermark == nil || !watermark.FetchWatermark.Equal(fetch) {
		t.Errorf("fetch_watermark = %v, want %s", watermark.FetchWatermark, fetch)
	}
	if watermark.DatasetWatermark == nil || !watermark.DatasetWatermark.Equal(dataset) {
		t.Errorf("dataset_watermark = %v, want %s", watermark.DatasetWatermark, dataset)
	}
	if watermark.LastRunID == nil || *watermark.LastRunID != runID {
		t.Errorf("last_run_id = %v, want %q", watermark.LastRunID, runID)
	}
}

func assertNoWatermark(t *testing.T, watermark storedWatermark) {
	t.Helper()
	if watermark.FetchWatermark != nil || watermark.DatasetWatermark != nil || watermark.LastRunID != nil {
		t.Errorf("watermark = %+v, want no watermark", watermark)
	}
}

func dayPartitionExists(t *testing.T, db *gorm.DB, datasetName string, day time.Time) bool {
	t.Helper()
	var exists bool
	err := db.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM pg_inherits
			WHERE inhrelid = to_regclass(?) AND inhparent = to_regclass(?)
		)`, "ds_"+datasetName+"_"+day.Format("20060102"), "ds_"+datasetName).Scan(&exists).Error
	if err != nil {
		t.Fatalf("look up day partition for %q: %v", datasetName, err)
	}
	return exists
}

func listPartitionChildren(t *testing.T, db *gorm.DB, datasetName string) int64 {
	t.Helper()
	var count int64
	err := db.Raw(`
		SELECT count(*) FROM pg_inherits WHERE inhparent = to_regclass(?)`, "ds_"+datasetName).
		Scan(&count).Error
	if err != nil {
		t.Fatalf("count partitions of %q: %v", datasetName, err)
	}
	return count
}

// statementCounter counts the statements GORM sends through the session.
type statementCounter struct {
	gormlogger.Interface
	mutex      sync.Mutex
	calls      atomic.Int64
	statements []string
}

// The hash is stored in dataset_events, so changing the byte layout would
// orphan every existing row.
func TestSourceKeyHash(t *testing.T) {
	key := SourceKey{FetcherInstanceID: "instance", Index: "index", DocumentID: "doc"}

	if got, want := hex.EncodeToString(key.Hash()), "d8fe9fa63e1a1d605f834ac7513d88a39b050f02171d187a18b14177a50f206b"; got != want {
		t.Fatalf("Hash() = %s, want %s", got, want)
	}

	reordered := SourceKey{FetcherInstanceID: "index", Index: "doc", DocumentID: "instance"}
	if got, other := hex.EncodeToString(key.Hash()), hex.EncodeToString(reordered.Hash()); got == other {
		t.Fatalf("reordering the parts produced the same hash %s", got)
	}
}

func TestRegisterDataset(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := Dataset{
		Name:            "auth_events",
		PipelineID:      "auth-events",
		Retention:       72 * time.Hour,
		AllowedLateness: 10 * time.Minute,
	}
	wantPartition := "RANGE (event_time)|FOR VALUES IN ('auth_events')"

	if err := registerDataset(t, store, db, registration); err != nil {
		t.Fatalf("RegisterDataset: %v", err)
	}

	stored := readDataset(t, db, registration.Name)
	if stored.PipelineID != registration.PipelineID {
		t.Errorf("pipeline_id = %q, want %q", stored.PipelineID, registration.PipelineID)
	}
	if stored.Retention != registration.Retention {
		t.Errorf("retention = %s, want %s", stored.Retention, registration.Retention)
	}
	if stored.AllowedLateness != registration.AllowedLateness {
		t.Errorf("allowed_lateness = %s, want %s", stored.AllowedLateness, registration.AllowedLateness)
	}
	if stored.Version != 1 {
		t.Errorf("version = %d, want 1", stored.Version)
	}
	if stored.FetchWatermark != nil {
		t.Errorf("fetch_watermark = %s, want NULL", stored.FetchWatermark)
	}
	if got := partitionDefinition(t, db, registration.Name); got != wantPartition {
		t.Errorf("partition = %q, want %q", got, wantPartition)
	}

	registration.Retention = 96 * time.Hour
	if err := registerDataset(t, store, db, registration); err != nil {
		t.Fatalf("RegisterDataset with new retention: %v", err)
	}
	stored = readDataset(t, db, registration.Name)
	if stored.Retention != registration.Retention {
		t.Errorf("retention after re-registration = %s, want %s", stored.Retention, registration.Retention)
	}
	if stored.AllowedLateness != registration.AllowedLateness {
		t.Errorf("allowed_lateness after re-registration = %s, want %s", stored.AllowedLateness, registration.AllowedLateness)
	}
	if stored.Version != 2 {
		t.Errorf("version after re-registration = %d, want 2", stored.Version)
	}
	if got := partitionDefinition(t, db, registration.Name); got != wantPartition {
		t.Errorf("partition after re-registration = %q, want %q", got, wantPartition)
	}
}

func TestRegisterDatasetRefusesAnotherPipeline(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	first := Dataset{
		Name:            "auth_events",
		PipelineID:      "auth-events",
		Retention:       72 * time.Hour,
		AllowedLateness: 10 * time.Minute,
	}
	if err := registerDataset(t, store, db, first); err != nil {
		t.Fatalf("RegisterDataset: %v", err)
	}

	second := first
	second.PipelineID = "other"
	second.Retention = 48 * time.Hour
	err := registerDataset(t, store, db, second)
	if !errors.Is(err, ErrDatasetOwned) {
		t.Fatalf("RegisterDataset from another pipeline = %v, want ErrDatasetOwned", err)
	}
	for _, pipeline := range []string{first.PipelineID, second.PipelineID} {
		if !strings.Contains(err.Error(), pipeline) {
			t.Errorf("error %q does not name pipeline %q", err, pipeline)
		}
	}

	stored := readDataset(t, db, first.Name)
	if stored.PipelineID != first.PipelineID {
		t.Errorf("pipeline_id = %q, want %q", stored.PipelineID, first.PipelineID)
	}
	if stored.Retention != first.Retention {
		t.Errorf("retention = %s, want %s", stored.Retention, first.Retention)
	}
	if stored.Version != 1 {
		t.Errorf("version = %d, want 1", stored.Version)
	}
	if got, want := partitionDefinition(t, db, first.Name), "RANGE (event_time)|FOR VALUES IN ('auth_events')"; got != want {
		t.Errorf("partition = %q, want %q", got, want)
	}
}

func TestRejectsHostileDatasetNames(t *testing.T) {
	db := databasetest.New(t)
	counter := &statementCounter{Interface: db.Logger}
	counting := db.Session(&gorm.Session{Logger: counter})
	store := NewPostgresStore(db)
	before := relationCount(t, db)
	end := time.Now().UTC()
	start := end.Add(-time.Hour)

	names := []string{"x; DROP TABLE datasets", `x"`, "A", strings.Repeat("a", 41)}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			registration := Dataset{Name: name, PipelineID: "auth-events", Retention: time.Hour}
			if err := store.RegisterDataset(context.Background(), counting, registration); !errors.Is(err, ErrInvalidDatasetName) {
				t.Errorf("RegisterDataset(%q) = %v, want ErrInvalidDatasetName", name, err)
			}
			if err := store.WriteBatch(context.Background(), counting, name, Batch{RunID: "run-1", FetchWatermark: end}); !errors.Is(err, ErrInvalidDatasetName) {
				t.Errorf("WriteBatch(%q) = %v, want ErrInvalidDatasetName", name, err)
			}
			if err := store.Expire(context.Background(), counting, name, end); !errors.Is(err, ErrInvalidDatasetName) {
				t.Errorf("Expire(%q) = %v, want ErrInvalidDatasetName", name, err)
			}
			readErrors := 0
			for _, err := range store.ReadWindow(context.Background(), name, start, end, Filter{}) {
				readErrors++
				if !errors.Is(err, ErrInvalidDatasetName) {
					t.Errorf("ReadWindow(%q) yielded %v, want ErrInvalidDatasetName", name, err)
				}
			}
			if readErrors != 1 {
				t.Errorf("ReadWindow(%q) yielded %d errors, want 1", name, readErrors)
			}
		})
	}

	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("invalid names sent %d statements, want none", calls)
	}
	if after := relationCount(t, db); after != before {
		t.Errorf("catalog holds %d relations after invalid names, want %d", after, before)
	}
	var datasets int64
	if err := db.Raw("SELECT count(*) FROM datasets").Scan(&datasets).Error; err != nil {
		t.Fatalf("count datasets: %v", err)
	}
	if datasets != 0 {
		t.Errorf("datasets holds %d rows after invalid names, want none", datasets)
	}
}

func TestWriteBatchStoresRecords(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := registerTestDataset(t, store, db)
	base := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)
	batch := Batch{
		RunID: "run-1",
		Records: []Record{
			newRecord(1, base, "run-1", udm.EventTypeUserLogin),
			newRecord(2, base.Add(time.Second), "run-1", udm.EventTypeGenericEvent),
		},
		FetchWatermark: base.Add(time.Hour),
	}

	if err := writeBatch(t, store, db, registration.Name, batch); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	if got := countEventRows(t, db, registration.Name); got != 2 {
		t.Errorf("dataset_events holds %d rows, want 2", got)
	}
	stored := readEvent(t, db, "doc-1")
	if !stored.EventTime.Equal(base) {
		t.Errorf("event_time = %s, want %s", stored.EventTime, base)
	}
	if !bytes.Equal(stored.SourceKeyHash, batch.Records[0].Key.Hash()) {
		t.Errorf("source_key_hash = %x, want %x", stored.SourceKeyHash, batch.Records[0].Key.Hash())
	}
	if stored.FetcherInstanceID != "fetcher" || stored.SourceIndex != "logs" || stored.DocumentID != "doc-1" {
		t.Errorf("source key columns = %q/%q/%q", stored.FetcherInstanceID, stored.SourceIndex, stored.DocumentID)
	}
	if stored.EventType != string(udm.EventTypeUserLogin) {
		t.Errorf("event_type = %q, want %q", stored.EventType, udm.EventTypeUserLogin)
	}
	if stored.TargetUser == nil || *stored.TargetUser != "alice" {
		t.Errorf("target_user = %v, want alice", stored.TargetUser)
	}
	if stored.TargetHost == nil || *stored.TargetHost != "host-1" {
		t.Errorf("target_host = %v, want host-1", stored.TargetHost)
	}
	if stored.PrincipalIP == nil || *stored.PrincipalIP != "203.0.113.7" {
		t.Errorf("principal_ip = %v, want 203.0.113.7", stored.PrincipalIP)
	}
	if stored.PipelineRunID != "run-1" {
		t.Errorf("pipeline_run_id = %q, want run-1", stored.PipelineRunID)
	}
	var event udm.Event
	if err := json.Unmarshal(stored.EventJSON, &event); err != nil {
		t.Fatalf("decode stored event: %v", err)
	}
	if event.Metadata.EventType != udm.EventTypeUserLogin || event.Metadata.Description != "record doc-1" {
		t.Errorf("stored event = %+v", event.Metadata)
	}

	assertWatermark(t, readWatermark(t, db, registration.Name),
		batch.FetchWatermark, batch.FetchWatermark.Add(-testLateness), "run-1")
}

func TestWriteBatchUpsertsOverlappingRuns(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := registerTestDataset(t, store, db)
	base := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)

	first := Batch{RunID: "run-a", FetchWatermark: base.Add(time.Hour)}
	for index := range 10 {
		first.Records = append(first.Records,
			newRecord(index, base.Add(time.Duration(index)*time.Second), "run-a", udm.EventTypeUserLogin))
	}
	if err := writeBatch(t, store, db, registration.Name, first); err != nil {
		t.Fatalf("WriteBatch run A: %v", err)
	}

	second := Batch{RunID: "run-b", FetchWatermark: base.Add(2 * time.Hour)}
	for index := range 15 {
		record := newRecord(index, base.Add(time.Duration(index)*time.Second), "run-b", udm.EventTypeUserLogin)
		record.Event.Metadata.Description = "written by run-b"
		second.Records = append(second.Records, record)
	}
	if err := writeBatch(t, store, db, registration.Name, second); err != nil {
		t.Fatalf("WriteBatch run B: %v", err)
	}

	if got := countEventRows(t, db, registration.Name); got != 15 {
		t.Errorf("dataset_events holds %d rows, want 15", got)
	}
	var fromRunB int64
	if err := db.Raw("SELECT count(*) FROM dataset_events WHERE pipeline_run_id = ?", "run-b").
		Scan(&fromRunB).Error; err != nil {
		t.Fatalf("count run B rows: %v", err)
	}
	if fromRunB != 15 {
		t.Errorf("%d rows carry run B's id, want 15", fromRunB)
	}
	stored := readEvent(t, db, "doc-0")
	if stored.PipelineRunID != "run-b" {
		t.Errorf("pipeline_run_id = %q, want run-b", stored.PipelineRunID)
	}
	var event udm.Event
	if err := json.Unmarshal(stored.EventJSON, &event); err != nil {
		t.Fatalf("decode stored event: %v", err)
	}
	if event.Metadata.Description != "written by run-b" {
		t.Errorf("stored event was not replaced: %q", event.Metadata.Description)
	}
}

func TestWriteBatchKeysChangedEventTimeAsNewRow(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := registerTestDataset(t, store, db)
	base := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Hour)

	first := Batch{RunID: "run-1", Records: []Record{newRecord(1, base, "run-1", udm.EventTypeUserLogin)}}
	if err := writeBatch(t, store, db, registration.Name, first); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	moved := Batch{RunID: "run-2", Records: []Record{newRecord(1, base.Add(time.Minute), "run-2", udm.EventTypeUserLogin)}}
	if err := writeBatch(t, store, db, registration.Name, moved); err != nil {
		t.Fatalf("WriteBatch with changed event time: %v", err)
	}

	if got := countEventRows(t, db, registration.Name); got != 2 {
		t.Errorf("dataset_events holds %d rows, want 2", got)
	}
}

func TestWriteBatchCreatesDayPartitions(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := registerTestDataset(t, store, db)
	day := utcDay(time.Now().UTC().Add(-48 * time.Hour))
	batch := Batch{
		RunID: "run-1",
		Records: []Record{
			newRecord(1, day.Add(23*time.Hour+59*time.Minute), "run-1", udm.EventTypeUserLogin),
			newRecord(2, day.Add(24*time.Hour+time.Minute), "run-1", udm.EventTypeUserLogin),
		},
		FetchWatermark: day.Add(48 * time.Hour),
	}
	if err := writeBatch(t, store, db, registration.Name, batch); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	if !dayPartitionExists(t, db, registration.Name, day) {
		t.Errorf("partition for %s is missing", day.Format("2006-01-02"))
	}
	if !dayPartitionExists(t, db, registration.Name, day.Add(24*time.Hour)) {
		t.Errorf("partition for %s is missing", day.Add(24*time.Hour).Format("2006-01-02"))
	}
	if got := listPartitionChildren(t, db, registration.Name); got != 2 {
		t.Errorf("list partition has %d children, want 2", got)
	}
	if got := countEventRows(t, db, registration.Name); got != 2 {
		t.Errorf("dataset_events holds %d rows, want 2", got)
	}
}

func TestWriteBatchRejectsEventsOutsideRetention(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := registerTestDataset(t, store, db)
	now := time.Now().UTC()
	quarantine := QuarantinedRecord{
		Key:            SourceKey{FetcherInstanceID: "fetcher", Index: "logs", DocumentID: "bad-1"},
		Payload:        []byte("payload"),
		MappingID:      "mapping-1",
		MappingVersion: 1,
		Errors:         []udm.ValidationError{{Path: "target.user.userid", Message: "is required"}},
	}
	batch := Batch{
		RunID: "run-1",
		Records: []Record{
			newRecord(1, now.Add(-time.Hour), "run-1", udm.EventTypeUserLogin),
			newRecord(2, now.Add(30*time.Hour), "run-1", udm.EventTypeUserLogin),
		},
		Quarantined:    []QuarantinedRecord{quarantine},
		FetchWatermark: now,
	}
	if err := writeBatch(t, store, db, registration.Name, batch); !errors.Is(err, ErrOutsideRetention) {
		t.Fatalf("WriteBatch with a future event = %v, want ErrOutsideRetention", err)
	}

	if got := countEventRows(t, db, registration.Name); got != 0 {
		t.Errorf("dataset_events holds %d rows after a rejected batch, want none", got)
	}
	if got := countQuarantineRows(t, db, registration.Name); got != 0 {
		t.Errorf("dataset_quarantine holds %d rows after a rejected batch, want none", got)
	}
	if got := listPartitionChildren(t, db, registration.Name); got != 0 {
		t.Errorf("list partition has %d children after a rejected batch, want none", got)
	}
	assertNoWatermark(t, readWatermark(t, db, registration.Name))

	old := Batch{RunID: "run-2", Records: []Record{newRecord(3, now.Add(-97*time.Hour), "run-2", udm.EventTypeUserLogin)}}
	if err := writeBatch(t, store, db, registration.Name, old); !errors.Is(err, ErrOutsideRetention) {
		t.Fatalf("WriteBatch with an old event = %v, want ErrOutsideRetention", err)
	}
	if got := countEventRows(t, db, registration.Name); got != 0 {
		t.Errorf("dataset_events holds %d rows after an old record, want none", got)
	}
}

func TestWriteBatchCapsQuarantinePayload(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := registerTestDataset(t, store, db)
	bigPayload := bytes.Repeat([]byte("a"), 100*1024)
	validationErrors := []udm.ValidationError{{Path: "target.user.userid", Message: "is required"}}
	batch := Batch{
		RunID: "run-1",
		Quarantined: []QuarantinedRecord{
			{
				Key:            SourceKey{FetcherInstanceID: "fetcher", Index: "logs", DocumentID: "bad-1"},
				Payload:        bigPayload,
				MappingID:      "mapping-1",
				MappingVersion: 2,
				Errors:         validationErrors,
			},
			{
				Key:            SourceKey{FetcherInstanceID: "fetcher", Index: "logs", DocumentID: "bad-2"},
				Payload:        []byte("small payload"),
				MappingID:      "mapping-2",
				MappingVersion: 3,
				Errors:         []udm.ValidationError{},
			},
		},
		FetchWatermark: time.Now().UTC(),
	}
	if err := writeBatch(t, store, db, registration.Name, batch); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	if got := countQuarantineRows(t, db, registration.Name); got != 2 {
		t.Fatalf("dataset_quarantine holds %d rows, want 2", got)
	}
	big := readQuarantine(t, db, "bad-1")
	if len(big.Payload) != 65536 {
		t.Errorf("big payload is %d bytes, want 65536", len(big.Payload))
	}
	if !bytes.Equal(big.Payload, bigPayload[:65536]) {
		t.Error("big payload is not the first 65536 bytes of the original")
	}
	if !big.Truncated {
		t.Error("big payload is not marked truncated")
	}
	if big.MappingID == nil || *big.MappingID != "mapping-1" {
		t.Errorf("mapping_id = %v, want mapping-1", big.MappingID)
	}
	if big.MappingVersion == nil || *big.MappingVersion != 2 {
		t.Errorf("mapping_version = %v, want 2", big.MappingVersion)
	}
	if big.PipelineRunID != "run-1" {
		t.Errorf("pipeline_run_id = %q, want run-1", big.PipelineRunID)
	}
	var errors []struct {
		Path    string `json:"path"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(big.ErrorsJSON, &errors); err != nil {
		t.Fatalf("decode quarantine errors: %v", err)
	}
	if len(errors) != 1 || errors[0].Path != validationErrors[0].Path || errors[0].Message != validationErrors[0].Message {
		t.Errorf("quarantine errors = %+v, want %+v", errors, validationErrors)
	}

	small := readQuarantine(t, db, "bad-2")
	if string(small.Payload) != "small payload" {
		t.Errorf("small payload = %q, want %q", small.Payload, "small payload")
	}
	if small.Truncated {
		t.Error("small payload is marked truncated")
	}
	if small.MappingID == nil || *small.MappingID != "mapping-2" {
		t.Errorf("mapping_id = %v, want mapping-2", small.MappingID)
	}
	if small.MappingVersion == nil || *small.MappingVersion != 3 {
		t.Errorf("mapping_version = %v, want 3", small.MappingVersion)
	}
}

func TestWriteBatchWatermarks(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := registerTestDataset(t, store, db)
	base := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)

	if err := writeBatch(t, store, db, registration.Name, Batch{
		RunID: "run-1", FetchWatermark: base.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	assertWatermark(t, readWatermark(t, db, registration.Name),
		base.Add(10*time.Minute), base, "run-1")

	if err := writeBatch(t, store, db, registration.Name, Batch{
		RunID: "run-2", FetchWatermark: base.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteBatch backwards: %v", err)
	}
	assertWatermark(t, readWatermark(t, db, registration.Name),
		base.Add(10*time.Minute), base, "run-2")

	if err := writeBatch(t, store, db, registration.Name, Batch{
		RunID: "run-3", FetchWatermark: base.Add(15 * time.Minute),
	}); err != nil {
		t.Fatalf("WriteBatch quiet source: %v", err)
	}
	assertWatermark(t, readWatermark(t, db, registration.Name),
		base.Add(15*time.Minute), base.Add(5*time.Minute), "run-3")

	if err := writeBatch(t, store, db, registration.Name, Batch{
		RunID:   "run-4",
		Records: []Record{newRecord(1, base, "run-4", udm.EventTypeUserLogin)},
	}); err != nil {
		t.Fatalf("WriteBatch without a watermark: %v", err)
	}
	assertWatermark(t, readWatermark(t, db, registration.Name),
		base.Add(15*time.Minute), base.Add(5*time.Minute), "run-4")
}

func TestWriteBatchRollsBackWithCaller(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := registerTestDataset(t, store, db)
	runnerError := errors.New("runner failed")
	batch := Batch{
		RunID:   "run-1",
		Records: []Record{newRecord(1, time.Now().UTC().Add(-time.Hour), "run-1", udm.EventTypeUserLogin)},
		Quarantined: []QuarantinedRecord{{
			Key:     SourceKey{FetcherInstanceID: "fetcher", Index: "logs", DocumentID: "bad-1"},
			Payload: []byte("payload"),
			Errors:  []udm.ValidationError{{Path: "x", Message: "y"}},
		}},
		FetchWatermark: time.Now().UTC(),
	}

	err := db.Transaction(func(transaction *gorm.DB) error {
		if err := store.WriteBatch(context.Background(), transaction, registration.Name, batch); err != nil {
			return err
		}
		return runnerError
	})
	if !errors.Is(err, runnerError) {
		t.Fatalf("transaction error = %v, want %v", err, runnerError)
	}

	if got := countEventRows(t, db, registration.Name); got != 0 {
		t.Errorf("dataset_events holds %d rows after rollback, want none", got)
	}
	if got := countQuarantineRows(t, db, registration.Name); got != 0 {
		t.Errorf("dataset_quarantine holds %d rows after rollback, want none", got)
	}
	if got := listPartitionChildren(t, db, registration.Name); got != 0 {
		t.Errorf("list partition has %d children after rollback, want none", got)
	}
	assertNoWatermark(t, readWatermark(t, db, registration.Name))
}

func TestWriteBatchUnknownDataset(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	err := writeBatch(t, store, db, "missing", Batch{RunID: "run-1", FetchWatermark: time.Now().UTC()})
	if !errors.Is(err, ErrUnknownDataset) {
		t.Fatalf("WriteBatch on a missing dataset = %v, want ErrUnknownDataset", err)
	}
}

func TestReadWindowWindowsAndOrders(t *testing.T) {
	db := databasetest.New(t)
	counter := &statementCounter{Interface: db.Logger}
	store := NewPostgresStore(db.Session(&gorm.Session{Logger: counter}))
	registration := registerTestDataset(t, store, db)
	base := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)

	records := make([]Record, 0, 2700)
	index := 0
	for offset := range 100 {
		records = append(records, newRecord(index, base.Add(time.Duration(offset)*time.Second), "run-1", udm.EventTypeUserLogin))
		index++
	}
	for offset := range 2500 {
		records = append(records, newRecord(index, base.Add(time.Hour).Add(time.Duration(offset)*500*time.Millisecond), "run-1", udm.EventTypeUserLogin))
		index++
	}
	for offset := range 100 {
		records = append(records, newRecord(index, base.Add(2*time.Hour).Add(time.Duration(offset)*time.Second), "run-1", udm.EventTypeUserLogin))
		index++
	}
	batch := Batch{RunID: "run-1", Records: records, FetchWatermark: base.Add(4 * time.Hour)}
	if err := writeBatch(t, store, db, registration.Name, batch); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	start := base.Add(time.Hour)
	end := start.Add(time.Hour)
	var read []Record
	for record, err := range store.ReadWindow(context.Background(), registration.Name, start, end, Filter{}) {
		if err != nil {
			t.Fatalf("ReadWindow: %v", err)
		}
		read = append(read, record)
	}

	if len(read) != 2500 {
		t.Fatalf("ReadWindow returned %d records, want 2500", len(read))
	}
	for position, record := range read {
		if record.EventTime.Before(start) || !record.EventTime.Before(end) {
			t.Errorf("record %s is outside [%s, %s)", record.EventTime, start, end)
		}
		if position == 0 {
			continue
		}
		previous := read[position-1]
		if record.EventTime.Before(previous.EventTime) {
			t.Errorf("record %d is out of order", position)
		}
		if record.EventTime.Equal(previous.EventTime) && bytes.Compare(record.Key.Hash(), previous.Key.Hash()) <= 0 {
			t.Errorf("record %d is not ordered by source key hash", position)
		}
	}
	if pages := counter.countStatements(`FROM "dataset_events"`); pages != 3 {
		t.Errorf("ReadWindow issued %d page queries, want 3", pages)
	}
}

func TestReadWindowFiltersEventTypes(t *testing.T) {
	db := databasetest.New(t)
	counter := &statementCounter{Interface: db.Logger}
	store := NewPostgresStore(db.Session(&gorm.Session{Logger: counter}))
	registration := registerTestDataset(t, store, db)
	base := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)

	records := make([]Record, 0, 20)
	for index := range 20 {
		eventType := udm.EventTypeUserLogin
		if index%2 == 1 {
			eventType = udm.EventTypeGenericEvent
		}
		records = append(records, newRecord(index, base.Add(time.Duration(index)*time.Second), "run-1", eventType))
	}
	batch := Batch{RunID: "run-1", Records: records, FetchWatermark: base.Add(time.Hour)}
	if err := writeBatch(t, store, db, registration.Name, batch); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	var read []Record
	filter := Filter{EventTypes: []udm.EventType{udm.EventTypeUserLogin}}
	for record, err := range store.ReadWindow(context.Background(), registration.Name, base, base.Add(time.Hour), filter) {
		if err != nil {
			t.Fatalf("ReadWindow: %v", err)
		}
		read = append(read, record)
	}
	if len(read) != 10 {
		t.Fatalf("ReadWindow returned %d records, want 10", len(read))
	}
	for _, record := range read {
		if record.Event.Metadata.EventType != udm.EventTypeUserLogin {
			t.Errorf("ReadWindow returned event type %q", record.Event.Metadata.EventType)
		}
	}
	if pushed := counter.countStatements("event_type IN"); pushed != 1 {
		t.Errorf("ReadWindow pushed the event type filter down %d times, want 1", pushed)
	}
}

func TestReadWindowStopsEarly(t *testing.T) {
	db := databasetest.New(t)
	counter := &statementCounter{Interface: db.Logger}
	store := NewPostgresStore(db.Session(&gorm.Session{Logger: counter}))
	registration := registerTestDataset(t, store, db)
	base := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)

	records := make([]Record, 0, 1500)
	for index := range 1500 {
		records = append(records, newRecord(index, base.Add(time.Duration(index)*time.Second), "run-1", udm.EventTypeUserLogin))
	}
	batch := Batch{RunID: "run-1", Records: records, FetchWatermark: base.Add(time.Hour)}
	if err := writeBatch(t, store, db, registration.Name, batch); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	consumed := 0
	for _, err := range store.ReadWindow(context.Background(), registration.Name, base, base.Add(time.Hour), Filter{}) {
		if err != nil {
			t.Fatalf("ReadWindow: %v", err)
		}
		consumed++
		break
	}
	if consumed != 1 {
		t.Errorf("consumer saw %d records, want 1", consumed)
	}
	if pages := counter.countStatements(`FROM "dataset_events"`); pages != 1 {
		t.Errorf("early break issued %d page queries, want 1", pages)
	}
}

func TestReadWindowStopsOnCanceledContext(t *testing.T) {
	db := databasetest.New(t)
	counter := &statementCounter{Interface: db.Logger}
	store := NewPostgresStore(db.Session(&gorm.Session{Logger: counter}))
	registration := registerTestDataset(t, store, db)
	base := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)

	records := make([]Record, 0, 1500)
	for index := range 1500 {
		records = append(records, newRecord(index, base.Add(time.Duration(index)*time.Second), "run-1", udm.EventTypeUserLogin))
	}
	batch := Batch{RunID: "run-1", Records: records, FetchWatermark: base.Add(time.Hour)}
	if err := writeBatch(t, store, db, registration.Name, batch); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	consumed := 0
	var readErr error
	for _, err := range store.ReadWindow(ctx, registration.Name, base, base.Add(time.Hour), Filter{}) {
		if err != nil {
			readErr = err
			break
		}
		consumed++
		if consumed == 1 {
			cancel()
		}
	}
	if !errors.Is(readErr, context.Canceled) {
		t.Fatalf("ReadWindow error = %v, want context.Canceled", readErr)
	}
	if consumed != 1000 {
		t.Errorf("consumer saw %d records before the cancellation error, want 1000", consumed)
	}
	if pages := counter.countStatements(`FROM "dataset_events"`); pages != 1 {
		t.Errorf("canceled read issued %d page queries, want 1", pages)
	}
}

func TestReadWindowUnknownDataset(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	end := time.Now().UTC()
	start := end.Add(-time.Hour)

	readErrors := 0
	for _, err := range store.ReadWindow(context.Background(), "missing", start, end, Filter{}) {
		readErrors++
		if !errors.Is(err, ErrUnknownDataset) {
			t.Errorf("ReadWindow on a missing dataset yielded %v, want ErrUnknownDataset", err)
		}
	}
	if readErrors != 1 {
		t.Errorf("ReadWindow yielded %d errors, want 1", readErrors)
	}
}

func TestReadWindowEmptyBounds(t *testing.T) {
	db := databasetest.New(t)
	counter := &statementCounter{Interface: db.Logger}
	store := NewPostgresStore(db.Session(&gorm.Session{Logger: counter}))
	registration := registerTestDataset(t, store, db)
	end := time.Now().UTC()
	start := end.Add(-time.Hour)

	for _, bounds := range [][2]time.Time{{start, start}, {end, start}} {
		for record, err := range store.ReadWindow(context.Background(), registration.Name, bounds[0], bounds[1], Filter{}) {
			t.Fatalf("ReadWindow(%s, %s) yielded %v, %v", bounds[0], bounds[1], record, err)
		}
	}
	if pages := counter.countStatements(`FROM "dataset_events"`); pages != 0 {
		t.Errorf("empty bounds issued %d page queries, want 0", pages)
	}
}

func TestWatermark(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	ctx := context.Background()

	if _, err := store.Watermark(ctx, "missing"); !errors.Is(err, ErrUnknownDataset) {
		t.Fatalf("Watermark on a missing dataset = %v, want ErrUnknownDataset", err)
	}

	registration := registerTestDataset(t, store, db)
	watermark, err := store.Watermark(ctx, registration.Name)
	if err != nil {
		t.Fatalf("Watermark: %v", err)
	}
	if !watermark.FetchWatermark.IsZero() || !watermark.DatasetWatermark.IsZero() {
		t.Errorf("watermarks before the first batch = %+v, want zero", watermark)
	}
	if watermark.LastRunID != "" {
		t.Errorf("last_run_id before the first batch = %q, want empty", watermark.LastRunID)
	}
	if watermark.UpdatedAt.IsZero() {
		t.Error("updated_at is zero")
	}

	base := time.Now().UTC().Truncate(time.Minute).Add(-time.Hour)
	batch := Batch{RunID: "run-1", FetchWatermark: base.Add(10 * time.Minute)}
	if err := writeBatch(t, store, db, registration.Name, batch); err != nil {
		t.Fatalf("WriteBatch: %v", err)
	}
	watermark, err = store.Watermark(ctx, registration.Name)
	if err != nil {
		t.Fatalf("Watermark: %v", err)
	}
	if !watermark.FetchWatermark.Equal(batch.FetchWatermark) {
		t.Errorf("fetch watermark = %s, want %s", watermark.FetchWatermark, batch.FetchWatermark)
	}
	if !watermark.DatasetWatermark.Equal(batch.FetchWatermark.Add(-testLateness)) {
		t.Errorf("dataset watermark = %s, want %s", watermark.DatasetWatermark, batch.FetchWatermark.Add(-testLateness))
	}
	if watermark.LastRunID != "run-1" {
		t.Errorf("last_run_id = %q, want run-1", watermark.LastRunID)
	}
}

func TestExpire(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	registration := registerTestDataset(t, store, db)
	now := time.Now().UTC()
	today := utcDay(now)

	for offset := 4; offset >= 0; offset-- {
		day := today.Add(-time.Duration(offset) * 24 * time.Hour)
		createDayPartition(t, db, registration.Name, day)
		insertEvent(t, db, registration.Name, newRecord(offset, day.Add(12*time.Hour), "run-1", udm.EventTypeUserLogin))
	}
	insertQuarantine(t, db, registration.Name, "old", now.Add(-100*time.Hour))
	insertQuarantine(t, db, registration.Name, "recent", now.Add(-time.Hour))

	if err := expireDataset(t, store, db, registration.Name, now); err != nil {
		t.Fatalf("Expire: %v", err)
	}

	if dayPartitionExists(t, db, registration.Name, today.Add(-4*24*time.Hour)) {
		t.Error("Expire kept the partition that ended before the retention cutoff")
	}
	for offset := 3; offset >= 0; offset-- {
		if !dayPartitionExists(t, db, registration.Name, today.Add(-time.Duration(offset)*24*time.Hour)) {
			t.Errorf("Expire dropped the partition for day -%d", offset)
		}
	}
	if got := countEventRows(t, db, registration.Name); got != 4 {
		t.Errorf("dataset_events holds %d rows after Expire, want 4", got)
	}
	if exists := quarantineExists(t, db, "old"); exists {
		t.Error("Expire kept the quarantine row older than retention")
	}
	if exists := quarantineExists(t, db, "recent"); !exists {
		t.Error("Expire dropped the quarantine row inside retention")
	}
	if partitionDefinition(t, db, registration.Name) == "" {
		t.Error("Expire dropped the list partition")
	}
}

func TestExpireUnknownDataset(t *testing.T) {
	db := databasetest.New(t)
	store := NewPostgresStore(db)
	err := expireDataset(t, store, db, "missing", time.Now().UTC())
	if !errors.Is(err, ErrUnknownDataset) {
		t.Fatalf("Expire on a missing dataset = %v, want ErrUnknownDataset", err)
	}
}

func registerDataset(t *testing.T, store *PostgresStore, db *gorm.DB, registration Dataset) error {
	t.Helper()
	return db.Transaction(func(transaction *gorm.DB) error {
		return store.RegisterDataset(context.Background(), transaction, registration)
	})
}

func readDataset(t *testing.T, db *gorm.DB, name string) storedDataset {
	t.Helper()
	var row struct {
		Name             string     `gorm:"column:name"`
		PipelineID       string     `gorm:"column:pipeline_id"`
		RetentionSeconds int64      `gorm:"column:retention_seconds"`
		LatenessSeconds  int64      `gorm:"column:lateness_seconds"`
		Version          int        `gorm:"column:version"`
		FetchWatermark   *time.Time `gorm:"column:fetch_watermark"`
	}
	err := db.Raw(`
		SELECT name, pipeline_id,
		       EXTRACT(EPOCH FROM retention)::bigint AS retention_seconds,
		       EXTRACT(EPOCH FROM allowed_lateness)::bigint AS lateness_seconds,
		       version, fetch_watermark
		FROM datasets
		WHERE name = ?`, name).Scan(&row).Error
	if err != nil {
		t.Fatalf("read dataset %q: %v", name, err)
	}
	if row.Name == "" {
		t.Fatalf("dataset %q was not registered", name)
	}
	return storedDataset{
		PipelineID:      row.PipelineID,
		Retention:       time.Duration(row.RetentionSeconds) * time.Second,
		AllowedLateness: time.Duration(row.LatenessSeconds) * time.Second,
		Version:         row.Version,
		FetchWatermark:  row.FetchWatermark,
	}
}

func partitionDefinition(t *testing.T, db *gorm.DB, datasetName string) string {
	t.Helper()
	var row struct {
		KeyDefinition string `gorm:"column:key_definition"`
		Bound         string `gorm:"column:bound"`
	}
	err := db.Raw(`
		SELECT pg_get_partkeydef(class.oid) AS key_definition,
		       pg_get_expr(class.relpartbound, class.oid) AS bound
		FROM pg_class AS class
		WHERE class.oid = to_regclass(?)`, "ds_"+datasetName).Scan(&row).Error
	if err != nil {
		t.Fatalf("read partition definition for %q: %v", datasetName, err)
	}
	if row.KeyDefinition == "" {
		return ""
	}
	return row.KeyDefinition + "|" + row.Bound
}

func expireDataset(t *testing.T, store *PostgresStore, db *gorm.DB, datasetName string, now time.Time) error {
	t.Helper()
	return db.Transaction(func(transaction *gorm.DB) error {
		return store.Expire(context.Background(), transaction, datasetName, now)
	})
}

func insertQuarantine(t *testing.T, db *gorm.DB, datasetName, documentID string, createdAt time.Time) {
	t.Helper()
	err := db.Exec(`
		INSERT INTO dataset_quarantine
			(dataset, fetcher_instance_id, source_index, document_id, payload,
			 payload_truncated, errors, pipeline_run_id, created_at)
		VALUES (?, ?, ?, ?, ?, false, ?, ?, ?)`,
		datasetName, "fetcher", "logs", documentID, []byte("payload"),
		[]byte("[]"), "run-1", createdAt).Error
	if err != nil {
		t.Fatalf("insert quarantined record %q: %v", documentID, err)
	}
}

func createDayPartition(t *testing.T, db *gorm.DB, datasetName string, day time.Time) {
	t.Helper()
	statement := fmt.Sprintf(
		`CREATE TABLE "%s" PARTITION OF "%s" FOR VALUES FROM ('%s') TO ('%s')`,
		"ds_"+datasetName+"_"+day.Format("20060102"),
		"ds_"+datasetName,
		day.Format("2006-01-02"),
		day.Add(24*time.Hour).Format("2006-01-02"),
	)
	if err := db.Exec(statement).Error; err != nil {
		t.Fatalf("create day partition for %s: %v", day.Format("2006-01-02"), err)
	}
}

func insertEvent(t *testing.T, db *gorm.DB, datasetName string, record Record) {
	t.Helper()
	err := db.Exec(`
		INSERT INTO dataset_events
			(dataset, event_time, source_key_hash, fetcher_instance_id, source_index,
			 document_id, event_type, event, pipeline_run_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		datasetName, record.EventTime, record.Key.Hash(),
		record.Key.FetcherInstanceID, record.Key.Index, record.Key.DocumentID,
		string(record.Event.Metadata.EventType), []byte(`{}`), record.RunID).Error
	if err != nil {
		t.Fatalf("insert event %q: %v", record.Key.DocumentID, err)
	}
}

func quarantineExists(t *testing.T, db *gorm.DB, documentID string) bool {
	t.Helper()
	var exists bool
	err := db.Raw("SELECT EXISTS (SELECT 1 FROM dataset_quarantine WHERE document_id = ?)", documentID).
		Scan(&exists).Error
	if err != nil {
		t.Fatalf("look up quarantined record %q: %v", documentID, err)
	}
	return exists
}

func relationCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var count int64
	err := db.Raw(`
		SELECT count(*)
		FROM pg_class
		JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
		WHERE pg_namespace.nspname = current_schema() AND pg_class.relkind IN ('r', 'p')`).
		Scan(&count).Error
	if err != nil {
		t.Fatalf("count relations: %v", err)
	}
	return count
}

func (counter *statementCounter) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	statement, _ := fc()
	counter.mutex.Lock()
	counter.calls.Add(1)
	counter.statements = append(counter.statements, statement)
	counter.mutex.Unlock()
	counter.Interface.Trace(ctx, begin, fc, err)
}

func (counter *statementCounter) countStatements(fragment string) int {
	counter.mutex.Lock()
	defer counter.mutex.Unlock()
	count := 0
	for _, statement := range counter.statements {
		if strings.Contains(statement, fragment) {
			count++
		}
	}
	return count
}
