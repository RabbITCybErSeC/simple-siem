package dataset

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
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

// statementCounter counts the statements GORM sends through the session.
type statementCounter struct {
	gormlogger.Interface
	calls atomic.Int64
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
	store := &PostgresStore{}
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
	store := &PostgresStore{}
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

func TestRegisterDatasetRejectsHostileNames(t *testing.T) {
	db := databasetest.New(t)
	counter := &statementCounter{Interface: db.Logger}
	counting := db.Session(&gorm.Session{Logger: counter})
	store := &PostgresStore{}
	before := relationCount(t, db)

	names := []string{"x; DROP TABLE datasets", `x"`, "A", strings.Repeat("a", 41)}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			err := store.RegisterDataset(context.Background(), counting, Dataset{
				Name:       name,
				PipelineID: "auth-events",
				Retention:  time.Hour,
			})
			if !errors.Is(err, ErrInvalidDatasetName) {
				t.Fatalf("RegisterDataset(%q) = %v, want ErrInvalidDatasetName", name, err)
			}
		})
	}

	if calls := counter.calls.Load(); calls != 0 {
		t.Errorf("RegisterDataset sent %d statements for invalid names, want none", calls)
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
	counter.calls.Add(1)
	counter.Interface.Trace(ctx, begin, fc, err)
}
