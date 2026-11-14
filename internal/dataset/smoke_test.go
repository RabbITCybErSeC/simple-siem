package dataset

import (
	"context"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
	"gorm.io/gorm"
)

func TestSmokeBudget(t *testing.T) {
	db := databasetest.New(t)
	var store Store = NewPostgresStore(db)
	ctx := context.Background()
	registration := Dataset{
		Name:            "smoke_events",
		PipelineID:      "smoke",
		Retention:       72 * time.Hour,
		AllowedLateness: 10 * time.Minute,
	}
	err := db.Transaction(func(transaction *gorm.DB) error {
		return store.RegisterDataset(ctx, transaction, registration)
	})
	if err != nil {
		t.Fatalf("RegisterDataset: %v", err)
	}
	t.Logf("smoke dataset %s registered", registration.Name)

	const (
		recordCount = 50000
		batchSize   = 5000
	)
	base := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	records := make([]Record, recordCount)
	for index := range records {
		records[index] = newRecord(index, base.Add(time.Duration(index)*10*time.Millisecond), "smoke-run", udm.EventTypeUserLogin)
	}

	writeStart := time.Now()
	for start := 0; start < recordCount; start += batchSize {
		batch := Batch{
			RunID:          "smoke-run",
			Records:        records[start : start+batchSize],
			FetchWatermark: base.Add(time.Hour),
		}
		err := db.Transaction(func(transaction *gorm.DB) error {
			return store.WriteBatch(ctx, transaction, registration.Name, batch)
		})
		if err != nil {
			t.Fatalf("WriteBatch: %v", err)
		}
	}
	writeDuration := time.Since(writeStart)
	writeRate := float64(recordCount) / writeDuration.Seconds()
	t.Logf("wrote %d records in %s (%.0f records/s)", recordCount, writeDuration, writeRate)
	if writeRate < 1000 {
		t.Fatalf("write rate %.0f records/s is below the 1000 records/s budget", writeRate)
	}

	readStart := time.Now()
	var firstRow time.Duration
	read := 0
	for _, err := range store.ReadWindow(ctx, registration.Name, base, base.Add(time.Hour), Filter{}) {
		if err != nil {
			t.Fatalf("ReadWindow: %v", err)
		}
		if read == 0 {
			firstRow = time.Since(readStart)
		}
		read++
	}
	t.Logf("read %d records; first row after %s", read, firstRow)
	if read != recordCount {
		t.Fatalf("ReadWindow returned %d records, want %d", read, recordCount)
	}
	if firstRow > 2*time.Second {
		t.Fatalf("first row took %s, want at most 2s", firstRow)
	}
}
