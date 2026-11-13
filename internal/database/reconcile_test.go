package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/database"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/pressly/goose/v3/lock"
	"gorm.io/gorm"
)

const migrationAppliedEvent = "simple_siem.database.migration_applied"

func TestReconcileWritesEventWhenVersionHasOtherEvent(t *testing.T) {
	db := databasetest.New(t)
	deleteMigrationAppliedEvents(t, db, "1")
	if err := audit.Record(db, otherDatabaseEvent("1")); err != nil {
		t.Fatalf("record the other event: %v", err)
	}

	err := database.ReconcileMigrationAuditEventsForTest(context.Background(), db)

	if err != nil {
		t.Fatalf("reconcile migration audit events: %v", err)
	}
	if got := countMigrationAppliedEvents(t, db, "1"); got != 1 {
		t.Errorf("migration 1 has %d migration_applied events, want 1", got)
	}
}

func TestReconcileWritesMissingEventWithCancelledContext(t *testing.T) {
	db := databasetest.New(t)
	deleteMigrationAppliedEvents(t, db, "1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := database.ReconcileMigrationAuditEventsForTest(ctx, db)

	if err != nil {
		t.Fatalf("reconcile migration audit events: %v", err)
	}
	if got := countMigrationAppliedEvents(t, db, "1"); got != 1 {
		t.Errorf("migration 1 has %d migration_applied events, want 1", got)
	}
}

func TestReconcileDoesNotWaitForMigrationLock(t *testing.T) {
	db := databasetest.New(t)
	deleteMigrationAppliedEvents(t, db, "1")

	sqlDatabase, err := db.DB()
	if err != nil {
		t.Fatalf("get database connection pool: %v", err)
	}
	lockConnection, err := sqlDatabase.Conn(context.Background())
	if err != nil {
		t.Fatalf("reserve a lock connection: %v", err)
	}
	if _, err := lockConnection.ExecContext(context.Background(), "SELECT pg_advisory_lock($1)", lock.DefaultLockID); err != nil {
		t.Fatalf("hold the goose migration lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = lockConnection.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", lock.DefaultLockID)
		_ = lockConnection.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	err = database.ReconcileMigrationAuditEventsForTest(ctx, db)
	elapsed := time.Since(started)

	if err != nil {
		t.Fatalf("reconcile migration audit events while the goose lock is held: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("reconcile took %s while the goose lock was held, want a few seconds at most", elapsed)
	}
	if got := countMigrationAppliedEvents(t, db, "1"); got != 1 {
		t.Errorf("migration 1 has %d migration_applied events, want 1", got)
	}
}

func TestReconcileSkipsMigrationThatNeverRan(t *testing.T) {
	db := databasetest.New(t)
	deleteMigrationAppliedEvents(t, db, "1")
	if err := db.Exec("DELETE FROM goose_db_version WHERE version_id = 1").Error; err != nil {
		t.Fatalf("remove migration 1 from the goose version table: %v", err)
	}

	err := database.ReconcileMigrationAuditEventsForTest(context.Background(), db)

	if err != nil {
		t.Fatalf("reconcile migration audit events: %v", err)
	}
	if got := countMigrationAppliedEvents(t, db, "1"); got != 0 {
		t.Errorf("migration 1 never ran but has %d migration_applied events, want 0", got)
	}
}

func otherDatabaseEvent(targetID string) audit.Event {
	return audit.Event{
		EventName:     "simple_siem.test.other_database_event",
		EventCategory: "DATABASE",
		EventOutcome:  "SUCCESS",
		ActorType:     "SYSTEM",
		TargetType:    "DATABASE_MIGRATION",
		TargetID:      targetID,
		Action:        "test",
	}
}

func deleteMigrationAppliedEvents(t *testing.T, db *gorm.DB, targetID string) {
	t.Helper()
	err := db.Exec(
		"DELETE FROM audit_events WHERE event_name = ? AND target_id = ?",
		migrationAppliedEvent,
		targetID,
	).Error
	if err != nil {
		t.Fatalf("delete migration_applied event for version %s: %v", targetID, err)
	}
}

func countMigrationAppliedEvents(t *testing.T, db *gorm.DB, targetID string) int64 {
	t.Helper()
	var count int64
	err := db.Raw(
		"SELECT count(*) FROM audit_events WHERE event_name = ? AND target_id = ?",
		migrationAppliedEvent,
		targetID,
	).Scan(&count).Error
	if err != nil {
		t.Fatalf("count migration_applied events for version %s: %v", targetID, err)
	}
	return count
}
