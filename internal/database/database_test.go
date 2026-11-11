package database_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"gorm.io/gorm"
)

func TestMigrateAppliesOnceConcurrently(t *testing.T) {
	db := databasetest.New(t)
	resetSchema(t, db)

	versions := make([][]int64, 2)
	errs := make([]error, 2)
	var wait sync.WaitGroup
	for index := range versions {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			versions[index], errs[index] = database.Migrate(context.Background(), db)
		}(index)
	}
	wait.Wait()

	applied := 0
	for index := range versions {
		if errs[index] != nil {
			t.Errorf("Migrate run %d: %v", index, errs[index])
		}
		applied += len(versions[index])
	}
	if applied != 1 {
		t.Errorf("applied %d versions across two runs, want 1: %v", applied, versions)
	}
	if got := countGooseVersion(t, db, 1); got != 1 {
		t.Errorf("migration 1 recorded %d times, want 1", got)
	}
}

func TestMigrateAlreadyApplied(t *testing.T) {
	db := databasetest.New(t)
	if got := countGooseVersion(t, db, 1); got != 1 {
		t.Fatalf("migration 1 recorded %d times after databasetest.New, want 1", got)
	}

	applied, err := database.Migrate(context.Background(), db)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("Migrate applied %v on an up-to-date database, want none", applied)
	}
	if got := countGooseVersion(t, db, 1); got != 1 {
		t.Errorf("migration 1 recorded %d times after a second run, want 1", got)
	}
}

func TestMigrateRefusesNewerSchema(t *testing.T) {
	db := databasetest.New(t)
	if err := db.Exec("INSERT INTO goose_db_version (version_id, is_applied) VALUES (?, ?)", 9999, true).Error; err != nil {
		t.Fatalf("record newer schema version: %v", err)
	}

	applied, err := database.Migrate(context.Background(), db)
	if err == nil {
		t.Fatal("Migrate accepted a database newer than the embedded migrations")
	}
	for _, version := range []string{"9999", "1"} {
		if !strings.Contains(err.Error(), version) {
			t.Errorf("Migrate error %q does not name version %s", err, version)
		}
	}
	if len(applied) != 0 {
		t.Errorf("Migrate applied %v while refusing a newer schema", applied)
	}
}

func TestOpenErrorDoesNotLeakPassword(t *testing.T) {
	password := "not-a-real-password-4f7c2"
	databaseURL := "postgres://test_user:" + password + "@127.0.0.1:1/test?sslmode=disable"

	_, err := database.Open(context.Background(), config.Config{DatabaseURL: databaseURL})
	if err == nil {
		t.Fatal("Open returned no error for an unreachable database")
	}
	if strings.Contains(err.Error(), password) {
		t.Errorf("Open error contains the password: %v", err)
	}
	if strings.Contains(err.Error(), databaseURL) {
		t.Errorf("Open error contains the database URL: %v", err)
	}
}

func TestCheckSchemaRejectsPendingMigration(t *testing.T) {
	db := databasetest.New(t)
	resetSchema(t, db)

	err := database.CheckSchema(context.Background(), db)
	if err == nil {
		t.Fatal("CheckSchema accepted a database with a pending migration")
	}
	for _, version := range []string{"0", "1"} {
		if !strings.Contains(err.Error(), version) {
			t.Errorf("CheckSchema error %q does not name version %s", err, version)
		}
	}
}

func TestCheckSchemaAllowsCurrentSchema(t *testing.T) {
	db := databasetest.New(t)

	if err := database.CheckSchema(context.Background(), db); err != nil {
		t.Errorf("CheckSchema on a fully migrated database: %v", err)
	}
}

func resetSchema(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, statement := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public"} {
		if err := db.Exec(statement).Error; err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

func countGooseVersion(t *testing.T, db *gorm.DB, version int64) int {
	t.Helper()
	var count int64
	if err := db.Raw("SELECT count(*) FROM goose_db_version WHERE version_id = ? AND is_applied", version).Scan(&count).Error; err != nil {
		t.Fatalf("count goose version %d: %v", version, err)
	}
	return int(count)
}
