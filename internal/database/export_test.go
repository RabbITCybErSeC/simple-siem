package database

import (
	"context"
	"fmt"
	"io/fs"
	"slices"

	"github.com/pressly/goose/v3"
	"gorm.io/gorm"
)

// ReconcileMigrationAuditEventsForTest exposes reconciliation to database_test.
func ReconcileMigrationAuditEventsForTest(ctx context.Context, db *gorm.DB) error {
	return reconcileMigrationAuditEvents(ctx, db)
}

// EmbeddedMigrationVersionsForTest lists the versions of the embedded
// migrations in ascending order, so tests never hard-code the count.
func EmbeddedMigrationVersionsForTest() ([]int64, error) {
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	names, err := fs.Glob(migrations, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list embedded migrations: %w", err)
	}
	versions := make([]int64, 0, len(names))
	for _, name := range names {
		version, err := goose.NumericComponent(name)
		if err != nil {
			return nil, fmt.Errorf("parse embedded migration %s: %w", name, err)
		}
		versions = append(versions, version)
	}
	slices.Sort(versions)
	return versions, nil
}
