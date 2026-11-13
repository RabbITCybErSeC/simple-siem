package database

import (
	"context"

	"gorm.io/gorm"
)

// ReconcileMigrationAuditEventsForTest exposes reconciliation to database_test.
func ReconcileMigrationAuditEventsForTest(ctx context.Context, db *gorm.DB) error {
	return reconcileMigrationAuditEvents(ctx, db)
}
