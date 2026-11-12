package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

const (
	slowQueryThreshold = 200 * time.Millisecond
	pingTimeout        = 5 * time.Second
	maxOpenConnections = 20
	maxIdleConnections = 5
	connectionLifetime = 30 * time.Minute

	// The default locker retries every 5 seconds; retry each second and keep
	// the same five-minute window to acquire the lock.
	migrationLockRetrySeconds = 1
	migrationLockRetries      = 300

	// Audit reconciliation runs after the goose session lock is released, so
	// this transaction lock serialises concurrent Migrate runs and keeps each
	// migration to exactly one audit event.
	migrationAuditLockKey int64 = 4097083627
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Open connects GORM to PostgreSQL and refines the connection pool.
func Open(ctx context.Context, settings config.Config) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(settings.DatabaseURL), &gorm.Config{
		Logger: gormlogger.NewSlogLogger(slog.Default(), gormlogger.Config{
			SlowThreshold:        slowQueryThreshold,
			LogLevel:             gormlogger.Warn,
			ParameterizedQueries: true,
		}),
		TranslateError:       true,
		DisableAutomaticPing: true,
	})
	if err != nil {
		return nil, openError(err, settings.DatabaseURL)
	}

	sqlDatabase, err := db.DB()
	if err != nil {
		return nil, openError(err, settings.DatabaseURL)
	}
	sqlDatabase.SetMaxOpenConns(maxOpenConnections)
	sqlDatabase.SetMaxIdleConns(maxIdleConnections)
	sqlDatabase.SetConnMaxLifetime(connectionLifetime)

	pingContext, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := sqlDatabase.PingContext(pingContext); err != nil {
		_ = sqlDatabase.Close()
		return nil, openError(err, settings.DatabaseURL)
	}
	return db, nil
}

// CheckSchema fails unless the database schema exactly matches the newest
// migration embedded in this binary.
func CheckSchema(ctx context.Context, db *gorm.DB) error {
	_, currentVersion, newestVersion, err := newMigrationProvider(ctx, db)
	if err != nil {
		return err
	}
	if err := checkNewerSchema(currentVersion, newestVersion); err != nil {
		return err
	}
	if currentVersion < newestVersion {
		return fmt.Errorf(
			"database schema version %d is behind the newest migration in this binary (%d)",
			currentVersion,
			newestVersion,
		)
	}
	return nil
}

// Migrate applies every pending migration under a PostgreSQL advisory lock and
// returns the versions Up applied. After Up, whether it succeeded or failed
// partway, Migrate writes a migration_applied audit event for every applied
// version that has none yet, all in one transaction. It returns the Up error
// after that reconciliation, joined with any reconciliation error.
func Migrate(ctx context.Context, db *gorm.DB) ([]int64, error) {
	provider, currentVersion, newestVersion, err := newMigrationProvider(ctx, db)
	if err != nil {
		return nil, err
	}
	if err := checkNewerSchema(currentVersion, newestVersion); err != nil {
		return nil, err
	}

	results, upErr := provider.Up(ctx)
	applied := make([]int64, 0, len(results))
	for _, result := range results {
		applied = append(applied, result.Source.Version)
	}

	reconcileErr := reconcileMigrationAuditEvents(ctx, db, provider)
	if upErr != nil {
		upErr = fmt.Errorf("apply migrations: %w", upErr)
	}
	if reconcileErr != nil {
		reconcileErr = fmt.Errorf("reconcile migration audit events: %w", reconcileErr)
	}
	if err := errors.Join(upErr, reconcileErr); err != nil {
		return applied, err
	}
	return applied, nil
}

// reconcileMigrationAuditEvents writes an event for every applied migration
// that has none yet.
func reconcileMigrationAuditEvents(ctx context.Context, db *gorm.DB, provider *goose.Provider) error {
	statuses, err := provider.Status(ctx)
	if err != nil {
		return fmt.Errorf("read migration status: %w", err)
	}
	versions := make([]int64, 0, len(statuses))
	for _, status := range statuses {
		if status.State == goose.StateApplied {
			versions = append(versions, status.Source.Version)
		}
	}
	if len(versions) == 0 {
		return nil
	}

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", migrationAuditLockKey).Error; err != nil {
			return fmt.Errorf("lock migration audit reconciliation: %w", err)
		}
		for _, version := range versions {
			targetID := strconv.FormatInt(version, 10)
			var existing int64
			err := tx.Model(&audit.Event{}).
				Where("target_type = ? AND target_id = ?", "DATABASE_MIGRATION", targetID).
				Count(&existing).Error
			if err != nil {
				return fmt.Errorf("count migration %d audit events: %w", version, err)
			}
			if existing > 0 {
				continue
			}
			if err := audit.Record(tx, migrationAuditEvent(version)); err != nil {
				return fmt.Errorf("record migration %d: %w", version, err)
			}
		}
		return nil
	})
}

func migrationAuditEvent(version int64) audit.Event {
	return audit.Event{
		EventName:     "simple_siem.database.migration_applied",
		EventCategory: "DATABASE",
		EventOutcome:  "SUCCESS",
		ActorType:     "SYSTEM",
		TargetType:    "DATABASE_MIGRATION",
		TargetID:      strconv.FormatInt(version, 10),
		Action:        "apply",
	}
}

// checkNewerSchema refuses a database whose schema is newer than this binary.
func checkNewerSchema(currentVersion, newestVersion int64) error {
	if currentVersion > newestVersion {
		return fmt.Errorf(
			"database schema version %d is newer than the newest migration in this binary (%d)",
			currentVersion,
			newestVersion,
		)
	}
	return nil
}

// newMigrationProvider builds the goose provider and reads the current and
// newest migration versions; Migrate and CheckSchema both need them.
func newMigrationProvider(ctx context.Context, db *gorm.DB) (*goose.Provider, int64, int64, error) {
	sqlDatabase, err := db.DB()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("get database connection pool: %w", err)
	}

	sessionLocker, err := lock.NewPostgresSessionLocker(
		lock.WithLockTimeout(migrationLockRetrySeconds, migrationLockRetries),
	)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("create migration lock: %w", err)
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read embedded migrations: %w", err)
	}
	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		sqlDatabase,
		migrations,
		goose.WithSessionLocker(sessionLocker),
	)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("create migration provider: %w", err)
	}

	sources := provider.ListSources()
	newestVersion := sources[len(sources)-1].Version
	currentVersion, err := provider.GetDBVersion(ctx)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read database schema version: %w", err)
	}
	return provider, currentVersion, newestVersion, nil
}

// The driver can echo the DSN, password included, so strip both the decoded and
// percent-encoded userinfo before the error leaves the package.
func openError(err error, databaseURL string) error {
	message := err.Error()
	if databaseURL != "" {
		message = strings.ReplaceAll(message, databaseURL, "[database]")
	}
	if parsed, parseError := url.Parse(databaseURL); parseError == nil && parsed.User != nil {
		userInfo := parsed.User.String()
		message = strings.ReplaceAll(message, userInfo, "[redacted]")
		if password, hasPassword := parsed.User.Password(); hasPassword && password != "" {
			message = strings.ReplaceAll(message, password, "[redacted]")
			_, encodedPassword, _ := strings.Cut(userInfo, ":")
			message = strings.ReplaceAll(message, encodedPassword, "[redacted]")
		}
	}
	return fmt.Errorf("open database: %s", message)
}
