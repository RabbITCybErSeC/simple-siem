package database

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

	// Reconciliation must finish even when the migrate context is cancelled,
	// and it must not wait for the goose session lock.
	reconcileTimeout = 30 * time.Second

	// Distinct from goose's own lock key (lock.DefaultLockID).
	migrationAuditLockKey = 4097083627

	migrationAuditEventName  = "simple_siem.database.migration_applied"
	migrationAuditTargetType = "DATABASE_MIGRATION"
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
	applied := appliedVersions(results, upErr)

	reconcileErr := reconcileMigrationAuditEvents(ctx, db)
	return applied, errors.Join(upErr, reconcileErr)
}

// appliedVersions returns the versions goose applied before it returned upErr.
// After a partial failure goose returns no results, only PartialError.Applied.
func appliedVersions(results []*goose.MigrationResult, upErr error) []int64 {
	var partial *goose.PartialError
	if errors.As(upErr, &partial) {
		results = partial.Applied
	}
	versions := make([]int64, 0, len(results))
	for _, result := range results {
		versions = append(versions, result.Source.Version)
	}
	return versions
}

// reconcileMigrationAuditEvents writes an event for every applied migration
// that has none yet. It reads goose's version table directly: the provider's
// status calls take the goose session lock, and a concurrent migrate would
// make reconciliation wait for it.
func reconcileMigrationAuditEvents(ctx context.Context, db *gorm.DB) error {
	reconcileContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), reconcileTimeout)
	defer cancel()

	return db.WithContext(reconcileContext).Transaction(func(tx *gorm.DB) error {
		// Until migration 00002 has run, no unique index stops two
		// reconcilers from writing the same event, so they take turns.
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", migrationAuditLockKey).Error; err != nil {
			return fmt.Errorf("lock migration audit events: %w", err)
		}

		var versions []int64
		err := tx.Raw(
			"SELECT version_id FROM goose_db_version WHERE is_applied AND version_id > 0 ORDER BY version_id",
		).Scan(&versions).Error
		if err != nil {
			return fmt.Errorf("read applied migrations: %w", err)
		}
		var recorded []string
		err = tx.Model(&audit.Event{}).
			Where("event_name = ?", migrationAuditEventName).
			Pluck("target_id", &recorded).Error
		if err != nil {
			return fmt.Errorf("read migration audit events: %w", err)
		}

		for _, version := range versions {
			targetID := strconv.FormatInt(version, 10)
			if slices.Contains(recorded, targetID) {
				continue
			}
			event := migrationAuditEvent(targetID)
			if err := audit.Record(tx.Clauses(clause.OnConflict{DoNothing: true}), event); err != nil {
				return fmt.Errorf("record migration %s: %w", targetID, err)
			}
		}
		return nil
	})
}

func migrationAuditEvent(targetID string) audit.Event {
	return audit.Event{
		EventName:     migrationAuditEventName,
		EventCategory: "DATABASE",
		EventOutcome:  "SUCCESS",
		ActorType:     "SYSTEM",
		TargetType:    migrationAuditTargetType,
		TargetID:      targetID,
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

	currentVersion, newestVersion, err := provider.GetVersions(ctx)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read database schema version: %w", err)
	}
	return provider, currentVersion, newestVersion, nil
}

// databasePassword returns the userinfo and password exactly as written in
// databaseURL, plus the decoded password. The driver may echo any of them.
func databasePassword(databaseURL string) (rawUserInfo, rawPassword, decodedPassword string, ok bool) {
	parsed, parseError := url.Parse(databaseURL)
	if parseError != nil || parsed.User == nil {
		return "", "", "", false
	}
	decodedPassword, hasPassword := parsed.User.Password()
	if !hasPassword || decodedPassword == "" {
		return "", "", "", false
	}
	schemeEnd := strings.Index(databaseURL, "://")
	if schemeEnd < 0 {
		return "", "", "", false
	}
	authority := databaseURL[schemeEnd+3:]
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return "", "", "", false
	}
	rawUserInfo = authority[:at]
	_, rawPassword, _ = strings.Cut(rawUserInfo, ":")
	return rawUserInfo, rawPassword, decodedPassword, true
}

// The driver can echo the DSN, password included, so strip the URL, the
// userinfo and password exactly as written, and the decoded password.
func openError(err error, databaseURL string) error {
	message := err.Error()
	if databaseURL != "" {
		message = strings.ReplaceAll(message, databaseURL, "[database]")
	}
	if rawUserInfo, rawPassword, decodedPassword, ok := databasePassword(databaseURL); ok {
		message = strings.ReplaceAll(message, rawUserInfo, "[redacted]")
		message = strings.ReplaceAll(message, rawPassword, "[redacted]")
		message = strings.ReplaceAll(message, decodedPassword, "[redacted]")
	}
	return fmt.Errorf("open database: %s", message)
}
