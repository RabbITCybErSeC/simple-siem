package database

import (
	"context"
	"embed"
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
	switch {
	case currentVersion > newestVersion:
		return fmt.Errorf(
			"database schema version %d is newer than the newest migration in this binary (%d)",
			currentVersion,
			newestVersion,
		)
	case currentVersion < newestVersion:
		return fmt.Errorf(
			"database schema version %d is behind the newest migration in this binary (%d)",
			currentVersion,
			newestVersion,
		)
	}
	return nil
}

// Migrate applies every pending migration under a PostgreSQL advisory lock and
// returns the versions it applied. Each applied version is audited in one
// transaction.
func Migrate(ctx context.Context, db *gorm.DB) ([]int64, error) {
	provider, currentVersion, newestVersion, err := newMigrationProvider(ctx, db)
	if err != nil {
		return nil, err
	}
	if currentVersion > newestVersion {
		return nil, fmt.Errorf(
			"database schema version %d is newer than the newest migration in this binary (%d)",
			currentVersion,
			newestVersion,
		)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	applied := make([]int64, 0, len(results))
	for _, result := range results {
		applied = append(applied, result.Source.Version)
	}
	if len(applied) > 0 {
		err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			for _, version := range applied {
				event := audit.Event{
					EventName:     "simple_siem.database.migration_applied",
					EventCategory: "DATABASE",
					EventOutcome:  "SUCCESS",
					ActorType:     "SYSTEM",
					TargetType:    "DATABASE_MIGRATION",
					TargetID:      strconv.FormatInt(version, 10),
					Action:        "apply",
				}
				if err := audit.Record(tx, event); err != nil {
					return fmt.Errorf("record migration %d: %w", version, err)
				}
			}
			return nil
		})
		if err != nil {
			return applied, fmt.Errorf("record applied migrations: %w", err)
		}
	}
	return applied, nil
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

// The driver can echo the DSN, password included, so strip both before the
// error leaves the package.
func openError(err error, databaseURL string) error {
	message := err.Error()
	if databaseURL != "" {
		message = strings.ReplaceAll(message, databaseURL, "[database]")
	}
	if parsed, parseError := url.Parse(databaseURL); parseError == nil && parsed.User != nil {
		if password, hasPassword := parsed.User.Password(); hasPassword && password != "" {
			message = strings.ReplaceAll(message, password, "[redacted]")
		}
	}
	return fmt.Errorf("open database: %s", message)
}
