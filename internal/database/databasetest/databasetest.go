// Package databasetest gives integration tests a migrated PostgreSQL database
// of their own.
package databasetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database"
	"gorm.io/gorm"
)

// New creates a uniquely named database, migrates it, and drops it when the
// test finishes. It fails instead of skipping when PostgreSQL is unreachable.
func New(t *testing.T) *gorm.DB {
	t.Helper()
	testDatabase, _ := NewUnmigrated(t)
	if _, err := database.Migrate(context.Background(), testDatabase); err != nil {
		t.Fatalf("databasetest: migrate test database: %v", err)
	}
	return testDatabase
}

// NewUnmigrated creates a uniquely named database without applying migrations
// and returns it with its connection URL. It drops the database when the test
// finishes and fails instead of skipping when PostgreSQL is unreachable.
func NewUnmigrated(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	checkEnvironment(t)

	name := databaseName(t)
	databaseURL := connectionURL(name)
	adminURL := connectionURL(os.Getenv("POSTGRES_DB"))

	admin, err := database.Open(context.Background(), config.Config{DatabaseURL: adminURL})
	if err != nil {
		t.Fatalf("databasetest: connect to PostgreSQL: %v", err)
	}
	adminDatabase, err := admin.DB()
	if err != nil {
		t.Fatalf("databasetest: get PostgreSQL connection pool: %v", err)
	}
	defer func() { _ = adminDatabase.Close() }()

	if err := admin.Exec("CREATE DATABASE " + name).Error; err != nil {
		t.Fatalf("databasetest: create database %s: %v", name, err)
	}

	var testDatabase *gorm.DB
	t.Cleanup(func() {
		if testDatabase != nil {
			if sqlDatabase, err := testDatabase.DB(); err == nil {
				_ = sqlDatabase.Close()
			}
		}
		dropDatabase(t, adminURL, name)
	})

	testDatabase, err = database.Open(context.Background(), config.Config{DatabaseURL: databaseURL})
	if err != nil {
		t.Fatalf("databasetest: connect to database %s: %v", name, err)
	}
	return testDatabase, databaseURL
}

func checkEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"POSTGRES_HOST", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"} {
		if os.Getenv(name) == "" {
			t.Fatalf("databasetest: %s is not set; run tests through make", name)
		}
	}
}

func connectionURL(databaseName string) string {
	address := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD")),
		Host:   net.JoinHostPort(os.Getenv("POSTGRES_HOST"), "5432"),
		Path:   "/" + databaseName,
	}
	query := address.Query()
	query.Set("sslmode", "disable")
	address.RawQuery = query.Encode()
	return address.String()
}

func databaseName(t *testing.T) string {
	t.Helper()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("databasetest: generate database name: %v", err)
	}
	return "test_" + sanitizedName(t.Name()) + "_" + hex.EncodeToString(suffix)
}

func sanitizedName(name string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(name) {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
	}
	sanitized := builder.String()
	if len(sanitized) > 32 {
		sanitized = sanitized[:32]
	}
	return sanitized
}

func dropDatabase(t *testing.T, adminURL, name string) {
	t.Helper()
	admin, err := database.Open(context.Background(), config.Config{DatabaseURL: adminURL})
	if err != nil {
		t.Errorf("databasetest: connect to PostgreSQL to drop %s: %v", name, err)
		return
	}
	adminDatabase, err := admin.DB()
	if err != nil {
		t.Errorf("databasetest: get PostgreSQL connection pool to drop %s: %v", name, err)
		return
	}
	defer func() { _ = adminDatabase.Close() }()

	if err := admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)").Error; err != nil {
		t.Errorf("databasetest: drop database %s: %v", name, err)
	}
}
