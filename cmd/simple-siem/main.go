package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/api"
	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database"
	"github.com/RabbITCybErSeC/simple-siem/internal/version"
	"github.com/RabbITCybErSeC/simple-siem/web"
	"gorm.io/gorm"
)

const (
	topLevelUsage = `usage: simple-siem <command> [flags]

commands:
  serve    run the HTTP API
  migrate  apply pending database migrations
  version  print the version`

	serveUsage   = "usage: simple-siem serve [--migrate=true|false]"
	migrateUsage = "usage: simple-siem migrate"
	versionUsage = "usage: simple-siem version"

	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run dispatches one command and returns the process exit status.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	logger := slog.New(slog.NewJSONHandler(stdout, nil))
	slog.SetDefault(logger)

	if len(args) == 0 {
		printVersion(stdout)
		return 0
	}

	switch args[0] {
	case "serve":
		return runServe(ctx, args[1:], getenv, stderr, logger)
	case "migrate":
		return runMigrate(ctx, args[1:], getenv, stderr, logger)
	case "version":
		return runVersion(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintln(stderr, topLevelUsage)
		return 2
	}
}

func runServe(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, logger *slog.Logger) int {
	flags := newFlagSet("serve", stderr, serveUsage)
	applyMigrations := flags.Bool("migrate", true, "apply pending database migrations before serving")
	if status, done := parseFlags(flags, args); done {
		return status
	}

	settings, err := config.Load(getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	db, err := database.Open(ctx, settings)
	if err != nil {
		logger.Error("open database", "error", err)
		return 1
	}
	defer closeDatabase(db, logger)

	if *applyMigrations {
		if _, err := database.Migrate(ctx, db); err != nil {
			logger.Error("migrate database", "error", err)
			return 1
		}
	} else if err := database.CheckSchema(ctx, db); err != nil {
		logger.Error("check database schema", "error", err)
		return 1
	}

	server := newHTTPServer(settings, db, logger)
	return serveHTTP(ctx, server, settings.ShutdownTimeout)
}

func newHTTPServer(settings config.Config, db *gorm.DB, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr: settings.Listen,
		Handler: api.NewRouter(api.Dependencies{
			DB:             db,
			Logger:         logger,
			Web:            web.Files(),
			TrustedProxies: settings.TrustedProxies,
			Version:        version.Version,
			Commit:         version.Commit,
		}),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

func runMigrate(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, logger *slog.Logger) int {
	flags := newFlagSet("migrate", stderr, migrateUsage)
	if status, done := parseFlags(flags, args); done {
		return status
	}

	settings, err := config.Load(getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	db, err := database.Open(ctx, settings)
	if err != nil {
		logger.Error("open database", "error", err)
		return 1
	}
	defer closeDatabase(db, logger)

	if _, err := database.Migrate(ctx, db); err != nil {
		logger.Error("migrate database", "error", err)
		return 1
	}
	return 0
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("version", stderr, versionUsage)
	if status, done := parseFlags(flags, args); done {
		return status
	}

	printVersion(stdout)
	return 0
}

func printVersion(stdout io.Writer) {
	_, _ = fmt.Fprintf(stdout, "simple-siem %s\n", version.String())
}

func newFlagSet(name string, stderr io.Writer, usage string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { _, _ = fmt.Fprintln(stderr, usage) }
	return flags
}

func parseFlags(flags *flag.FlagSet, args []string) (status int, done bool) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return 2, true
	}
	if flags.NArg() > 0 {
		flags.Usage()
		return 2, true
	}
	return 0, false
}

// serveHTTP runs server until ctx is cancelled, then stops accepting requests
// and lets in-flight requests finish within the timeout.
func serveHTTP(ctx context.Context, server *http.Server, timeout time.Duration) int {
	listenErrors := make(chan error, 1)
	go func() { listenErrors <- server.ListenAndServe() }()

	select {
	case <-ctx.Done():
	case err := <-listenErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server", "error", err)
			return 1
		}
		return 0
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		_ = server.Close()
		slog.Error("shutdown http server", "error", err)
		return 1
	}
	return 0
}

func closeDatabase(db *gorm.DB, logger *slog.Logger) {
	sqlDatabase, err := db.DB()
	if err != nil {
		logger.Error("get database connection pool", "error", err)
		return
	}
	if err := sqlDatabase.Close(); err != nil {
		logger.Error("close database connection pool", "error", err)
	}
}
