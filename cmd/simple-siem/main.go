package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/detections"
	"github.com/RabbITCybErSeC/simple-siem/internal/api"
	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/detection"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher/elasticsearch"
	"github.com/RabbITCybErSeC/simple-siem/internal/pipeline"
	"github.com/RabbITCybErSeC/simple-siem/internal/version"
	"github.com/RabbITCybErSeC/simple-siem/web"
	"golang.org/x/term"
	"gorm.io/gorm"
)

const (
	topLevelUsage = `usage: simple-siem <command> [flags]

commands:
  serve    run the HTTP API
  migrate  apply pending database migrations
  admin    create or recover admin accounts
  config   validate the file configuration
  run      run one pipeline once
  detect   run one detection window or fixture
  version  print the version`

	serveUsage   = "usage: simple-siem serve [--migrate=true|false]"
	migrateUsage = "usage: simple-siem migrate"
	adminUsage   = `usage: simple-siem admin create --email <email> [--display-name <name>] [--password-file <path>]
usage: simple-siem admin reset-password --email <email> [--password-file <path>]`
	configUsage = "usage: simple-siem config validate [--config-dir DIR]"
	runUsage    = "usage: simple-siem run <pipeline-id> [--config-dir DIR]"
	detectUsage = `usage: simple-siem detect <detection-id> --window-end <RFC3339> [--config-dir DIR]
usage: simple-siem detect <detection-id> --fixture <path>`
	versionUsage = "usage: simple-siem version"

	defaultDisplayNameRunes = 200

	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second

	authPurgeInterval = 10 * time.Minute
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}

// run dispatches one command and returns the process exit status.
func run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
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
	case "admin":
		return runAdmin(ctx, args[1:], getenv, stdin, stdout, stderr, logger)
	case "config":
		return runConfig(args[1:], getenv, stdout, stderr)
	case "run":
		return runPipeline(ctx, args[1:], getenv, stdout, stderr)
	case "detect":
		return runDetect(ctx, args[1:], getenv, stdout, stderr)
	case "version":
		return runVersion(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintln(stderr, topLevelUsage)
		return 2
	}
}

// loadFileConfig loads and validates the file configuration, including the
// Phase 1 pipeline shape, every mapping, the Elasticsearch dialect of every
// query template, and every compiled detection against the loaded pipelines.
// Every command that loads file configuration must use it.
func loadFileConfig(directory string, environment config.Environment, getenv func(string) string) (config.Files, detection.Registry, error) {
	files, err := config.LoadFiles(directory, environment, getenv)
	if err != nil {
		return config.Files{}, detection.Registry{}, err
	}

	if err := pipeline.ValidateFiles(files); err != nil {
		return config.Files{}, detection.Registry{}, err
	}

	var templateProblems []error
	for _, id := range slices.Sorted(maps.Keys(files.QueryTemplates)) {
		template := files.QueryTemplates[id]
		if err := elasticsearch.ValidateQuery(template.RawQuery); err != nil {
			templateProblems = append(templateProblems, fmt.Errorf("query template %s: %w", template.File, err))
		}
	}
	if err := errors.Join(templateProblems...); err != nil {
		return config.Files{}, detection.Registry{}, err
	}

	registry, err := detection.ValidateRegistrations(detections.All, files)
	if err != nil {
		return config.Files{}, detection.Registry{}, err
	}
	return files, registry, nil
}

func runConfig(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		_, _ = fmt.Fprintln(stderr, configUsage)
		return 2
	}

	flags := newFlagSet("config validate", stderr, configUsage)
	directory := flags.String("config-dir", "config", "configuration directory")
	if status, done := parseFlags(flags, args[1:]); done {
		return status
	}

	environment, err := config.ParseEnvironment(getenv("SIMPLE_SIEM_ENV"))
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}

	files, registry, err := loadFileConfig(*directory, environment, getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	for _, id := range slices.Sorted(maps.Keys(registry.Inactive)) {
		_, _ = fmt.Fprintf(stderr, "warning: %s\n", registry.Inactive[id])
	}

	datasets := 0
	for _, pipeline := range files.Pipelines {
		datasets += len(pipeline.Outputs)
	}
	_, _ = fmt.Fprintf(stdout, "config valid: %s, %s, %s\n",
		countLabel(len(files.Fetchers), "fetcher instance"),
		countLabel(len(files.Pipelines), "pipeline"),
		countLabel(datasets, "dataset"))
	return 0
}

func countLabel(count int, singular string) string {
	if count == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %ss", count, singular)
}

// runPipeline runs one pipeline once and prints its result as one JSON line.
func runPipeline(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := newFlagSet("run", stderr, runUsage)
	directory := flags.String("config-dir", "config", "configuration directory")
	options, positionals := splitArguments(args, "config-dir")
	if err := flags.Parse(options); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(positionals) != 1 {
		flags.Usage()
		return 2
	}
	pipelineID := positionals[0]

	settings, err := config.Load(getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	files, _, err := loadFileConfig(*directory, settings.Environment, getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	// Keep stdout for the one result line; GORM and the runner log to stderr.
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	slog.SetDefault(logger)

	db, err := database.Open(ctx, settings)
	if err != nil {
		logger.Error("open database", "error", err)
		return 1
	}
	defer closeDatabase(db, logger)

	// One-shot runs apply pending migrations themselves so an operator does not
	// need a separate migrate step before the first run.
	if _, err := database.Migrate(ctx, db); err != nil {
		logger.Error("migrate database", "error", err)
		return 1
	}

	runner := &pipeline.Runner{
		Files:    files,
		Database: db,
		Store:    dataset.NewPostgresStore(db),
		NewFetcher: func(instance config.FetcherInstance) (fetcher.Fetcher, error) {
			return elasticsearch.New(instance, getenv)
		},
		Logger: logger,
	}
	result, err := runner.Run(ctx, pipelineID)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	if status := writeJSONLine(stdout, stderr, result); status != 0 {
		return status
	}

	switch result.Status {
	case pipeline.StatusOK, pipeline.StatusPartial, pipeline.StatusSkipped:
		return 0
	default:
		return 1
	}
}

// splitArguments separates flags from positional arguments so a flag may
// follow them, which the standard flag package does not allow. valueFlags
// names the flags that consume the next argument in their bare form; a flag
// written with an equals sign carries its own value.
func splitArguments(args []string, valueFlags ...string) (options []string, positionals []string) {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			return options, append(positionals, args[index+1:]...)
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			positionals = append(positionals, argument)
			continue
		}
		options = append(options, argument)
		name, _, hasValue := strings.Cut(strings.TrimLeft(argument, "-"), "=")
		if !hasValue && slices.Contains(valueFlags, name) && index+1 < len(args) {
			index++
			options = append(options, args[index])
		}
	}
	return options, positionals
}

// runDetect evaluates one detection window or fixture and prints one JSON
// result line.
func runDetect(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := newFlagSet("detect", stderr, detectUsage)
	windowEndValue := flags.String("window-end", "", "end of the window in RFC 3339")
	fixturePath := flags.String("fixture", "", "fixture file to evaluate")
	directory := flags.String("config-dir", "config", "configuration directory")
	options, positionals := splitArguments(args, "window-end", "fixture", "config-dir")
	if err := flags.Parse(options); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(positionals) != 1 || (*windowEndValue == "") == (*fixturePath == "") {
		flags.Usage()
		return 2
	}

	registration, manifest, known := findCompiledDetection(positionals[0])
	if !known {
		_, _ = fmt.Fprintf(stderr, "unknown detection %q\n", positionals[0])
		return 1
	}
	if *fixturePath != "" {
		return runDetectFixture(registration, manifest, *fixturePath, stdout, stderr)
	}

	windowEnd, err := time.Parse(time.RFC3339, *windowEndValue)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid --window-end %q: %v\n", *windowEndValue, err)
		return 2
	}
	if windowEnd.Nanosecond() != 0 {
		_, _ = fmt.Fprintf(stderr, "invalid --window-end %q: not a whole second\n", *windowEndValue)
		return 2
	}
	return runDetectWindow(ctx, registration, manifest, windowEnd, *directory, getenv, stdout, stderr)
}

// findCompiledDetection resolves one id from detections.All to its
// registration and parsed manifest.
func findCompiledDetection(id string) (detection.Registration, config.DetectionManifest, bool) {
	for _, registration := range detections.All {
		manifest, err := config.ParseDetectionManifest(registration.Manifest)
		if err != nil {
			continue
		}
		if manifest.ID == id {
			return registration, manifest, true
		}
	}
	return detection.Registration{}, config.DetectionManifest{}, false
}

// runDetectFixture evaluates a fixture without a database or file config.
func runDetectFixture(registration detection.Registration, manifest config.DetectionManifest, path string, stdout, stderr io.Writer) int {
	result, err := detection.EvaluateFixture(registration, manifest, path)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if status := writeJSONLine(stdout, stderr, result); status != 0 {
		return status
	}
	if !result.Passed {
		return 1
	}
	return 0
}

// runDetectWindow runs one window with the database and file configuration.
func runDetectWindow(ctx context.Context, registration detection.Registration, manifest config.DetectionManifest,
	windowEnd time.Time, directory string, getenv func(string) string, stdout, stderr io.Writer) int {
	settings, err := config.Load(getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, registry, err := loadFileConfig(directory, settings.Environment, getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	if warning, inactive := registry.Inactive[manifest.ID]; inactive {
		_, _ = fmt.Fprintln(stderr, warning)
		return 1
	}

	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	slog.SetDefault(logger)
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

	runner := &detection.Runner{
		Database: db,
		Store:    dataset.NewPostgresStore(db),
		Registry: registry,
		Logger:   logger,
	}
	result, err := runner.RunWindow(ctx, registration, windowEnd)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		if errors.Is(err, detection.ErrInputNotReady) {
			return 3
		}
		return 1
	}
	if status := writeJSONLine(stdout, stderr, result); status != 0 {
		return status
	}
	if result.Status == detection.RunStatusOK {
		return 0
	}
	return 1
}

// writeJSONLine prints one JSON result line and keeps encoding errors off
// stdout.
func writeJSONLine(stdout, stderr io.Writer, value any) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, string(encoded))
	return 0
}

func runAdmin(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer, logger *slog.Logger) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, adminUsage)
		return 2
	}
	switch args[0] {
	case "create":
		return runAdminCreate(ctx, args[1:], getenv, stdin, stdout, stderr, logger)
	case "reset-password":
		return runAdminResetPassword(ctx, args[1:], getenv, stdin, stdout, stderr, logger)
	default:
		_, _ = fmt.Fprintln(stderr, adminUsage)
		return 2
	}
}

// adminSetup is what both admin subcommands need once the configuration,
// database, schema, password, and service are ready.
type adminSetup struct {
	service  *auth.Service
	password string
	cleanup  func()
}

// openAdminSetup prepares an admin subcommand and reports false when a step
// fails; the caller runs cleanup when it is not nil.
func openAdminSetup(ctx context.Context, getenv func(string) string, stdin io.Reader, stderr io.Writer, logger *slog.Logger, passwordFile string) (*adminSetup, bool) {
	settings, err := config.Load(getenv)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return nil, false
	}

	db, err := database.Open(ctx, settings)
	if err != nil {
		logger.Error("open database", "error", err)
		return nil, false
	}
	cleanup := func() { closeDatabase(db, logger) }

	if err := database.CheckSchema(ctx, db); err != nil {
		logger.Error("check database schema", "error", err)
		cleanup()
		return nil, false
	}

	password, err := readPassword(stdin, passwordFile, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		cleanup()
		return nil, false
	}

	service, err := newAuthService(ctx, db, settings, logger)
	if err != nil {
		logger.Error("build auth service", "error", err)
		cleanup()
		return nil, false
	}
	return &adminSetup{service: service, password: password, cleanup: cleanup}, true
}

func runAdminCreate(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer, logger *slog.Logger) int {
	flags := newFlagSet("admin create", stderr, adminUsage)
	email := flags.String("email", "", "email address of the admin")
	displayName := flags.String("display-name", "", "display name (defaults to the part before @)")
	passwordFile := flags.String("password-file", "", "file whose first line is the password")
	if status, done := parseFlags(flags, args); done {
		return status
	}
	if *email == "" {
		flags.Usage()
		return 2
	}

	setup, ok := openAdminSetup(ctx, getenv, stdin, stderr, logger, *passwordFile)
	if !ok {
		return 1
	}
	defer setup.cleanup()

	name := *displayName
	if name == "" {
		if normalizedEmail, err := auth.NormalizeEmail(*email); err == nil {
			localPart, _, _ := strings.Cut(normalizedEmail, "@")
			if runes := []rune(localPart); len(runes) > defaultDisplayNameRunes {
				localPart = string(runes[:defaultDisplayNameRunes])
			}
			name = localPart
		}
	}
	user, err := setup.service.CreateAdmin(ctx, *email, name, setup.password)
	if err != nil {
		if isAdminInputError(err) {
			_, _ = fmt.Fprintln(stderr, err)
		} else {
			logger.Error("create admin", "error", err)
		}
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "created admin %s\n", user.ID)
	return 0
}

func runAdminResetPassword(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer, logger *slog.Logger) int {
	flags := newFlagSet("admin reset-password", stderr, adminUsage)
	email := flags.String("email", "", "email address of the admin")
	passwordFile := flags.String("password-file", "", "file whose first line is the new password")
	if status, done := parseFlags(flags, args); done {
		return status
	}
	if *email == "" {
		flags.Usage()
		return 2
	}

	setup, ok := openAdminSetup(ctx, getenv, stdin, stderr, logger, *passwordFile)
	if !ok {
		return 1
	}
	defer setup.cleanup()

	revokedCount, err := setup.service.ResetPassword(ctx, *email, setup.password)
	if err != nil {
		if isAdminInputError(err) {
			_, _ = fmt.Fprintln(stderr, err)
		} else {
			logger.Error("reset password", "error", err)
		}
		return 1
	}

	_, _ = fmt.Fprintf(stdout, "reset password for %s; revoked %d sessions\n", *email, revokedCount)
	return 0
}

// isAdminInputError reports whether the operator can fix the failure by
// changing the arguments.
func isAdminInputError(err error) bool {
	return errors.Is(err, auth.ErrInvalidEmail) || errors.Is(err, auth.ErrInvalidDisplayName) ||
		errors.Is(err, auth.ErrPasswordLength) || errors.Is(err, auth.ErrUserExists) ||
		errors.Is(err, auth.ErrUserNotFound)
}

// readPassword takes the first line of the password file, the terminal without
// echo, or the first line of stdin.
func readPassword(stdin io.Reader, passwordFile string, stderr io.Writer) (string, error) {
	source := stdin
	if passwordFile != "" {
		file, err := os.Open(passwordFile)
		if err != nil {
			return "", fmt.Errorf("open password file: %w", err)
		}
		defer func() { _ = file.Close() }()
		source = file
	} else if file, ok := stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		password, err := promptPassword(file, "Password: ", stderr)
		if err != nil {
			return "", err
		}
		repeated, err := promptPassword(file, "Repeat password: ", stderr)
		if err != nil {
			return "", err
		}
		if password == "" {
			return "", errors.New("no password given")
		}
		if password != repeated {
			return "", errors.New("passwords do not match")
		}
		return password, nil
	}

	line, err := bufio.NewReader(source).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password: %w", err)
	}
	if strings.HasSuffix(line, "\r\n") {
		line = strings.TrimSuffix(line, "\r\n")
	} else {
		line = strings.TrimSuffix(line, "\n")
	}
	if line == "" {
		return "", errors.New("no password given")
	}
	return line, nil
}

// promptPassword asks for one password on the terminal without echo and
// returns it as a string.
func promptPassword(file *os.File, prompt string, stderr io.Writer) (string, error) {
	_, _ = fmt.Fprint(stderr, prompt)
	password, err := term.ReadPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(password), nil
}

func newAuthService(ctx context.Context, db *gorm.DB, settings config.Config, logger *slog.Logger) (*auth.Service, error) {
	return auth.NewService(ctx, db, auth.Settings{
		IdleTimeout:      settings.SessionIdleTimeout,
		AbsoluteLifetime: settings.SessionAbsoluteLifetime,
	}, logger)
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

	authService, err := newAuthService(ctx, db, settings, logger)
	if err != nil {
		logger.Error("build auth service", "error", err)
		return 1
	}
	userCount, err := authService.CountUsers(ctx)
	if err != nil {
		logger.Error("count users", "error", err)
		return 1
	}
	if userCount == 0 {
		logger.Warn(`no users exist; run "simple-siem admin create --email <email>"`)
	}

	// shortcut: purge ticker in serve, move into the scheduler when Phase 3 lands
	go purgeExpiredAuthRows(ctx, authService, logger)

	sqlDatabase, err := db.DB()
	if err != nil {
		logger.Error("get database connection pool", "error", err)
		return 1
	}
	server := newHTTPServer(settings, sqlDatabase, db, authService, logger)
	return serveHTTP(ctx, server, settings.ShutdownTimeout)
}

// purgeExpiredAuthRows deletes stale auth rows once, then on every tick until
// the serve context ends. A failed pass is logged and retried on the next tick.
func purgeExpiredAuthRows(ctx context.Context, service *auth.Service, logger *slog.Logger) {
	purge := func() {
		result, err := service.PurgeExpired(ctx, time.Now())
		if err != nil {
			logger.Error("purge expired auth rows", "error", err)
			return
		}
		if result.LoginAttempts == 0 && result.Sessions == 0 && result.ResetTokens == 0 {
			return
		}
		logger.Info("purged expired auth rows",
			"login_attempts", result.LoginAttempts,
			"sessions", result.Sessions,
			"reset_tokens", result.ResetTokens,
		)
	}

	purge()
	ticker := time.NewTicker(authPurgeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purge()
		}
	}
}

func newHTTPServer(settings config.Config, database api.ReadinessChecker, auditDatabase *gorm.DB, authService *auth.Service, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr: settings.Listen,
		Handler: api.NewRouter(api.Dependencies{
			Database:       database,
			AuditDatabase:  auditDatabase,
			Logger:         logger,
			Auth:           authService,
			Web:            web.Files(),
			TrustedProxies: settings.TrustedProxies,
			PublicURL:      settings.PublicURL,
			Development:    settings.Environment == config.EnvironmentDevelopment,
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
