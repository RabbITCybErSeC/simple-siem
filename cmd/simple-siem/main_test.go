package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/version"
	"gorm.io/gorm"
)

const cliTestPassword = "correct horse battery"

func TestRunVersion(t *testing.T) {
	previousVersion := version.Version
	previousCommit := version.Commit
	version.Version = "v1.2.3"
	version.Commit = "abc1234"
	t.Cleanup(func() {
		version.Version = previousVersion
		version.Commit = previousCommit
	})

	tests := []struct {
		name       string
		args       []string
		wantStatus int
		wantStdout string
	}{
		{
			name:       "version command",
			args:       []string{"version"},
			wantStatus: 0,
			wantStdout: "simple-siem v1.2.3 (abc1234)\n",
		},
		{
			name:       "no command",
			wantStatus: 0,
			wantStdout: "simple-siem v1.2.3 (abc1234)\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			status := run(context.Background(), test.args, mapGetenv(nil), strings.NewReader(""), &stdout, &stderr)

			if status != test.wantStatus {
				t.Errorf("run() status = %d, want %d", status, test.wantStatus)
			}
			if got := stdout.String(); got != test.wantStdout {
				t.Errorf("run() stdout = %q, want %q", got, test.wantStdout)
			}
			if got := stderr.String(); got != "" {
				t.Errorf("run() stderr = %q, want empty", got)
			}
		})
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	status := run(context.Background(), []string{"frobnicate"}, mapGetenv(nil), strings.NewReader(""), &stdout, &stderr)

	if status != 2 {
		t.Errorf("run() status = %d, want 2", status)
	}
	if stdout.Len() != 0 {
		t.Errorf("run() stdout = %q, want empty", stdout.String())
	}
	for _, command := range []string{"serve", "migrate", "admin", "version"} {
		if !strings.Contains(stderr.String(), command) {
			t.Errorf("run() stderr %q does not list command %q", stderr.String(), command)
		}
	}
}

func TestRunUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer

	status := run(context.Background(), []string{"serve", "--no-such-flag"}, mapGetenv(nil), strings.NewReader(""), &stdout, &stderr)

	if status != 2 {
		t.Errorf("run() status = %d, want 2", status)
	}
	if stdout.Len() != 0 {
		t.Errorf("run() stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "no-such-flag") {
		t.Errorf("run() stderr %q does not name the unknown flag", stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage: simple-siem serve") {
		t.Errorf("run() stderr %q does not print the serve usage", stderr.String())
	}
}

func TestRunInvalidConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer

	status := run(context.Background(), []string{"serve"}, mapGetenv(nil), strings.NewReader(""), &stdout, &stderr)

	if status != 1 {
		t.Errorf("run() status = %d, want 1", status)
	}
	if !strings.Contains(stderr.String(), "SIMPLE_SIEM_DATABASE_URL") {
		t.Errorf("run() stderr %q does not name SIMPLE_SIEM_DATABASE_URL", stderr.String())
	}
}

func TestRunServeRefusesPendingSchema(t *testing.T) {
	_, databaseURL := databasetest.NewUnmigrated(t)
	getenv := mapGetenv(map[string]string{
		"SIMPLE_SIEM_ENV":          "development",
		"SIMPLE_SIEM_DATABASE_URL": databaseURL,
	})

	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"serve", "--migrate=false"}, getenv, strings.NewReader(""), &stdout, &stderr)

	if status != 1 {
		t.Fatalf("run() status = %d, want 1; stderr: %s", status, stderr.String())
	}
	if !strings.Contains(stdout.String(), "behind") {
		t.Errorf("run() stdout %q does not report the schema as behind", stdout.String())
	}
}

func TestRunMigrateAppliesPendingMigrations(t *testing.T) {
	testDatabase, databaseURL := databasetest.NewUnmigrated(t)
	getenv := mapGetenv(map[string]string{
		"SIMPLE_SIEM_ENV":          "development",
		"SIMPLE_SIEM_DATABASE_URL": databaseURL,
	})

	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"migrate"}, getenv, strings.NewReader(""), &stdout, &stderr)

	if status != 0 {
		t.Fatalf("run() status = %d, want 0; stdout: %s; stderr: %s", status, stdout.String(), stderr.String())
	}
	if err := database.CheckSchema(context.Background(), testDatabase); err != nil {
		t.Errorf("schema after migrate: %v", err)
	}
}

func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	server := newHTTPServer(config.Config{Listen: "127.0.0.1:0"}, nil, nil, logger)

	timeouts := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", server.ReadHeaderTimeout, readHeaderTimeout},
		{"ReadTimeout", server.ReadTimeout, readTimeout},
		{"WriteTimeout", server.WriteTimeout, writeTimeout},
		{"IdleTimeout", server.IdleTimeout, idleTimeout},
	}
	for _, timeout := range timeouts {
		if timeout.got != timeout.want {
			t.Errorf("server.%s = %s, want %s", timeout.name, timeout.got, timeout.want)
		}
	}
}

func TestServeHTTPCompletesInFlightRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		time.Sleep(time.Second)
		_, _ = writer.Write([]byte("done"))
	})
	server, address := newTestServer(t, handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitCode := make(chan int, 1)
	go func() { exitCode <- serveHTTP(ctx, server, 5*time.Second) }()
	waitForListener(t, address)

	type requestResult struct {
		statusCode int
		body       string
		err        error
	}
	results := make(chan requestResult, 1)
	go func() {
		response, err := http.Get("http://" + address + "/slow")
		if err != nil {
			results <- requestResult{err: err}
			return
		}
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		results <- requestResult{statusCode: response.StatusCode, body: string(body), err: err}
	}()

	waitForSignal(t, requestStarted, "request did not reach the handler")
	cancel()

	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("in-flight request failed: %v", result.err)
		}
		if result.statusCode != http.StatusOK {
			t.Errorf("in-flight request status = %d, want 200", result.statusCode)
		}
		if result.body != "done" {
			t.Errorf("in-flight request body = %q, want %q", result.body, "done")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not complete")
	}

	select {
	case code := <-exitCode:
		if code != 0 {
			t.Errorf("serveHTTP() status = %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTP did not return after the in-flight request completed")
	}
}

func TestServeHTTPTimeoutCutsOffRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		time.Sleep(5 * time.Second)
	})
	server, address := newTestServer(t, handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitCode := make(chan int, 1)
	go func() { exitCode <- serveHTTP(ctx, server, time.Second) }()
	waitForListener(t, address)

	go func() {
		response, err := http.Get("http://" + address + "/slow")
		if err == nil {
			_ = response.Body.Close()
		}
	}()

	waitForSignal(t, requestStarted, "request did not reach the handler")
	cancelledAt := time.Now()
	cancel()

	select {
	case code := <-exitCode:
		if code != 1 {
			t.Errorf("serveHTTP() status = %d, want 1", code)
		}
		if elapsed := time.Since(cancelledAt); elapsed > 2*time.Second {
			t.Errorf("serveHTTP took %s to stop, want about 1s", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTP did not return after the shutdown timeout")
	}
}

func TestAdminCreateFromStdin(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, stdout, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", " Admin@Example.com ")
	if status != 0 {
		t.Fatalf("admin create status = %d, want 0; stderr: %s", status, stderr)
	}
	if !strings.Contains(stdout, "created admin ") {
		t.Errorf("stdout = %q, want a created admin line", stdout)
	}
	if strings.Contains(stdout, cliTestPassword) || strings.Contains(stderr, cliTestPassword) {
		t.Errorf("output contains the password: stdout %q, stderr %q", stdout, stderr)
	}
	assertNoUserPassword(t, database, cliTestPassword)

	var user struct {
		ID          string
		Status      string
		DisplayName string
	}
	mustScan(t, database, &user,
		"SELECT id::text AS id, status, display_name FROM users WHERE email = ?", "admin@example.com")
	if user.ID == "" {
		t.Fatal("admin create wrote no user")
	}
	if user.Status != auth.StatusActive {
		t.Errorf("user status = %q, want %q", user.Status, auth.StatusActive)
	}
	if user.DisplayName != "admin" {
		t.Errorf("user display name = %q, want the email local part", user.DisplayName)
	}

	var roles int64
	mustScan(t, database, &roles,
		"SELECT count(*) FROM user_roles WHERE user_id = ? AND role_name = ?", user.ID, auth.RoleAdmin)
	if roles != 1 {
		t.Errorf("user has %d ADMIN roles, want 1", roles)
	}

	var events int64
	mustScan(t, database, &events,
		"SELECT count(*) FROM audit_events WHERE event_name = 'simple_siem.user.created'")
	if events != 1 {
		t.Errorf("admin create wrote %d user.created audit events, want 1", events)
	}
}

func TestAdminCreateFromPasswordFile(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)
	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte(cliTestPassword+"\r\n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	status, stdout, stderr := runAdminCommand(t, getenv, "",
		"create", "--email", "admin@example.com", "--password-file", passwordFile)
	if status != 0 {
		t.Fatalf("admin create status = %d, want 0; stderr: %s", status, stderr)
	}
	if strings.Contains(stdout, cliTestPassword) || strings.Contains(stderr, cliTestPassword) {
		t.Errorf("output contains the password: stdout %q, stderr %q", stdout, stderr)
	}

	service := newAdminTestService(t, database)
	result, err := service.Login(
		context.Background(),
		auth.LoginRequest{Email: "admin@example.com", Password: cliTestPassword},
		auth.ClientInfo{IP: net.ParseIP("192.0.2.7")},
	)
	if err != nil {
		t.Fatalf("login with the password file's first line: %v", err)
	}
	if result.User.Email != "admin@example.com" {
		t.Errorf("login user email = %q, want admin@example.com", result.User.Email)
	}
}

func TestAdminCreateRejectsShortPassword(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, "short pass1", "create", "--email", "admin@example.com")
	if status != 1 {
		t.Fatalf("admin create status = %d, want 1", status)
	}
	if !strings.Contains(stderr, "12 to 128") {
		t.Errorf("stderr = %q, want the password length rule", stderr)
	}

	var users int64
	mustScan(t, database, &users, "SELECT count(*) FROM users")
	if users != 0 {
		t.Errorf("admin create wrote %d users, want 0", users)
	}
}

func TestAdminCreateRejectsDuplicateEmail(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", "admin@example.com")
	if status != 0 {
		t.Fatalf("first admin create status = %d, want 0; stderr: %s", status, stderr)
	}
	var eventsBefore int64
	mustScan(t, database, &eventsBefore, "SELECT count(*) FROM audit_events")

	status, _, stderr = runAdminCommand(t, getenv, "another correct horse", "create", "--email", " Admin@Example.com ")
	if status != 1 {
		t.Fatalf("duplicate admin create status = %d, want 1", status)
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("stderr = %q, want the duplicate email message", stderr)
	}

	var eventsAfter int64
	mustScan(t, database, &eventsAfter, "SELECT count(*) FROM audit_events")
	if eventsAfter != eventsBefore {
		t.Errorf("duplicate admin create wrote %d audit events, want 0", eventsAfter-eventsBefore)
	}
}

func TestAdminCreateRejectsLongDisplayName(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword,
		"create", "--email", "admin@example.com", "--display-name", strings.Repeat("a", 201))
	if status != 1 {
		t.Fatalf("admin create with a long display name status = %d, want 1", status)
	}
	if !strings.Contains(stderr, "display name must be 1 to 200") {
		t.Errorf("stderr = %q, want the display name rule", stderr)
	}

	var users int64
	mustScan(t, database, &users, "SELECT count(*) FROM users")
	if users != 0 {
		t.Errorf("admin create wrote %d users, want 0", users)
	}
}

func TestAdminCreateCutsDefaultDisplayName(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)
	localPart := strings.Repeat("a", 210)
	email := localPart + "@example.com"

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", email)
	if status != 0 {
		t.Fatalf("admin create status = %d, want 0; stderr: %s", status, stderr)
	}

	var displayName string
	mustScan(t, database, &displayName, "SELECT display_name FROM users WHERE email = ?", email)
	if displayName != strings.Repeat("a", 200) {
		t.Errorf("display name = %q (%d runes), want 200 a's", displayName, len([]rune(displayName)))
	}
}

func TestAdminCreateRejectsNonASCIIEmail(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", "ÄDMIN@example.com")
	if status != 1 {
		t.Fatalf("admin create status = %d, want 1", status)
	}
	if stderr == "" {
		t.Error("admin create printed no error for a non-ASCII email")
	}

	var users int64
	mustScan(t, database, &users, "SELECT count(*) FROM users")
	if users != 0 {
		t.Errorf("admin create wrote %d users, want 0", users)
	}
}

func TestAdminCreateRejectsPasswordFlag(t *testing.T) {
	status, stdout, stderr := runAdminCommand(t, mapGetenv(nil), "",
		"create", "--email", "admin@example.com", "--password", "x")

	if status != 2 {
		t.Fatalf("admin create --password status = %d, want 2", status)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "usage: simple-siem admin create") {
		t.Errorf("stderr = %q, want the admin usage", stderr)
	}
}

func TestAdminCreateRequiresEmail(t *testing.T) {
	status, _, stderr := runAdminCommand(t, mapGetenv(nil), "", "create")

	if status != 2 {
		t.Fatalf("admin create without --email status = %d, want 2", status)
	}
	if !strings.Contains(stderr, "usage: simple-siem admin create") {
		t.Errorf("stderr = %q, want the admin usage", stderr)
	}
}

func TestAdminResetPasswordRevokesSessions(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", "admin@example.com")
	if status != 0 {
		t.Fatalf("admin create status = %d, want 0; stderr: %s", status, stderr)
	}

	service := newAdminTestService(t, database)
	client := auth.ClientInfo{IP: net.ParseIP("192.0.2.7")}
	var tokens []string
	for attempt := 1; attempt <= 2; attempt++ {
		result, err := service.Login(
			context.Background(),
			auth.LoginRequest{Email: "admin@example.com", Password: cliTestPassword},
			client,
		)
		if err != nil {
			t.Fatalf("login %d: %v", attempt, err)
		}
		tokens = append(tokens, result.Token)
	}

	const newPassword = "fresh correct horse"
	status, stdout, stderr := runAdminCommand(t, getenv, newPassword,
		"reset-password", "--email", "admin@example.com")
	if status != 0 {
		t.Fatalf("admin reset-password status = %d, want 0; stderr: %s", status, stderr)
	}
	if !strings.Contains(stdout, "revoked 2 sessions") {
		t.Errorf("stdout = %q, want two revoked sessions", stdout)
	}
	if strings.Contains(stdout, newPassword) || strings.Contains(stderr, newPassword) {
		t.Errorf("output contains the new password: stdout %q, stderr %q", stdout, stderr)
	}

	for index, token := range tokens {
		if _, err := service.Authenticate(context.Background(), token); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("session %d after reset: error = %v, want ErrUnauthenticated", index+1, err)
		}
	}

	if _, err := service.Login(
		context.Background(),
		auth.LoginRequest{Email: "admin@example.com", Password: newPassword},
		client,
	); err != nil {
		t.Errorf("login with the new password: %v", err)
	}
}

func TestAdminResetPasswordRejectsUnknownEmail(t *testing.T) {
	_, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, "fresh correct horse",
		"reset-password", "--email", "nobody@example.com")
	if status != 1 {
		t.Fatalf("admin reset-password status = %d, want 1", status)
	}
	if !strings.Contains(stderr, "no user with this email") {
		t.Errorf("stderr = %q, want the unknown email message", stderr)
	}
}

func TestRunServeWarnsWithoutUsers(t *testing.T) {
	_, baseGetenv := newAdminTestDatabase(t)
	address := reserveAddress(t)
	getenv := func(name string) string {
		if name == "SIMPLE_SIEM_LISTEN" {
			return address
		}
		return baseGetenv(name)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	exitCode := make(chan int, 1)
	go func() {
		exitCode <- run(ctx, []string{"serve"}, getenv, strings.NewReader(""), &stdout, &stderr)
	}()

	waitForListener(t, address)
	cancel()

	select {
	case status := <-exitCode:
		if status != 0 {
			t.Fatalf("serve status = %d, want 0; stderr: %s", status, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after the context was cancelled")
	}

	for _, fragment := range []string{"no users exist", "simple-siem admin create --email <email>"} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Errorf("stdout %q does not contain %q", stdout.String(), fragment)
		}
	}
}

func TestRunAdminUnknownSubcommand(t *testing.T) {
	status, stdout, stderr := runAdminCommand(t, mapGetenv(nil), "", "frobnicate")

	if status != 2 {
		t.Errorf("admin frobnicate status = %d, want 2", status)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	for _, usage := range []string{
		"usage: simple-siem admin create",
		"usage: simple-siem admin reset-password",
	} {
		if !strings.Contains(stderr, usage) {
			t.Errorf("stderr %q does not contain %q", stderr, usage)
		}
	}
}

func TestNewHTTPServerWiresAuthService(t *testing.T) {
	database, _ := newAdminTestDatabase(t)
	service := newAdminTestService(t, database)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	server := newHTTPServer(config.Config{Listen: "127.0.0.1:0"}, nil, service, logger)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/providers = %d, want 200: %s", response.Code, response.Body)
	}
	if got, want := response.Body.String(), `{"data":[{"id":"local"}]}`; got != want {
		t.Errorf("providers body = %s, want %s", got, want)
	}
}

func newAdminTestDatabase(t *testing.T) (*gorm.DB, func(string) string) {
	t.Helper()
	testDatabase, databaseURL := databasetest.NewUnmigrated(t)
	if _, err := database.Migrate(context.Background(), testDatabase); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return testDatabase, mapGetenv(map[string]string{
		"SIMPLE_SIEM_ENV":          "development",
		"SIMPLE_SIEM_DATABASE_URL": databaseURL,
	})
}

func newAdminTestService(t *testing.T, database *gorm.DB) *auth.Service {
	t.Helper()
	service, err := auth.NewService(
		context.Background(),
		database,
		auth.Settings{IdleTimeout: 30 * time.Minute, AbsoluteLifetime: 12 * time.Hour},
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service
}

func runAdminCommand(t *testing.T, getenv func(string) string, stdin string, args ...string) (status int, stdout, stderr string) {
	t.Helper()
	var stdoutBuffer, stderrBuffer bytes.Buffer
	status = run(context.Background(), append([]string{"admin"}, args...), getenv, strings.NewReader(stdin), &stdoutBuffer, &stderrBuffer)
	return status, stdoutBuffer.String(), stderrBuffer.String()
}

func mustScan(t *testing.T, database *gorm.DB, value any, query string, args ...any) {
	t.Helper()
	if err := database.Raw(query, args...).Scan(value).Error; err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
}

// assertNoUserPassword checks that no identity or audit row stores the password.
func assertNoUserPassword(t *testing.T, database *gorm.DB, password string) {
	t.Helper()
	var identityRows, auditRows string
	mustScan(t, database, &identityRows,
		"SELECT COALESCE(jsonb_agg(user_identities)::text, '') FROM user_identities")
	mustScan(t, database, &auditRows,
		"SELECT COALESCE(jsonb_agg(changes)::text, '') FROM audit_events")
	if strings.Contains(identityRows, password) {
		t.Errorf("user identities contain the password: %s", identityRows)
	}
	if strings.Contains(auditRows, password) {
		t.Errorf("audit changes contain the password: %s", auditRows)
	}
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return address
}

func mapGetenv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func newTestServer(t *testing.T, handler http.Handler) (*http.Server, string) {
	t.Helper()
	address := reserveAddress(t)
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 10 * time.Second}, address
}

func waitForListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.Dial("tcp", address)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s did not start listening", address)
}

func waitForSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal(message)
	}
}
