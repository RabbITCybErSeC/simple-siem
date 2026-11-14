package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
)

const (
	testEmail    = "admin@example.com"
	testPassword = "correct horse battery"
)

type testService struct {
	service  *Service
	database *gorm.DB
	logs     *bytes.Buffer
}

func newTestService(t *testing.T) testService {
	t.Helper()
	database := databasetest.New(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	service, err := NewService(
		context.Background(),
		database,
		Settings{IdleTimeout: 30 * time.Minute, AbsoluteLifetime: 12 * time.Hour},
		logger,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return testService{service: service, database: database, logs: &logs}
}

func (test testService) createAdmin(t *testing.T, email string) User {
	t.Helper()
	user, err := test.service.CreateAdmin(context.Background(), email, "Admin User", testPassword)
	if err != nil {
		t.Fatalf("CreateAdmin(%q): %v", email, err)
	}
	return user
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		want    string
		wantErr bool
	}{
		{"surrounding spaces and case", " Admin@Example.com ", "admin@example.com", false},
		{"non-ascii local part", "ÄDMIN@example.com", "", true},
		{"kelvin sign local part", "\u212ADMIN@example.com", "", true},
		{"display name form", "Admin <admin@example.com>", "", true},
		{"two bytes", "a@", "", true},
		{"three bytes", "a@b", "a@b", false},
		{"254 bytes", strings.Repeat("a", 242) + "@example.com", strings.Repeat("a", 242) + "@example.com", false},
		{"255 bytes", strings.Repeat("a", 243) + "@example.com", "", true},
		{"control character", "admin\n@example.com", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeEmail(test.email)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidEmail) {
					t.Fatalf("NormalizeEmail(%q) error = %v, want ErrInvalidEmail", test.email, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeEmail(%q) error = %v, want nil", test.email, err)
			}
			if got != test.want {
				t.Errorf("NormalizeEmail(%q) = %q, want %q", test.email, got, test.want)
			}
		})
	}
}

func TestNormalizeDisplayName(t *testing.T) {
	tests := []struct {
		name    string
		display string
		want    string
		wantErr bool
	}{
		{"surrounding spaces", " Alice ", "Alice", false},
		{"empty", "", "", true},
		{"spaces only", "   ", "", true},
		{"200 runes", strings.Repeat("é", 200), strings.Repeat("é", 200), false},
		{"201 runes", strings.Repeat("é", 201), "", true},
		{"tab inside", "Ali\tce", "", true},
		{"null inside", "Ali\x00ce", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeDisplayName(test.display)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidDisplayName) {
					t.Fatalf("NormalizeDisplayName(%q) error = %v, want ErrInvalidDisplayName", test.display, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDisplayName(%q) error = %v, want nil", test.display, err)
			}
			if got != test.want {
				t.Errorf("NormalizeDisplayName(%q) = %q, want %q", test.display, got, test.want)
			}
		})
	}
}

func TestCreateAdminRejectsInvalidDisplayName(t *testing.T) {
	test := newTestService(t)
	usersBefore := countRows(t, test.database, "users")
	eventsBefore := countRows(t, test.database, "audit_events")

	_, err := test.service.CreateAdmin(
		context.Background(), testEmail, strings.Repeat("a", 201), testPassword,
	)
	if !errors.Is(err, ErrInvalidDisplayName) {
		t.Fatalf("CreateAdmin with a 201-rune display name = %v, want ErrInvalidDisplayName", err)
	}
	if got := countRows(t, test.database, "users"); got != usersBefore {
		t.Errorf("users count = %d, want %d", got, usersBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d, want %d", got, eventsBefore)
	}
}

func TestRolesRejectDelimiterInName(t *testing.T) {
	test := newTestService(t)
	err := test.database.Exec(
		"INSERT INTO roles (name, description) VALUES ('READ,WRITE', 'invalid role')",
	).Error
	if err == nil {
		t.Fatal("inserting a role named READ,WRITE succeeded, want a check constraint violation")
	}
	if !strings.Contains(err.Error(), "roles_name_check") {
		t.Errorf("inserting READ,WRITE error = %v, want the roles_name_check violation", err)
	}
}

// TestDefaultRolePermissions compares the migration with a second,
// independent copy of the reviewed mapping in rbac-admin-api decision 3.
func TestDefaultRolePermissions(t *testing.T) {
	test := newTestService(t)
	want := map[string][]string{
		RoleAdmin: {
			"alert:read",
			"audit:read",
			"case:close",
			"case:merge",
			"case:read",
			"case:write",
			"config:read",
			"config:write",
			"dataset:read",
			"detection:read",
			"detection:reload",
			"detection:run",
			"detection:write",
			"pipeline:read",
			"pipeline:run",
			"pipeline:write",
			"role:assign",
			"suppression:broad_write",
			"suppression:read",
			"suppression:write",
			"tag:manage",
			"task:read",
			"task:write",
			"template:write",
			"user:on_call",
			"user:read",
			"user:write",
			"view:share",
			"webhook:read",
			"webhook:write",
		},
		"SECURITY_ENGINEER": {
			"alert:read",
			"audit:read",
			"case:read",
			"config:read",
			"config:write",
			"dataset:read",
			"detection:read",
			"detection:reload",
			"detection:run",
			"detection:write",
			"pipeline:read",
			"pipeline:run",
			"pipeline:write",
			"suppression:broad_write",
			"suppression:read",
			"suppression:write",
			"tag:manage",
			"task:read",
			"template:write",
			"view:share",
			"webhook:read",
			"webhook:write",
		},
		"ANALYST": {
			"alert:read",
			"case:close",
			"case:merge",
			"case:read",
			"case:write",
			"dataset:read",
			"detection:read",
			"pipeline:read",
			"suppression:read",
			"suppression:write",
			"task:read",
			"task:write",
			"view:share",
		},
		"READ_ONLY": {
			"alert:read",
			"case:read",
			"detection:read",
			"pipeline:read",
			"suppression:read",
			"task:read",
		},
		"SERVICE": {},
	}

	var rows []struct {
		Role       string `gorm:"column:role_name"`
		Permission string `gorm:"column:permission"`
	}
	err := test.database.Raw(
		"SELECT role_name, permission FROM role_permissions ORDER BY role_name, permission",
	).Scan(&rows).Error
	if err != nil {
		t.Fatalf("read role permissions: %v", err)
	}

	got := make(map[string][]string, len(want))
	for role := range want {
		got[role] = []string{}
	}
	for _, row := range rows {
		got[row.Role] = append(got[row.Role], row.Permission)
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("role permissions = %v, want %v", got, want)
	}
}

func TestProviders(t *testing.T) {
	test := newTestService(t)
	providers := test.service.Providers()
	if len(providers) != 1 || providers[0] != ProviderLocal {
		t.Errorf("Providers() = %v, want [%q]", providers, ProviderLocal)
	}
}

func TestCountUsers(t *testing.T) {
	test := newTestService(t)
	count, err := test.service.CountUsers(context.Background())
	if err != nil {
		t.Fatalf("CountUsers on an empty database: %v", err)
	}
	if count != 0 {
		t.Errorf("CountUsers on an empty database = %d, want 0", count)
	}

	test.createAdmin(t, testEmail)

	count, err = test.service.CountUsers(context.Background())
	if err != nil {
		t.Fatalf("CountUsers after CreateAdmin: %v", err)
	}
	if count != 1 {
		t.Errorf("CountUsers after CreateAdmin = %d, want 1", count)
	}
}

func TestCreateAdmin(t *testing.T) {
	test := newTestService(t)
	user, err := test.service.CreateAdmin(context.Background(), " Admin@Example.com ", "Admin User", testPassword)
	if err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	if user.ID == "" {
		t.Error("CreateAdmin returned a user without an id")
	}
	if user.Email != testEmail {
		t.Errorf("user email = %q, want %q", user.Email, testEmail)
	}
	if user.DisplayName != "Admin User" {
		t.Errorf("user display name = %q, want Admin User", user.DisplayName)
	}
	if user.Status != StatusActive {
		t.Errorf("user status = %q, want %q", user.Status, StatusActive)
	}
	if user.LastLoginAt != nil {
		t.Errorf("user last login = %v, want nil", user.LastLoginAt)
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.Provider != ProviderLocal {
		t.Errorf("identity provider = %q, want %q", identity.Provider, ProviderLocal)
	}
	if identity.Subject != user.ID {
		t.Errorf("identity subject = %q, want the user id %q", identity.Subject, user.ID)
	}
	if identity.PasswordHash == nil {
		t.Fatal("identity password hash is nil")
	}
	if !strings.HasPrefix(*identity.PasswordHash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("identity password hash %q does not use the current parameters", *identity.PasswordHash)
	}
	if strings.Contains(*identity.PasswordHash, testPassword) {
		t.Errorf("identity password hash contains the password: %q", *identity.PasswordHash)
	}

	var roleCount int64
	err = test.database.Raw(
		"SELECT count(*) FROM user_roles WHERE user_id = ? AND role_name = ?", user.ID, RoleAdmin,
	).Scan(&roleCount).Error
	if err != nil {
		t.Fatalf("count user roles: %v", err)
	}
	if roleCount != 1 {
		t.Errorf("user has %d ADMIN roles, want 1", roleCount)
	}

	events := auditEventsForTarget(t, test.database, user.ID)
	if len(events) != 1 {
		t.Fatalf("CreateAdmin wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventName != "simple_siem.user.created" {
		t.Errorf("audit event name = %q, want simple_siem.user.created", event.EventName)
	}
	if event.EventCategory != "USER" {
		t.Errorf("audit category = %q, want USER", event.EventCategory)
	}
	if event.EventOutcome != "SUCCESS" {
		t.Errorf("audit outcome = %q, want SUCCESS", event.EventOutcome)
	}
	if event.ActorType != "SYSTEM" {
		t.Errorf("audit actor type = %q, want SYSTEM", event.ActorType)
	}
	if event.ActorID != nil {
		t.Errorf("audit actor id = %v, want nil", *event.ActorID)
	}
	if event.ActorSessionID != nil {
		t.Errorf("audit actor session id = %v, want nil", *event.ActorSessionID)
	}
	if event.TargetType != "USER" || event.TargetID != user.ID {
		t.Errorf("audit target = %q/%q, want USER/%q", event.TargetType, event.TargetID, user.ID)
	}
	if event.Action != "create" {
		t.Errorf("audit action = %q, want create", event.Action)
	}

	changes := storedChanges(t, event)
	if changes["email"] != testEmail {
		t.Errorf("audit changes.email = %v, want %q", changes["email"], testEmail)
	}
	if changes["via"] != "cli" {
		t.Errorf("audit changes.via = %v, want cli", changes["via"])
	}
	roles, ok := changes["roles"].([]any)
	if !ok || len(roles) != 1 || roles[0] != RoleAdmin {
		t.Errorf("audit changes.roles = %v, want [%s]", changes["roles"], RoleAdmin)
	}
	if strings.Contains(string(event.Changes), testPassword) {
		t.Errorf("audit changes contain the password: %s", event.Changes)
	}
}

func TestCreateAdminStartsVersionsAtOne(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)

	var storedUser struct {
		Version int `gorm:"column:version"`
	}
	if err := test.database.Raw("SELECT version FROM users WHERE id = ?", user.ID).Scan(&storedUser).Error; err != nil {
		t.Fatalf("read user version: %v", err)
	}
	if storedUser.Version != 1 {
		t.Errorf("user version = %d, want 1", storedUser.Version)
	}

	var storedIdentity struct {
		Version int `gorm:"column:version"`
	}
	err := test.database.Raw(
		"SELECT version FROM user_identities WHERE user_id = ? AND provider = ?", user.ID, ProviderLocal,
	).Scan(&storedIdentity).Error
	if err != nil {
		t.Fatalf("read identity version: %v", err)
	}
	if storedIdentity.Version != 1 {
		t.Errorf("identity version = %d, want 1", storedIdentity.Version)
	}
}

func TestCreateAdminRejectsDuplicateEmail(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	usersBefore := countRows(t, test.database, "users")
	eventsBefore := countRows(t, test.database, "audit_events")

	_, err := test.service.CreateAdmin(context.Background(), " Admin@Example.com ", "Other", testPassword)
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("CreateAdmin duplicate error = %v, want ErrUserExists", err)
	}
	if got := countRows(t, test.database, "users"); got != usersBefore {
		t.Errorf("users count = %d after duplicate, want %d", got, usersBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit event count = %d after duplicate, want %d", got, eventsBefore)
	}
}

func TestCreateAdminValidatesInput(t *testing.T) {
	test := newTestService(t)
	eventsBefore := countRows(t, test.database, "audit_events")

	tests := []struct {
		name     string
		email    string
		password string
		wantErr  error
	}{
		{"short password", testEmail, strings.Repeat("a", 11), ErrPasswordLength},
		{"non-ascii email", "ÄDMIN@example.com", testPassword, ErrInvalidEmail},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := test.service.CreateAdmin(context.Background(), testCase.email, "Admin", testCase.password)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("CreateAdmin error = %v, want %v", err, testCase.wantErr)
			}
			if got := countRows(t, test.database, "users"); got != 0 {
				t.Errorf("users count = %d, want 0", got)
			}
			if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
				t.Errorf("audit event count = %d, want %d", got, eventsBefore)
			}
		})
	}
}

func TestLoginRateLimitPerEmail(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	for attempt := 0; attempt < emailFailureLimit; attempt++ {
		insertFailedAttempt(t, test.database, testEmail, fmt.Sprintf("192.0.2.%d", attempt+10), time.Now().Add(-time.Minute))
	}
	attemptsBefore := countRows(t, test.database, "login_attempts")
	eventsBefore := countRows(t, test.database, "audit_events")

	_, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: testPassword},
		ClientInfo{IP: net.ParseIP("192.0.2.20"), UserAgent: "test-agent", RequestID: "request-limited"},
	)
	var rateLimited RateLimitedError
	if !errors.As(err, &rateLimited) {
		t.Fatalf("Login over the email limit = %v, want RateLimitedError", err)
	}
	if rateLimited.RetryAfter < 13*time.Minute || rateLimited.RetryAfter > failureWindowDuration {
		t.Errorf("RetryAfter = %v, want about 14 minutes and at most 15", rateLimited.RetryAfter)
	}
	if got := countRows(t, test.database, "sessions"); got != 0 {
		t.Errorf("sessions count = %d, want 0", got)
	}
	if got := countRows(t, test.database, "login_attempts"); got != attemptsBefore {
		t.Errorf("login attempts = %d after a rate-limited login, want %d", got, attemptsBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after a rate-limited login, want %d", got, eventsBefore)
	}
	logged := test.logs.String()
	if !strings.Contains(logged, "login rate limited") {
		t.Errorf("logs do not contain the rate-limit warning: %s", logged)
	}
	if !strings.Contains(logged, `"request_id":"request-limited"`) {
		t.Errorf("rate-limit log lacks the request id: %s", logged)
	}
	if strings.Contains(logged, testEmail) {
		t.Errorf("rate-limit log contains the email: %s", logged)
	}
}

func TestLoginRateLimitPerAddress(t *testing.T) {
	test := newTestService(t)
	for attempt := 0; attempt < addressFailureLimit; attempt++ {
		insertFailedAttempt(
			t,
			test.database,
			fmt.Sprintf("user%d@example.com", attempt),
			"192.0.2.7",
			time.Now().Add(-time.Minute),
		)
	}

	_, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: "other@example.com", Password: testPassword},
		ClientInfo{IP: net.ParseIP("192.0.2.7"), UserAgent: "test-agent", RequestID: "request-limited"},
	)
	var rateLimited RateLimitedError
	if !errors.As(err, &rateLimited) {
		t.Fatalf("Login over the address limit = %v, want RateLimitedError", err)
	}
	if rateLimited.RetryAfter <= 0 || rateLimited.RetryAfter > failureWindowDuration {
		t.Errorf("RetryAfter = %v, want between 1 second and 15 minutes", rateLimited.RetryAfter)
	}
	if got := countRows(t, test.database, "sessions"); got != 0 {
		t.Errorf("sessions count = %d, want 0", got)
	}
}

func TestLoginRateLimitCountsConcurrentAttempts(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)

	const burst = 20
	var wait sync.WaitGroup
	results := make([]error, burst)
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, results[index] = test.service.Login(
				context.Background(),
				LoginRequest{Email: testEmail, Password: "the wrong password"},
				ClientInfo{IP: net.ParseIP("192.0.2.7"), UserAgent: "test-agent", RequestID: "request-burst"},
			)
		}()
	}
	wait.Wait()

	var reached, limited int
	for _, err := range results {
		var rateLimited RateLimitedError
		switch {
		case errors.Is(err, ErrInvalidCredentials):
			reached++
		case errors.As(err, &rateLimited):
			limited++
		default:
			t.Errorf("burst login error = %v, want ErrInvalidCredentials or RateLimitedError", err)
		}
	}
	if reached > emailFailureLimit {
		t.Errorf("burst logins = %d reached the hash, want at most %d", reached, emailFailureLimit)
	}

	var failed int64
	err := test.database.Raw(
		"SELECT count(*) FROM login_attempts WHERE NOT succeeded AND email_hash = ?", emailHash(testEmail),
	).Scan(&failed).Error
	if err != nil {
		t.Fatalf("count failed attempts: %v", err)
	}
	if failed != int64(reached) {
		t.Errorf(
			"failed attempt rows = %d, want %d (the logins that reached the hash, %d limited)",
			failed, reached, limited,
		)
	}
}

func TestLoginRateLimitedWhileLockHeld(t *testing.T) {
	tests := []struct {
		name string
		keys []int64
	}{
		{"email lock", []int64{loginLockKey("login-email:", hex.EncodeToString(emailHash(testEmail)))}},
		{"address lock", []int64{loginLockKey("login-ip:", "192.0.2.7")}},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			test := newTestService(t)
			test.createAdmin(t, testEmail)

			var loginErr error
			err := test.database.WithContext(context.Background()).Transaction(func(tx *gorm.DB) error {
				for _, key := range testCase.keys {
					if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", key).Error; err != nil {
						return fmt.Errorf("hold the lock: %w", err)
					}
				}
				loginContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_, loginErr = test.service.Login(
					loginContext,
					LoginRequest{Email: testEmail, Password: testPassword},
					testClient(),
				)
				return nil
			})
			if err != nil {
				t.Fatalf("hold lock transaction: %v", err)
			}

			var rateLimited RateLimitedError
			if !errors.As(loginErr, &rateLimited) {
				t.Fatalf("Login while the %s is held = %v, want RateLimitedError", testCase.name, loginErr)
			}
			if rateLimited.RetryAfter != time.Second {
				t.Errorf("RetryAfter = %v, want 1s", rateLimited.RetryAfter)
			}
			if got := countRows(t, test.database, "login_attempts"); got != 0 {
				t.Errorf("login attempts = %d, want 0", got)
			}
		})
	}
}

func TestLoginRateLimitWindowExpires(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	for attempt := 0; attempt < emailFailureLimit; attempt++ {
		insertFailedAttempt(
			t,
			test.database,
			testEmail,
			fmt.Sprintf("192.0.2.%d", attempt+10),
			time.Now().Add(-failureWindowDuration-time.Minute),
		)
	}

	result, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: testPassword},
		testClient(),
	)
	if err != nil {
		t.Fatalf("Login after the rate-limit window = %v, want nil", err)
	}
	if result.Token == "" {
		t.Error("Login after the rate-limit window returned no token")
	}
}

func insertFailedAttempt(t *testing.T, db *gorm.DB, email, address string, createdAt time.Time) {
	t.Helper()
	err := db.Exec(
		"INSERT INTO login_attempts (email_hash, client_ip, succeeded, created_at) VALUES (decode(?, 'hex'), ?::inet, false, ?)",
		hex.EncodeToString(emailHash(email)),
		address,
		createdAt,
	).Error
	if err != nil {
		t.Fatalf("insert failed login attempt: %v", err)
	}
}

func TestAuthenticateRejectsMalformedTokens(t *testing.T) {
	test := newTestService(t)
	tokens := []string{
		"",
		"not base64!",
		base64.RawURLEncoding.EncodeToString(make([]byte, 31)),
		base64.RawURLEncoding.EncodeToString(make([]byte, 33)),
	}
	for _, token := range tokens {
		_, err := test.service.Authenticate(context.Background(), token)
		if !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(%q) error = %v, want ErrUnauthenticated", token, err)
		}
	}
}

func TestAuthenticateRejectsUnknownToken(t *testing.T) {
	test := newTestService(t)
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	_, err := test.service.Authenticate(context.Background(), token)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Authenticate(unknown token) error = %v, want ErrUnauthenticated", err)
	}
}

func TestAuthenticateReturnsActor(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	if err := test.database.Exec(
		"INSERT INTO user_roles (user_id, role_name) VALUES (?, ?)", user.ID, "READ_ONLY",
	).Error; err != nil {
		t.Fatalf("add second role: %v", err)
	}
	login := test.login(t, testEmail, testPassword)

	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if actor.UserID != user.ID {
		t.Errorf("actor user id = %q, want %q", actor.UserID, user.ID)
	}
	if actor.SessionID == "" {
		t.Error("actor session id is empty")
	}
	if actor.Email != testEmail {
		t.Errorf("actor email = %q, want %q", actor.Email, testEmail)
	}
	if actor.DisplayName != user.DisplayName {
		t.Errorf("actor display name = %q, want %q", actor.DisplayName, user.DisplayName)
	}
	if !slices.Equal(actor.Roles, []string{RoleAdmin, "READ_ONLY"}) {
		t.Errorf("actor roles = %v, want [%s READ_ONLY]", actor.Roles, RoleAdmin)
	}
}

func TestAuthenticateLoadsAnalystPermissions(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	setRoles(t, test.database, user.ID, "ANALYST")
	login := test.login(t, testEmail, testPassword)

	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	for _, permission := range []string{"case:write", "alert:read"} {
		if !slices.Contains(actor.Permissions, permission) {
			t.Errorf("actor permissions %v do not contain %q", actor.Permissions, permission)
		}
		if !actor.Can(permission) {
			t.Errorf("Can(%q) = false, want true", permission)
		}
	}
	if slices.Contains(actor.Permissions, "user:read") {
		t.Errorf("actor permissions %v contain user:read, want none", actor.Permissions)
	}
	if actor.Can("user:read") {
		t.Error("Can(user:read) = true, want false")
	}
	if !slices.Equal(actor.Roles, []string{"ANALYST"}) {
		t.Errorf("actor roles = %v, want [ANALYST]", actor.Roles)
	}
}

func TestAuthenticateWithoutRolesHasNoPermissions(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	setRoles(t, test.database, user.ID)
	login := test.login(t, testEmail, testPassword)

	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(actor.Permissions) != 0 {
		t.Errorf("actor permissions = %v (%d entries), want none", actor.Permissions, len(actor.Permissions))
	}
	if actor.Can("alert:read") {
		t.Error("Can(alert:read) = true, want false")
	}
}

func TestAuthenticatePermissionsAreSortedAndUnique(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	setRoles(t, test.database, user.ID, "ANALYST", "READ_ONLY")
	login := test.login(t, testEmail, testPassword)

	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !slices.IsSorted(actor.Permissions) {
		t.Errorf("actor permissions %v are not sorted", actor.Permissions)
	}
	unique := slices.Compact(slices.Clone(actor.Permissions))
	if len(unique) != len(actor.Permissions) {
		t.Errorf("actor permissions %v contain duplicates", actor.Permissions)
	}
	if !slices.Equal(actor.Roles, []string{"ANALYST", "READ_ONLY"}) {
		t.Errorf("actor roles = %v, want [ANALYST READ_ONLY]", actor.Roles)
	}
}

func TestAuthenticateReloadsRolesOnNextRequest(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	setRoles(t, test.database, user.ID)
	login := test.login(t, testEmail, testPassword)

	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if actor.Can("case:read") {
		t.Fatal("Can(case:read) before the role is assigned = true, want false")
	}

	if err := test.database.Exec(
		"INSERT INTO user_roles (user_id, role_name) VALUES (?, 'READ_ONLY')", user.ID,
	).Error; err != nil {
		t.Fatalf("assign READ_ONLY: %v", err)
	}

	actor, err = test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate after the role is assigned: %v", err)
	}
	if !actor.Can("case:read") {
		t.Errorf("actor permissions %v after the role is assigned lack case:read", actor.Permissions)
	}
}

func setRoles(t *testing.T, db *gorm.DB, userID string, roles ...string) {
	t.Helper()
	if err := db.Exec("DELETE FROM user_roles WHERE user_id = ?", userID).Error; err != nil {
		t.Fatalf("clear user roles: %v", err)
	}
	for _, role := range roles {
		if err := db.Exec(
			"INSERT INTO user_roles (user_id, role_name) VALUES (?, ?)", userID, role,
		).Error; err != nil {
			t.Fatalf("assign role %s: %v", role, err)
		}
	}
}

func TestAuthenticateRejectsExpiredSessions(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{"idle expiry in the past", "UPDATE sessions SET idle_expires_at = now() - interval '1 minute' WHERE id = ?"},
		{
			"absolute expiry in the past",
			"UPDATE sessions SET idle_expires_at = now() + interval '1 hour', absolute_expires_at = now() - interval '1 minute' WHERE id = ?",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			test := newTestService(t)
			test.createAdmin(t, testEmail)
			login := test.login(t, testEmail, testPassword)
			session := readSessionByUser(t, test.database, testEmail)
			if err := test.database.Exec(testCase.query, session.ID).Error; err != nil {
				t.Fatalf("expire session: %v", err)
			}

			_, err := test.service.Authenticate(context.Background(), login.Token)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Authenticate(expired session) error = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestAuthenticateRejectsDisabledUser(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	if err := test.database.Exec("UPDATE users SET status = 'DISABLED' WHERE id = ?", user.ID).Error; err != nil {
		t.Fatalf("disable user: %v", err)
	}

	_, err := test.service.Authenticate(context.Background(), login.Token)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate(disabled user) error = %v, want ErrUnauthenticated", err)
	}
}

func TestAuthenticateSlidesIdleExpiry(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	session := readSessionByUser(t, test.database, testEmail)
	if err := test.database.Exec(
		"UPDATE sessions SET last_used_at = now() - interval '2 minutes', idle_expires_at = now() + interval '1 minute' WHERE id = ?",
		session.ID,
	).Error; err != nil {
		t.Fatalf("age session: %v", err)
	}

	if _, err := test.service.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	updated := readSessionByID(t, test.database, session.ID)
	if until := time.Until(updated.IdleExpiresAt); until < 29*time.Minute || until > 31*time.Minute {
		t.Errorf("idle expiry after use is %v away, want about 30 minutes", until)
	}
	if updated.IdleExpiresAt.After(updated.AbsoluteExpiresAt) {
		t.Errorf("idle expiry %v is after absolute expiry %v", updated.IdleExpiresAt, updated.AbsoluteExpiresAt)
	}
	if time.Since(updated.LastUsedAt) > time.Minute {
		t.Errorf("last used at %v is not recent", updated.LastUsedAt)
	}
}

func TestAuthenticateCapsIdleExpiryAtAbsolute(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	session := readSessionByUser(t, test.database, testEmail)
	if err := test.database.Exec(
		"UPDATE sessions SET last_used_at = now() - interval '2 minutes', idle_expires_at = now() + interval '1 minute', absolute_expires_at = now() + interval '5 minutes' WHERE id = ?",
		session.ID,
	).Error; err != nil {
		t.Fatalf("age session: %v", err)
	}

	if _, err := test.service.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	updated := readSessionByID(t, test.database, session.ID)
	if !updated.IdleExpiresAt.Equal(updated.AbsoluteExpiresAt) {
		t.Errorf("idle expiry %v is not capped at absolute expiry %v", updated.IdleExpiresAt, updated.AbsoluteExpiresAt)
	}
}

func TestAuthenticateSkipsIdleSlideWithinAMinute(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	session := readSessionByUser(t, test.database, testEmail)
	if err := test.database.Exec(
		"UPDATE sessions SET last_used_at = now(), idle_expires_at = now() + interval '10 minutes' WHERE id = ?",
		session.ID,
	).Error; err != nil {
		t.Fatalf("set session times: %v", err)
	}
	before := readSessionByID(t, test.database, session.ID)

	if _, err := test.service.Authenticate(context.Background(), login.Token); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	after := readSessionByID(t, test.database, session.ID)
	if !after.IdleExpiresAt.Equal(before.IdleExpiresAt) {
		t.Errorf("idle expiry moved from %v to %v within a minute", before.IdleExpiresAt, after.IdleExpiresAt)
	}
}

func TestCurrentUser(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	current, roles, err := test.service.CurrentUser(context.Background(), actor)
	if err != nil {
		t.Fatalf("CurrentUser: %v", err)
	}
	if current.ID != user.ID || current.Email != testEmail || current.Status != StatusActive {
		t.Errorf("CurrentUser = %+v, want %+v", current, user)
	}
	if current.Version != user.Version {
		t.Errorf("CurrentUser version = %d, want %d", current.Version, user.Version)
	}
	if !slices.Equal(roles, []string{RoleAdmin}) {
		t.Errorf("CurrentUser roles = %v, want [%s]", roles, RoleAdmin)
	}
}

func TestLogout(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if err := test.service.Logout(context.Background(), actor, testClient()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if got := countRows(t, test.database, "sessions"); got != 1 {
		t.Errorf("sessions count = %d after logout, want 1 (the other login)", got)
	}
	if _, err := test.service.Authenticate(context.Background(), login.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Authenticate after logout error = %v, want ErrUnauthenticated", err)
	}

	events := auditEventsForTarget(t, test.database, actor.SessionID)
	if len(events) != 1 {
		t.Fatalf("logout wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventName != "simple_siem.auth.logout" || event.EventOutcome != "SUCCESS" {
		t.Errorf("logout audit = %q/%q, want simple_siem.auth.logout/SUCCESS", event.EventName, event.EventOutcome)
	}
	if event.ActorType != "USER" || event.ActorID == nil || *event.ActorID != user.ID {
		t.Errorf("logout audit actor = %s/%v, want USER/%q", event.ActorType, event.ActorID, user.ID)
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != actor.SessionID {
		t.Errorf("logout audit actor session id = %v, want %q", event.ActorSessionID, actor.SessionID)
	}
	if event.TargetType != "SESSION" || event.TargetID != actor.SessionID || event.Action != "logout" {
		t.Errorf("logout audit target = %q/%q action %q, want SESSION/%q logout", event.TargetType, event.TargetID, event.Action, actor.SessionID)
	}
	if event.RequestID != "request-1" || event.SourceIP == nil || *event.SourceIP != "192.0.2.7" {
		t.Errorf("logout audit request/source = %q/%v, want request-1/192.0.2.7", event.RequestID, event.SourceIP)
	}

	logged := test.logs.String()
	for _, secret := range []string{testPassword, login.Token} {
		if strings.Contains(logged, secret) {
			t.Errorf("logs contain the secret %q: %s", secret, logged)
		}
		if strings.Contains(string(event.Changes), secret) {
			t.Errorf("logout audit changes contain the secret %q: %s", secret, event.Changes)
		}
	}
}

func TestRecordPermissionDenied(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	required := []string{"user:read", "role:assign"}
	err = test.service.RecordPermissionDenied(
		context.Background(), actor, testClient(), "/api/v1/users", http.MethodGet, required,
	)
	if err != nil {
		t.Fatalf("RecordPermissionDenied: %v", err)
	}

	events := auditEventsForTarget(t, test.database, "/api/v1/users")
	if len(events) != 1 {
		t.Fatalf("permission denial wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventName != "simple_siem.auth.permission_denied" || event.EventCategory != "AUTHORIZATION" ||
		event.EventOutcome != "DENIED" {
		t.Errorf("denial audit = %q/%q/%q, want simple_siem.auth.permission_denied/AUTHORIZATION/DENIED",
			event.EventName, event.EventCategory, event.EventOutcome)
	}
	if event.ActorType != "USER" || event.ActorID == nil || *event.ActorID != user.ID {
		t.Errorf("denial audit actor = %s/%v, want USER/%q", event.ActorType, event.ActorID, user.ID)
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != actor.SessionID {
		t.Errorf("denial audit actor session id = %v, want %q", event.ActorSessionID, actor.SessionID)
	}
	if event.TargetType != "ROUTE" || event.TargetID != "/api/v1/users" || event.Action != http.MethodGet {
		t.Errorf("denial audit target = %q/%q action %q, want ROUTE//api/v1/users GET",
			event.TargetType, event.TargetID, event.Action)
	}
	if event.RequestID != "request-1" || event.SourceIP == nil || *event.SourceIP != "192.0.2.7" {
		t.Errorf("denial audit request/source = %q/%v, want request-1/192.0.2.7", event.RequestID, event.SourceIP)
	}
	storedRequired, ok := storedChanges(t, event)["required"].([]any)
	if !ok || !slices.Equal(storedRequired, []any{"user:read", "role:assign"}) {
		t.Errorf("denial audit required = %v, want [user:read role:assign]", storedRequired)
	}
}

func TestLogoutWithoutSession(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	eventsBefore := countRows(t, test.database, "audit_events")

	err := test.service.Logout(
		context.Background(),
		Actor{UserID: user.ID, SessionID: "0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f"},
		testClient(),
	)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Logout without a session = %v, want ErrUnauthenticated", err)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after failed logout, want %d", got, eventsBefore)
	}
}

func (test testService) login(t *testing.T, email, password string) LoginResult {
	t.Helper()
	result, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: email, Password: password},
		testClient(),
	)
	if err != nil {
		t.Fatalf("Login(%q): %v", email, err)
	}
	return result
}

func readSessionByUser(t *testing.T, db *gorm.DB, email string) storedSession {
	t.Helper()
	var session storedSession
	err := db.Raw(`
		SELECT sessions.id::text AS id, sessions.user_id::text AS user_id, token_hash,
		       auth_provider, last_used_at, idle_expires_at, absolute_expires_at,
		       host(client_ip) AS client_ip, user_agent
		FROM sessions
		JOIN users ON users.id = sessions.user_id
		WHERE users.email = ?`, email).Scan(&session).Error
	if err != nil {
		t.Fatalf("read session for %q: %v", email, err)
	}
	if session.ID == "" {
		t.Fatalf("no session for %q", email)
	}
	return session
}

func readSessionByID(t *testing.T, db *gorm.DB, sessionID string) storedSession {
	t.Helper()
	var session storedSession
	err := db.Raw(`
		SELECT id::text AS id, user_id::text AS user_id, token_hash, auth_provider,
		       last_used_at, idle_expires_at, absolute_expires_at,
		       host(client_ip) AS client_ip, user_agent
		FROM sessions
		WHERE id = ?`, sessionID).Scan(&session).Error
	if err != nil {
		t.Fatalf("read session %q: %v", sessionID, err)
	}
	return session
}

func TestResetPassword(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	test.login(t, testEmail, testPassword)
	test.login(t, testEmail, testPassword)
	const newPassword = "another correct horse"

	revoked, err := test.service.ResetPassword(context.Background(), " Admin@Example.com ", newPassword)
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if revoked != 2 {
		t.Errorf("ResetPassword revoked %d sessions, want 2", revoked)
	}
	if got := countRows(t, test.database, "sessions"); got != 0 {
		t.Errorf("sessions count = %d after reset, want 0", got)
	}

	if _, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: testPassword},
		testClient(),
	); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login with the old password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: newPassword},
		testClient(),
	); err != nil {
		t.Errorf("Login with the new password = %v, want nil", err)
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.PasswordHash == nil {
		t.Fatal("identity password hash is nil after reset")
	}
	if identity.Version != 2 {
		t.Errorf("identity version after reset = %d, want 2", identity.Version)
	}
	if strings.Contains(*identity.PasswordHash, newPassword) {
		t.Errorf("identity password hash contains the password: %q", *identity.PasswordHash)
	}
	matches, err := VerifyPassword(context.Background(), newPassword, *identity.PasswordHash)
	if err != nil || !matches {
		t.Errorf("VerifyPassword(new password) = %v/%v, want true/nil", matches, err)
	}

	var resetEvents []storedAuditEvent
	for _, event := range auditEventsForTarget(t, test.database, user.ID) {
		if event.EventName == "simple_siem.auth.password_reset" {
			resetEvents = append(resetEvents, event)
		}
	}
	if len(resetEvents) != 1 {
		t.Fatalf("ResetPassword wrote %d audit events, want 1", len(resetEvents))
	}
	event := resetEvents[0]
	if event.EventCategory != "AUTHENTICATION" || event.EventOutcome != "SUCCESS" || event.ActorType != "SYSTEM" {
		t.Errorf("reset audit = %s/%s/%s, want AUTHENTICATION/SUCCESS/SYSTEM", event.EventCategory, event.EventOutcome, event.ActorType)
	}
	if event.ActorID != nil {
		t.Errorf("reset audit actor id = %v, want nil", *event.ActorID)
	}
	if event.TargetType != "USER" || event.TargetID != user.ID || event.Action != "reset_password" {
		t.Errorf("reset audit target = %q/%q action %q, want USER/%q reset_password", event.TargetType, event.TargetID, event.Action, user.ID)
	}
	changes := storedChanges(t, event)
	if changes["via"] != "cli" {
		t.Errorf("reset audit changes.via = %v, want cli", changes["via"])
	}
	if got := changes["revokedCount"]; got != float64(revoked) {
		t.Errorf("reset audit changes.revokedCount = %v, want %d", got, revoked)
	}
}

func TestResetPasswordUnknownEmail(t *testing.T) {
	test := newTestService(t)
	usersBefore := countRows(t, test.database, "users")
	eventsBefore := countRows(t, test.database, "audit_events")

	revoked, err := test.service.ResetPassword(context.Background(), "nobody@example.com", "another correct horse")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("ResetPassword for an unknown email = %v, want ErrUserNotFound", err)
	}
	if revoked != 0 {
		t.Errorf("ResetPassword revoked %d sessions, want 0", revoked)
	}
	if got := countRows(t, test.database, "users"); got != usersBefore {
		t.Errorf("users count = %d after reset, want %d", got, usersBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after reset, want %d", got, eventsBefore)
	}
}

func TestResetPasswordValidatesInput(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	test.login(t, testEmail, testPassword)
	eventsBefore := countRows(t, test.database, "audit_events")

	revoked, err := test.service.ResetPassword(context.Background(), testEmail, strings.Repeat("a", 11))
	if !errors.Is(err, ErrPasswordLength) {
		t.Fatalf("ResetPassword with a short password = %v, want ErrPasswordLength", err)
	}
	if revoked != 0 {
		t.Errorf("ResetPassword revoked %d sessions, want 0", revoked)
	}
	if got := countRows(t, test.database, "sessions"); got != 1 {
		t.Errorf("sessions count = %d, want 1", got)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after a rejected reset, want %d", got, eventsBefore)
	}
}

func TestLoginSuccess(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)

	result, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: " Admin@Example.com ", Password: testPassword},
		testClient(),
	)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if len(result.Token) != 43 {
		t.Errorf("session token %q has %d characters, want 43", result.Token, len(result.Token))
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(result.Token)
	if err != nil || len(rawToken) != 32 {
		t.Errorf("session token decodes to %d bytes (error %v), want 32", len(rawToken), err)
	}
	if until := time.Until(result.ExpiresAt); until < 11*time.Hour+50*time.Minute || until > 12*time.Hour+10*time.Minute {
		t.Errorf("expires at %v is %v away, want about 12 hours", result.ExpiresAt, until)
	}
	if result.User.ID != user.ID || result.User.Email != testEmail || result.User.DisplayName != user.DisplayName {
		t.Errorf("login user = %+v, want %+v", result.User, user)
	}
	if !slices.Equal(result.Roles, []string{RoleAdmin}) {
		t.Errorf("login roles = %v, want [%s]", result.Roles, RoleAdmin)
	}

	var session storedSession
	err = test.database.Raw(`
		SELECT id::text AS id, user_id::text AS user_id, token_hash, auth_provider,
		       idle_expires_at, absolute_expires_at, host(client_ip) AS client_ip, user_agent
		FROM sessions
		WHERE user_id = ?`, user.ID).Scan(&session).Error
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	if session.ID == "" {
		t.Fatal("Login wrote no session row")
	}
	tokenHash := sha256.Sum256(rawToken)
	if !bytes.Equal(session.TokenHash, tokenHash[:]) {
		t.Errorf("stored token hash = %x, want sha256 of the decoded token", session.TokenHash)
	}
	if session.AuthProvider != ProviderLocal {
		t.Errorf("session provider = %q, want %q", session.AuthProvider, ProviderLocal)
	}
	if until := time.Until(session.IdleExpiresAt); until < 29*time.Minute || until > 31*time.Minute {
		t.Errorf("idle expiry is %v away, want about 30 minutes", until)
	}
	if until := time.Until(session.AbsoluteExpiresAt); until < 11*time.Hour+50*time.Minute || until > 12*time.Hour+10*time.Minute {
		t.Errorf("absolute expiry is %v away, want about 12 hours", until)
	}
	if session.UserAgent != "test-agent" {
		t.Errorf("session user agent = %q, want test-agent", session.UserAgent)
	}
	if session.ClientIP != "192.0.2.7" {
		t.Errorf("session client ip = %q, want 192.0.2.7", session.ClientIP)
	}

	var attempt storedAttempt
	err = test.database.Raw(
		"SELECT succeeded, host(client_ip) AS client_ip FROM login_attempts WHERE email_hash = ?", emailHash(testEmail),
	).Scan(&attempt).Error
	if err != nil {
		t.Fatalf("read login attempt: %v", err)
	}
	if !attempt.Succeeded {
		t.Error("successful login wrote a failed attempt")
	}
	if attempt.ClientIP != "192.0.2.7" {
		t.Errorf("attempt client ip = %q, want 192.0.2.7", attempt.ClientIP)
	}

	if user = storedUser(t, test.database, user.ID); user.LastLoginAt == nil {
		t.Error("users.last_login_at is nil after login")
	}
	if user.Version != 1 {
		t.Errorf("user version after login = %d, want 1 (last_login_at does not bump it)", user.Version)
	}
	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.LastUsedAt == nil {
		t.Error("user_identities.last_used_at is nil after login")
	}

	events := authLoginEvents(t, test.database, user.ID)
	if len(events) != 1 {
		t.Fatalf("login wrote %d login audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "AUTHENTICATION" || event.EventOutcome != "SUCCESS" {
		t.Errorf("login audit = %s/%s, want AUTHENTICATION/SUCCESS", event.EventCategory, event.EventOutcome)
	}
	if event.ActorType != "USER" {
		t.Errorf("login audit actor type = %q, want USER", event.ActorType)
	}
	if event.ActorID == nil || *event.ActorID != user.ID {
		t.Errorf("login audit actor id = %v, want %q", event.ActorID, user.ID)
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != session.ID {
		t.Errorf("login audit actor session id = %v, want %q", event.ActorSessionID, session.ID)
	}
	if event.RequestID != "request-1" {
		t.Errorf("login audit request id = %q, want request-1", event.RequestID)
	}
	if event.SourceIP == nil || *event.SourceIP != "192.0.2.7" {
		t.Errorf("login audit source ip = %v, want 192.0.2.7", event.SourceIP)
	}
	if event.TargetType != "USER" || event.TargetID != user.ID || event.Action != "login" {
		t.Errorf("login audit target = %q/%q action %q, want USER/%q login", event.TargetType, event.TargetID, event.Action, user.ID)
	}
	changes := storedChanges(t, event)
	if changes["provider"] != ProviderLocal {
		t.Errorf("login audit changes.provider = %v, want %q", changes["provider"], ProviderLocal)
	}

	logged := test.logs.String()
	for _, secret := range []string{testPassword, result.Token} {
		if strings.Contains(logged, secret) {
			t.Errorf("logs contain the secret %q: %s", secret, logged)
		}
		if strings.Contains(string(event.Changes), secret) {
			t.Errorf("login audit changes contain the secret %q: %s", secret, event.Changes)
		}
	}
	var auditText string
	if err := test.database.Raw(
		"SELECT COALESCE(string_agg(changes::text, ' '), '') FROM audit_events",
	).Scan(&auditText).Error; err != nil {
		t.Fatalf("read audit changes: %v", err)
	}
	for _, secret := range []string{testPassword, result.Token} {
		if strings.Contains(auditText, secret) {
			t.Errorf("audit changes contain the secret %q: %s", secret, auditText)
		}
	}
}

func TestLoginAcceptsInvalidUTF8UserAgent(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)

	client := testClient()
	client.UserAgent = "foo\xff"
	if _, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: testPassword},
		client,
	); err != nil {
		t.Fatalf("Login with a non-UTF-8 user agent: %v", err)
	}

	session := readSessionByUser(t, test.database, testEmail)
	if session.UserAgent != "foo" {
		t.Errorf("session user agent = %q, want foo", session.UserAgent)
	}
}

func TestLoginConcurrentRehashBothSucceed(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	oldHash := oldPasswordHash(t, testPassword)
	if err := test.database.Exec(
		"UPDATE user_identities SET password_hash = ? WHERE user_id = ?", oldHash, user.ID,
	).Error; err != nil {
		t.Fatalf("store old password hash: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	test.service.provider = signalingProvider{provider: test.service.provider, entered: entered, release: release}

	const logins = 2
	var wait sync.WaitGroup
	results := make([]error, logins)
	login := func(index int) {
		defer wait.Done()
		_, results[index] = test.service.Login(
			context.Background(),
			LoginRequest{Email: testEmail, Password: testPassword},
			testClient(),
		)
	}

	// Start one login at a time so the rate-limit lock never contends; both
	// wait in the provider until both have passed it, then hash together.
	wait.Add(1)
	go login(0)
	<-entered
	wait.Add(1)
	go login(1)
	<-entered
	close(release)
	wait.Wait()

	for index, err := range results {
		if err != nil {
			t.Fatalf("concurrent login %d with a t=1 hash = %v, want success", index+1, err)
		}
	}
	if got := countRows(t, test.database, "sessions"); got != logins {
		t.Errorf("sessions count = %d, want %d", got, logins)
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.PasswordHash == nil || !strings.HasPrefix(*identity.PasswordHash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("stored hash after concurrent rehash = %v, want t=2 parameters", identity.PasswordHash)
	}
}

func TestLoginRejectsIdentityDeletedBeforeSession(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	test.service.provider = fixedProvider{identity: ExternalIdentity{
		Provider:          ProviderLocal,
		Subject:           user.ID,
		CredentialVersion: identity.Version,
	}}

	deleteStarted := make(chan struct{})
	releaseDelete := make(chan struct{})
	deleteResult := make(chan error, 1)
	go func() {
		deleteResult <- test.database.WithContext(context.Background()).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("DELETE FROM user_identities WHERE id = ?", identity.ID).Error; err != nil {
				return err
			}
			close(deleteStarted)
			<-releaseDelete
			return nil
		})
	}()
	<-deleteStarted

	loginResult := make(chan error, 1)
	go func() {
		_, err := test.service.Login(
			context.Background(),
			LoginRequest{Email: testEmail, Password: testPassword},
			testClient(),
		)
		loginResult <- err
	}()

	waitForLockWaits(t, test.database, 1)
	close(releaseDelete)
	if err := <-deleteResult; err != nil {
		t.Fatalf("delete identity: %v", err)
	}

	err := <-loginResult
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login with the identity deleted before the session = %v, want ErrInvalidCredentials", err)
	}
	if got := countRows(t, test.database, "sessions"); got != 0 {
		t.Errorf("sessions count = %d, want 0", got)
	}
	events := authLoginEvents(t, test.database, user.ID)
	if len(events) != 1 {
		t.Fatalf("missing identity wrote %d audit events, want 1", len(events))
	}
	if events[0].EventOutcome != "FAILED" {
		t.Errorf("missing identity audit outcome = %q, want FAILED", events[0].EventOutcome)
	}
	changes := storedChanges(t, events[0])
	if changes["reason"] != "identity_missing" {
		t.Errorf("missing identity audit reason = %v, want identity_missing", changes["reason"])
	}
	if got := countRows(t, test.database, "login_attempts"); got != 1 {
		t.Errorf("login attempts = %d, want 1 (the attempt row is kept)", got)
	}
}

func waitForLockWaits(t *testing.T, db *gorm.DB, want int64) {
	t.Helper()
	var waiting int64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		err := db.Raw(`
			SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting).Error
		if err != nil {
			t.Fatalf("read postgres activity: %v", err)
		}
		if waiting >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d sessions waited on a lock, want %d", waiting, want)
}

// runWhileUserLocked runs change in the background and commits mutate from a
// transaction holding the user row, so change waits on that row.
func runWhileUserLocked(t *testing.T, database *gorm.DB, userID string, mutate func(tx *gorm.DB) error, change func() error) error {
	t.Helper()
	userLocked := make(chan struct{})
	releaseUser := make(chan struct{})
	lockResult := make(chan error, 1)
	go func() {
		lockResult <- database.WithContext(context.Background()).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(
				"SELECT id FROM users WHERE id = ? FOR NO KEY UPDATE", userID,
			).Error; err != nil {
				return err
			}
			if err := mutate(tx); err != nil {
				return err
			}
			close(userLocked)
			<-releaseUser
			return nil
		})
	}()
	<-userLocked

	changed := make(chan error, 1)
	go func() {
		changed <- change()
	}()
	waitForLockWaits(t, database, 1)
	close(releaseUser)
	if err := <-lockResult; err != nil {
		t.Fatalf("release the user lock: %v", err)
	}
	return <-changed
}

// TestConcurrentLoginAndResetTokenUse races a login with the redemption of a
// reset token for the same user. Both take the user row lock first, so they
// serialize instead of deadlocking on the identity row.
func TestConcurrentLoginAndResetTokenUse(t *testing.T) {
	test := newTestService(t)
	admin := test.createAdmin(t, testEmail)
	actor := testActorFor(admin)

	// The real hash runs before UseResetToken opens its transaction, so a fast
	// hash keeps both calls in the lock race; Login uses a fixed provider and
	// never verifies this hash.
	original := hashPasswordFunction
	hashPasswordFunction = func(context.Context, string) (string, error) {
		return "test-password-hash", nil
	}
	t.Cleanup(func() { hashPasswordFunction = original })

	const rounds = 20
	for round := 0; round < rounds; round++ {
		email := fmt.Sprintf("login%02d@example.com", round)
		user := test.createAdmin(t, email)

		var identity Identity
		if err := test.database.Where(
			"user_id = ? AND provider = ?", user.ID, ProviderLocal,
		).First(&identity).Error; err != nil {
			t.Fatalf("round %d: read identity: %v", round, err)
		}
		test.service.provider = fixedProvider{identity: ExternalIdentity{
			Provider:          ProviderLocal,
			Subject:           user.ID,
			CredentialVersion: identity.Version,
		}}

		token, _, err := test.service.CreateResetToken(
			context.Background(), actor, testClient(), user.ID,
		)
		if err != nil {
			t.Fatalf("round %d: CreateResetToken: %v", round, err)
		}

		// Hold the identity row so Login queues on it before UseResetToken
		// reaches it. Releasing it then leaves each call waiting for a row
		// lock the other holds, which is the inversion this test guards
		// against.
		identityLocked := make(chan struct{})
		releaseIdentity := make(chan struct{})
		lockResult := make(chan error, 1)
		go func() {
			lockResult <- test.database.WithContext(context.Background()).Transaction(
				func(tx *gorm.DB) error {
					if err := tx.Exec(
						"SELECT id FROM user_identities WHERE id = ? FOR UPDATE", identity.ID,
					).Error; err != nil {
						return err
					}
					close(identityLocked)
					<-releaseIdentity
					return nil
				},
			)
		}()
		<-identityLocked

		var wait sync.WaitGroup
		var loginErr, resetErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			_, loginErr = test.service.Login(
				context.Background(),
				LoginRequest{Email: email, Password: testPassword},
				testClient(),
			)
		}()
		waitForLockWaits(t, test.database, 1)
		go func() {
			defer wait.Done()
			resetErr = test.service.UseResetToken(
				context.Background(), token, testNewPassword, testClient(),
			)
		}()
		waitForLockWaits(t, test.database, 2)
		close(releaseIdentity)
		if err := <-lockResult; err != nil {
			t.Fatalf("round %d: release the identity lock: %v", round, err)
		}
		wait.Wait()

		if resetErr != nil {
			t.Fatalf("round %d: UseResetToken = %v, want nil", round, resetErr)
		}
		for _, callErr := range []error{loginErr, resetErr} {
			if callErr == nil {
				continue
			}
			if strings.Contains(strings.ToLower(callErr.Error()), "deadlock") {
				t.Fatalf("round %d: %v", round, callErr)
			}
			if !errors.Is(callErr, ErrInvalidCredentials) {
				t.Fatalf("round %d: unexpected error %v", round, callErr)
			}
		}
	}
}

func TestLoginDiscardsAttemptOnProviderError(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	eventsBefore := countRows(t, test.database, "audit_events")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	test.service.provider = cancelingProvider{cancel: cancel}

	_, err := test.service.Login(
		ctx,
		LoginRequest{Email: testEmail, Password: testPassword},
		testClient(),
	)
	if err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login with a canceled context = %v, want a non-credential error", err)
	}
	if got := countRows(t, test.database, "login_attempts"); got != 0 {
		t.Errorf("login attempts = %d after a canceled login, want 0", got)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after a canceled login, want %d", got, eventsBefore)
	}
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)

	tests := []struct {
		name   string
		email  string
		wantID string
	}{
		{"wrong password", testEmail, user.ID},
		{"unknown email", "nobody@example.com", "unknown"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := test.service.Login(
				context.Background(),
				LoginRequest{Email: testCase.email, Password: testPassword + "-wrong"},
				testClient(),
			)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("Login error = %v, want ErrInvalidCredentials", err)
			}
			if got := countRows(t, test.database, "sessions"); got != 0 {
				t.Errorf("sessions count = %d, want 0", got)
			}

			events := authLoginEvents(t, test.database, testCase.wantID)
			if len(events) != 1 {
				t.Fatalf("failed login wrote %d audit events for target %q, want 1", len(events), testCase.wantID)
			}
			event := events[0]
			if event.EventOutcome != "FAILED" || event.ActorType != "ANONYMOUS" || event.ActorID != nil {
				t.Errorf("failed login audit = %s/%s actor %v, want FAILED/ANONYMOUS nil", event.EventOutcome, event.ActorType, event.ActorID)
			}
			if event.TargetType != "USER" || event.Action != "login" {
				t.Errorf("failed login audit target = %q action %q, want USER/login", event.TargetType, event.Action)
			}
			changes := storedChanges(t, event)
			if changes["reason"] != "invalid_credentials" {
				t.Errorf("failed login changes = %v, want reason invalid_credentials", changes)
			}
			if strings.Contains(string(event.Changes), testEmail) || strings.Contains(string(event.Changes), testPassword) {
				t.Errorf("failed login audit contains the email or password: %s", event.Changes)
			}
		})
	}

	var failedAttempts int64
	if err := test.database.Raw(
		"SELECT count(*) FROM login_attempts WHERE NOT succeeded",
	).Scan(&failedAttempts).Error; err != nil {
		t.Fatalf("count failed attempts: %v", err)
	}
	if failedAttempts != 2 {
		t.Errorf("failed attempts = %d, want 2 (wrong password and unknown email)", failedAttempts)
	}
}

func TestLoginRejectsCredentialVersionChange(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	test.service.provider = fixedProvider{identity: ExternalIdentity{
		Provider:          ProviderLocal,
		Subject:           user.ID,
		CredentialVersion: identity.Version - 1,
	}}

	_, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: testPassword},
		testClient(),
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login after a credential change = %v, want ErrInvalidCredentials", err)
	}
	if got := countRows(t, test.database, "sessions"); got != 0 {
		t.Errorf("sessions count = %d, want 0", got)
	}

	events := authLoginEvents(t, test.database, user.ID)
	if len(events) != 1 {
		t.Fatalf("credential-change login wrote %d audit events, want 1", len(events))
	}
	if events[0].EventOutcome != "FAILED" {
		t.Errorf("credential-change audit outcome = %q, want FAILED", events[0].EventOutcome)
	}
	changes := storedChanges(t, events[0])
	if changes["reason"] != "credential_changed" {
		t.Errorf("credential-change audit reason = %v, want credential_changed", changes["reason"])
	}
}

func TestLoginRejectsDisabledUser(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	if err := test.database.Exec("UPDATE users SET status = 'DISABLED' WHERE id = ?", user.ID).Error; err != nil {
		t.Fatalf("disable user: %v", err)
	}

	_, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: testPassword},
		testClient(),
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login for a disabled user = %v, want ErrInvalidCredentials", err)
	}
	if got := countRows(t, test.database, "sessions"); got != 0 {
		t.Errorf("sessions count = %d, want 0", got)
	}
	events := authLoginEvents(t, test.database, user.ID)
	if len(events) != 1 || events[0].EventOutcome != "FAILED" {
		t.Fatalf("disabled user login audits = %+v, want one FAILED event", events)
	}
}

func TestChangePassword(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	sessions := []LoginResult{
		test.login(t, testEmail, testPassword),
		test.login(t, testEmail, testPassword),
		test.login(t, testEmail, testPassword),
	}
	actor, err := test.service.Authenticate(context.Background(), sessions[0].Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	resetToken, _, err := test.service.CreateResetToken(
		context.Background(), actor, testClient(), user.ID,
	)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}

	const newPassword = "a whole new password"
	revoked, err := test.service.ChangePassword(
		context.Background(), actor, testClient(), testPassword, newPassword,
	)
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if revoked != 2 {
		t.Errorf("ChangePassword revoked %d sessions, want 2", revoked)
	}

	if _, err := test.service.Authenticate(context.Background(), sessions[0].Token); err != nil {
		t.Errorf("Authenticate with the current session after the change = %v, want nil", err)
	}
	for index, session := range sessions[1:] {
		if _, err := test.service.Authenticate(context.Background(), session.Token); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate with revoked session %d = %v, want ErrUnauthenticated", index+2, err)
		}
	}
	if err := test.service.UseResetToken(
		context.Background(), resetToken, "another correct horse", testClient(),
	); !errors.Is(err, ErrInvalidResetToken) {
		t.Errorf("UseResetToken after the change = %v, want ErrInvalidResetToken", err)
	}

	if _, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: testPassword},
		testClient(),
	); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("Login with the old password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: newPassword},
		testClient(),
	); err != nil {
		t.Errorf("Login with the new password = %v, want nil", err)
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.PasswordHash == nil {
		t.Fatal("identity password hash is nil after the change")
	}
	if identity.Version != 2 {
		t.Errorf("identity version after the change = %d, want 2", identity.Version)
	}
	matches, err := VerifyPassword(context.Background(), newPassword, *identity.PasswordHash)
	if err != nil || !matches {
		t.Errorf("VerifyPassword(new password) = %v/%v, want true/nil", matches, err)
	}

	var succeeded int64
	if err := test.database.Raw(
		"SELECT count(*) FROM login_attempts WHERE succeeded AND email_hash = ?", emailHash(testEmail),
	).Scan(&succeeded).Error; err != nil {
		t.Fatalf("count succeeded attempts: %v", err)
	}
	if succeeded != 5 {
		t.Errorf("succeeded attempts = %d, want 5 (three logins, the change, and the new-password login)", succeeded)
	}

	events := authEventsNamed(t, test.database, user.ID, "simple_siem.auth.password_changed")
	if len(events) != 1 {
		t.Fatalf("ChangePassword wrote %d password_changed events, want 1", len(events))
	}
	event := events[0]
	if event.EventCategory != "AUTHENTICATION" || event.EventOutcome != "SUCCESS" || event.ActorType != "USER" {
		t.Errorf("password change audit = %s/%s/%s, want AUTHENTICATION/SUCCESS/USER",
			event.EventCategory, event.EventOutcome, event.ActorType)
	}
	if event.ActorID == nil || *event.ActorID != user.ID {
		t.Errorf("password change audit actor id = %v, want %q", event.ActorID, user.ID)
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != actor.SessionID {
		t.Errorf("password change audit actor session id = %v, want %q", event.ActorSessionID, actor.SessionID)
	}
	if event.TargetType != "USER" || event.TargetID != user.ID || event.Action != "change_password" {
		t.Errorf("password change audit target = %q/%q action %q, want USER/%q change_password",
			event.TargetType, event.TargetID, event.Action, user.ID)
	}
	changes := storedChanges(t, event)
	if changes["revokedCount"] != float64(revoked) {
		t.Errorf("password change audit revokedCount = %v, want %d", changes["revokedCount"], revoked)
	}

	logged := test.logs.String()
	for _, secret := range []string{testPassword, newPassword} {
		if strings.Contains(logged, secret) {
			t.Errorf("logs contain the password %q: %s", secret, logged)
		}
	}
	var auditText string
	if err := test.database.Raw(
		"SELECT COALESCE(string_agg(changes::text, ' '), '') FROM audit_events",
	).Scan(&auditText).Error; err != nil {
		t.Fatalf("read audit changes: %v", err)
	}
	for _, secret := range []string{testPassword, newPassword} {
		if strings.Contains(auditText, secret) {
			t.Errorf("audit changes contain the password %q: %s", secret, auditText)
		}
	}
}

func TestChangePasswordRejectsWrongCurrentPassword(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	const newPassword = "a whole new password"

	revoked, err := test.service.ChangePassword(
		context.Background(), actor, testClient(), testPassword+"-wrong", newPassword,
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("ChangePassword with a wrong current password = %v, want ErrInvalidCredentials", err)
	}
	if revoked != 0 {
		t.Errorf("ChangePassword revoked %d sessions, want 0", revoked)
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.PasswordHash == nil {
		t.Fatal("identity password hash is nil")
	}
	matches, err := VerifyPassword(context.Background(), testPassword, *identity.PasswordHash)
	if err != nil || !matches {
		t.Errorf("VerifyPassword(old password) after the rejection = %v/%v, want true/nil", matches, err)
	}
	matches, err = VerifyPassword(context.Background(), newPassword, *identity.PasswordHash)
	if err != nil {
		t.Fatalf("VerifyPassword(new password): %v", err)
	}
	if matches {
		t.Error("VerifyPassword(new password) after the rejection = true, want false")
	}
	if identity.Version != 1 {
		t.Errorf("identity version after the rejection = %d, want 1", identity.Version)
	}

	var failed int64
	if err := test.database.Raw(
		"SELECT count(*) FROM login_attempts WHERE NOT succeeded AND email_hash = ?", emailHash(testEmail),
	).Scan(&failed).Error; err != nil {
		t.Fatalf("count failed attempts: %v", err)
	}
	if failed != 1 {
		t.Errorf("failed attempts = %d, want 1 (the rejected change)", failed)
	}

	events := authEventsNamed(t, test.database, user.ID, "simple_siem.auth.password_change")
	if len(events) != 1 {
		t.Fatalf("rejected change wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventOutcome != "FAILED" || event.ActorType != "USER" {
		t.Errorf("rejected change audit = %s/%s, want FAILED/USER", event.EventOutcome, event.ActorType)
	}
	if event.ActorID == nil || *event.ActorID != user.ID {
		t.Errorf("rejected change audit actor id = %v, want %q", event.ActorID, user.ID)
	}
	if event.TargetType != "USER" || event.TargetID != user.ID || event.Action != "change_password" {
		t.Errorf("rejected change audit target = %q/%q action %q, want USER/%q change_password",
			event.TargetType, event.TargetID, event.Action, user.ID)
	}
	changes := storedChanges(t, event)
	if changes["reason"] != "invalid_current_password" {
		t.Errorf("rejected change audit reason = %v, want invalid_current_password", changes["reason"])
	}
	if strings.Contains(string(event.Changes), testPassword) || strings.Contains(string(event.Changes), newPassword) {
		t.Errorf("rejected change audit contains a password: %s", event.Changes)
	}
}

func TestChangePasswordRateLimited(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	for attempt := 0; attempt < emailFailureLimit; attempt++ {
		insertFailedAttempt(t, test.database, testEmail, fmt.Sprintf("192.0.2.%d", attempt+10), time.Now().Add(-time.Minute))
	}
	attemptsBefore := countRows(t, test.database, "login_attempts")
	sessionsBefore := countRows(t, test.database, "sessions")
	eventsBefore := countRows(t, test.database, "audit_events")
	var identityBefore Identity
	if err := test.database.Where("user_id = ?", actor.UserID).First(&identityBefore).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}

	revoked, err := test.service.ChangePassword(
		context.Background(), actor, testClient(), testPassword, "a whole new password",
	)
	var rateLimited RateLimitedError
	if !errors.As(err, &rateLimited) {
		t.Fatalf("ChangePassword over the email limit = %v, want RateLimitedError", err)
	}
	if revoked != 0 {
		t.Errorf("ChangePassword revoked %d sessions, want 0", revoked)
	}
	if got := countRows(t, test.database, "login_attempts"); got != attemptsBefore {
		t.Errorf("login attempts = %d after a rate-limited change, want %d", got, attemptsBefore)
	}
	if got := countRows(t, test.database, "sessions"); got != sessionsBefore {
		t.Errorf("sessions = %d after a rate-limited change, want %d", got, sessionsBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after a rate-limited change, want %d", got, eventsBefore)
	}
	var identityAfter Identity
	if err := test.database.Where("user_id = ?", actor.UserID).First(&identityAfter).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identityAfter.PasswordHash == nil || identityBefore.PasswordHash == nil ||
		*identityAfter.PasswordHash != *identityBefore.PasswordHash || identityAfter.Version != identityBefore.Version {
		t.Error("a rate-limited change altered the identity")
	}
	if !strings.Contains(test.logs.String(), "login rate limited") {
		t.Errorf("logs do not contain the rate-limit warning: %s", test.logs.String())
	}
}

func TestChangePasswordValidatesNewPasswordBeforeReservation(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	for attempt := 0; attempt < emailFailureLimit; attempt++ {
		insertFailedAttempt(t, test.database, testEmail, fmt.Sprintf("192.0.2.%d", attempt+10), time.Now().Add(-time.Minute))
	}
	attemptsBefore := countRows(t, test.database, "login_attempts")
	eventsBefore := countRows(t, test.database, "audit_events")
	var identityBefore Identity
	if err := test.database.Where("user_id = ?", actor.UserID).First(&identityBefore).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}

	revoked, err := test.service.ChangePassword(
		context.Background(), actor, testClient(), testPassword, strings.Repeat("a", 11),
	)
	if !errors.Is(err, ErrPasswordLength) {
		t.Fatalf("ChangePassword over the limit with an 11-character password = %v, want ErrPasswordLength", err)
	}
	if revoked != 0 {
		t.Errorf("ChangePassword revoked %d sessions, want 0", revoked)
	}
	if got := countRows(t, test.database, "login_attempts"); got != attemptsBefore {
		t.Errorf("login attempts = %d after a short new password, want %d (no reservation)", got, attemptsBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after a short new password, want %d", got, eventsBefore)
	}
	var identityAfter Identity
	if err := test.database.Where("user_id = ?", actor.UserID).First(&identityAfter).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identityAfter.PasswordHash == nil || identityBefore.PasswordHash == nil ||
		*identityAfter.PasswordHash != *identityBefore.PasswordHash || identityAfter.Version != identityBefore.Version {
		t.Error("a rejected short password altered the identity")
	}
}

func TestChangePasswordRejectsOverlongCurrentPassword(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	revoked, err := test.service.ChangePassword(
		context.Background(), actor, testClient(), strings.Repeat("a", 129), "a whole new password",
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("ChangePassword with a 129-rune current password = %v, want ErrInvalidCredentials", err)
	}
	if revoked != 0 {
		t.Errorf("ChangePassword revoked %d sessions, want 0", revoked)
	}

	var failed int64
	if err := test.database.Raw(
		"SELECT count(*) FROM login_attempts WHERE NOT succeeded AND email_hash = ?", emailHash(testEmail),
	).Scan(&failed).Error; err != nil {
		t.Fatalf("count failed attempts: %v", err)
	}
	if failed != 1 {
		t.Errorf("failed attempts = %d, want 1 (the rejected change)", failed)
	}
	events := authEventsNamed(t, test.database, user.ID, "simple_siem.auth.password_change")
	if len(events) != 1 || events[0].EventOutcome != "FAILED" {
		t.Fatalf("overlong current password audits = %+v, want one FAILED event", events)
	}
	if changes := storedChanges(t, events[0]); changes["reason"] != "invalid_current_password" {
		t.Errorf("overlong current password reason = %v, want invalid_current_password", changes["reason"])
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	matches, err := VerifyPassword(context.Background(), testPassword, *identity.PasswordHash)
	if err != nil || !matches {
		t.Errorf("VerifyPassword(old password) = %v/%v, want true/nil", matches, err)
	}
}

func TestChangePasswordWithConcurrentLoginRehash(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	oldHash := oldPasswordHash(t, testPassword)
	if err := test.database.Exec(
		"UPDATE user_identities SET password_hash = ? WHERE user_id = ?", oldHash, user.ID,
	).Error; err != nil {
		t.Fatalf("store old password hash: %v", err)
	}
	const newPassword = "a whole new password"

	userLocked := make(chan struct{})
	releaseUser := make(chan struct{})
	lockResult := make(chan error, 1)
	go func() {
		lockResult <- test.database.WithContext(context.Background()).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(
				"SELECT id FROM users WHERE id = ? FOR NO KEY UPDATE", user.ID,
			).Error; err != nil {
				return err
			}
			close(userLocked)
			<-releaseUser
			return nil
		})
	}()
	<-userLocked

	type changeResult struct {
		revoked int64
		err     error
	}
	changed := make(chan changeResult, 1)
	go func() {
		revoked, err := test.service.ChangePassword(
			context.Background(), actor, testClient(), testPassword, newPassword,
		)
		changed <- changeResult{revoked: revoked, err: err}
	}()
	waitForLockWaits(t, test.database, 1)

	loginDone := make(chan error, 1)
	go func() {
		_, err := test.service.Login(
			context.Background(),
			LoginRequest{Email: testEmail, Password: testPassword},
			testClient(),
		)
		loginDone <- err
	}()
	waitForLockWaits(t, test.database, 2)
	close(releaseUser)
	if err := <-lockResult; err != nil {
		t.Fatalf("release the user lock: %v", err)
	}

	result := <-changed
	if loginErr := <-loginDone; loginErr != nil && !errors.Is(loginErr, ErrInvalidCredentials) {
		t.Errorf("concurrent login = %v, want nil or ErrInvalidCredentials", loginErr)
	}
	if result.err != nil {
		t.Fatalf("ChangePassword with a concurrent login rehash = %v, want nil", result.err)
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.PasswordHash == nil {
		t.Fatal("identity password hash is nil after the change")
	}
	matches, err := VerifyPassword(context.Background(), newPassword, *identity.PasswordHash)
	if err != nil || !matches {
		t.Errorf("VerifyPassword(new password) = %v/%v, want true/nil", matches, err)
	}
	matches, err = VerifyPassword(context.Background(), testPassword, *identity.PasswordHash)
	if err != nil {
		t.Fatalf("VerifyPassword(old password): %v", err)
	}
	if matches {
		t.Error("VerifyPassword(old password) after the change = true, want false")
	}
}

func TestChangePasswordRejectsShortNewPassword(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	attemptsBefore := countRows(t, test.database, "login_attempts")
	eventsBefore := countRows(t, test.database, "audit_events")
	var identityBefore Identity
	if err := test.database.Where("user_id = ?", actor.UserID).First(&identityBefore).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}

	revoked, err := test.service.ChangePassword(
		context.Background(), actor, testClient(), testPassword, strings.Repeat("a", 11),
	)
	if !errors.Is(err, ErrPasswordLength) {
		t.Fatalf("ChangePassword with an 11-character password = %v, want ErrPasswordLength", err)
	}
	if revoked != 0 {
		t.Errorf("ChangePassword revoked %d sessions, want 0", revoked)
	}
	if got := countRows(t, test.database, "login_attempts"); got != attemptsBefore {
		t.Errorf("login attempts = %d after a short new password, want %d", got, attemptsBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after a short new password, want %d", got, eventsBefore)
	}
	var identityAfter Identity
	if err := test.database.Where("user_id = ?", actor.UserID).First(&identityAfter).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identityAfter.PasswordHash == nil || identityBefore.PasswordHash == nil ||
		*identityAfter.PasswordHash != *identityBefore.PasswordHash || identityAfter.Version != identityBefore.Version {
		t.Error("a rejected short password altered the identity")
	}
}

func TestChangePasswordFailureAuditSurvivesCanceledContext(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	original := test.service.provider
	test.service.provider = cancelOnInvalidProvider{provider: original, cancel: cancel}
	t.Cleanup(func() { test.service.provider = original })

	revoked, err := test.service.ChangePassword(
		ctx, actor, testClient(), testPassword+"-wrong", "a whole new password",
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("ChangePassword with a wrong password and a canceled context = %v, want ErrInvalidCredentials", err)
	}
	if revoked != 0 {
		t.Errorf("ChangePassword revoked %d sessions, want 0", revoked)
	}

	var failed int64
	if err := test.database.Raw(
		"SELECT count(*) FROM login_attempts WHERE NOT succeeded AND email_hash = ?", emailHash(testEmail),
	).Scan(&failed).Error; err != nil {
		t.Fatalf("count failed attempts: %v", err)
	}
	if failed != 1 {
		t.Errorf("failed attempts = %d, want 1 (the attempt row is kept)", failed)
	}
	events := authEventsNamed(t, test.database, actor.UserID, "simple_siem.auth.password_change")
	if len(events) != 1 {
		t.Fatalf("canceled password change wrote %d FAILED audits, want 1", len(events))
	}
	if events[0].EventOutcome != "FAILED" {
		t.Errorf("canceled password change audit outcome = %q, want FAILED", events[0].EventOutcome)
	}
	if changes := storedChanges(t, events[0]); changes["reason"] != "invalid_current_password" {
		t.Errorf("canceled password change reason = %v, want invalid_current_password", changes["reason"])
	}
}

func TestChangePasswordRejectsDisabledUser(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	attemptsBefore := countRows(t, test.database, "login_attempts")
	eventsBefore := countRows(t, test.database, "audit_events")
	sessionsBefore := countRows(t, test.database, "sessions")
	var identityBefore Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identityBefore).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}

	changeErr := runWhileUserLocked(t, test.database, user.ID, func(tx *gorm.DB) error {
		return tx.Exec("UPDATE users SET status = 'DISABLED' WHERE id = ?", user.ID).Error
	}, func() error {
		_, err := test.service.ChangePassword(
			context.Background(), actor, testClient(), testPassword, "a whole new password",
		)
		return err
	})
	if !errors.Is(changeErr, ErrUnauthenticated) {
		t.Fatalf("ChangePassword for a user disabled during the change = %v, want ErrUnauthenticated", changeErr)
	}
	if got := countRows(t, test.database, "login_attempts"); got != attemptsBefore {
		t.Errorf("login attempts = %d after the rejection, want %d (the attempt row is deleted)", got, attemptsBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after the rejection, want %d", got, eventsBefore)
	}
	if got := countRows(t, test.database, "sessions"); got != sessionsBefore {
		t.Errorf("sessions = %d after the rejection, want %d", got, sessionsBefore)
	}
	var identityAfter Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identityAfter).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identityAfter.PasswordHash == nil || identityBefore.PasswordHash == nil ||
		*identityAfter.PasswordHash != *identityBefore.PasswordHash || identityAfter.Version != identityBefore.Version {
		t.Error("a rejected change altered the identity")
	}
}

func TestChangePasswordRejectsRevokedSession(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	attemptsBefore := countRows(t, test.database, "login_attempts")
	eventsBefore := countRows(t, test.database, "audit_events")
	sessionsBefore := countRows(t, test.database, "sessions")
	var identityBefore Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identityBefore).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}

	sessionsAfterDelete := sessionsBefore - 1
	changeErr := runWhileUserLocked(t, test.database, user.ID, func(tx *gorm.DB) error {
		return tx.Exec(
			"DELETE FROM sessions WHERE id = ? AND user_id = ?", actor.SessionID, actor.UserID,
		).Error
	}, func() error {
		_, err := test.service.ChangePassword(
			context.Background(), actor, testClient(), testPassword, "a whole new password",
		)
		return err
	})
	if !errors.Is(changeErr, ErrUnauthenticated) {
		t.Fatalf("ChangePassword for a revoked session = %v, want ErrUnauthenticated", changeErr)
	}
	if got := countRows(t, test.database, "login_attempts"); got != attemptsBefore {
		t.Errorf("login attempts = %d after the rejection, want %d (the attempt row is deleted)", got, attemptsBefore)
	}
	if got := countRows(t, test.database, "audit_events"); got != eventsBefore {
		t.Errorf("audit events = %d after the rejection, want %d", got, eventsBefore)
	}
	if got := countRows(t, test.database, "sessions"); got != sessionsAfterDelete {
		t.Errorf("sessions = %d after the rejection, want %d", got, sessionsAfterDelete)
	}
	var identityAfter Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identityAfter).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identityAfter.PasswordHash == nil || identityBefore.PasswordHash == nil ||
		*identityAfter.PasswordHash != *identityBefore.PasswordHash || identityAfter.Version != identityBefore.Version {
		t.Error("a rejected change altered the identity")
	}
}

func TestChangePasswordRejectsCredentialChange(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}

	identityLocked := make(chan struct{})
	releaseIdentity := make(chan struct{})
	lockResult := make(chan error, 1)
	go func() {
		lockResult <- test.database.WithContext(context.Background()).Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(
				"SELECT id FROM user_identities WHERE id = ? FOR UPDATE", identity.ID,
			).Error; err != nil {
				return err
			}
			if err := tx.Exec(
				"UPDATE user_identities SET version = version + 1 WHERE id = ?", identity.ID,
			).Error; err != nil {
				return err
			}
			close(identityLocked)
			<-releaseIdentity
			return nil
		})
	}()
	<-identityLocked

	type changeResult struct {
		revoked int64
		err     error
	}
	changed := make(chan changeResult, 1)
	go func() {
		revoked, err := test.service.ChangePassword(
			context.Background(), actor, testClient(), testPassword, "a whole new password",
		)
		changed <- changeResult{revoked: revoked, err: err}
	}()
	waitForLockWaits(t, test.database, 1)
	close(releaseIdentity)
	if err := <-lockResult; err != nil {
		t.Fatalf("release the identity lock: %v", err)
	}

	result := <-changed
	if !errors.Is(result.err, ErrInvalidCredentials) {
		t.Fatalf("ChangePassword after a credential change = %v, want ErrInvalidCredentials", result.err)
	}
	if result.revoked != 0 {
		t.Errorf("ChangePassword revoked %d sessions, want 0", result.revoked)
	}

	var stored Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&stored).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if stored.PasswordHash == nil {
		t.Fatal("identity password hash is nil")
	}
	matches, err := VerifyPassword(context.Background(), testPassword, *stored.PasswordHash)
	if err != nil || !matches {
		t.Errorf("VerifyPassword(old password) after the rejection = %v/%v, want true/nil", matches, err)
	}

	var failed int64
	if err := test.database.Raw(
		"SELECT count(*) FROM login_attempts WHERE NOT succeeded AND email_hash = ?", emailHash(testEmail),
	).Scan(&failed).Error; err != nil {
		t.Fatalf("count failed attempts: %v", err)
	}
	if failed != 1 {
		t.Errorf("failed attempts = %d, want 1 (the rejected change)", failed)
	}

	events := authEventsNamed(t, test.database, user.ID, "simple_siem.auth.password_change")
	if len(events) != 1 {
		t.Fatalf("credential-change rejection wrote %d audit events, want 1", len(events))
	}
	if events[0].EventOutcome != "FAILED" {
		t.Errorf("credential-change audit outcome = %q, want FAILED", events[0].EventOutcome)
	}
	changes := storedChanges(t, events[0])
	if changes["reason"] != "credential_changed" {
		t.Errorf("credential-change audit reason = %v, want credential_changed", changes["reason"])
	}
}

func authEventsNamed(t *testing.T, db *gorm.DB, targetID, name string) []storedAuditEvent {
	t.Helper()
	var events []storedAuditEvent
	for _, event := range auditEventsForTarget(t, db, targetID) {
		if event.EventName == name {
			events = append(events, event)
		}
	}
	return events
}

func TestListSessions(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	logins := []LoginResult{
		test.login(t, testEmail, testPassword),
		test.login(t, testEmail, testPassword),
		test.login(t, testEmail, testPassword),
	}
	actors := make([]Actor, len(logins))
	for index, login := range logins {
		actor, err := test.service.Authenticate(context.Background(), login.Token)
		if err != nil {
			t.Fatalf("Authenticate session %d: %v", index+1, err)
		}
		actors[index] = actor
	}
	ages := []string{"3 minutes", "2 minutes", "1 minute"}
	for index, actor := range actors {
		if err := test.database.Exec(
			"UPDATE sessions SET created_at = now() - interval '"+ages[index]+"' WHERE id = ?", actor.SessionID,
		).Error; err != nil {
			t.Fatalf("age session %d: %v", index+1, err)
		}
	}
	if err := test.database.Exec(
		"UPDATE sessions SET idle_expires_at = now() - interval '1 minute' WHERE id = ?", actors[2].SessionID,
	).Error; err != nil {
		t.Fatalf("expire session 3: %v", err)
	}

	sessions, err := test.service.ListSessions(context.Background(), actors[0])
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("ListSessions returned %d sessions, want 2 live ones", len(sessions))
	}
	if sessions[0].ID != actors[1].SessionID || sessions[1].ID != actors[0].SessionID {
		t.Errorf("ListSessions order = %q, %q, want the newer session first", sessions[0].ID, sessions[1].ID)
	}
	if sessions[0].Current || !sessions[1].Current {
		t.Errorf("ListSessions current flags = %v, %v, want false, true", sessions[0].Current, sessions[1].Current)
	}
	info := sessions[0]
	if info.CreatedAt.IsZero() || info.LastUsedAt.IsZero() || info.IdleExpiresAt.IsZero() || info.AbsoluteExpiresAt.IsZero() {
		t.Errorf("ListSessions left a time zero: %+v", info)
	}
	if info.ClientIP == nil || *info.ClientIP != "192.0.2.7" {
		t.Errorf("ListSessions client ip = %v, want 192.0.2.7", info.ClientIP)
	}
	if info.UserAgent != "test-agent" {
		t.Errorf("ListSessions user agent = %q, want test-agent", info.UserAgent)
	}
	if info.AuthProvider != ProviderLocal {
		t.Errorf("ListSessions auth provider = %q, want %q", info.AuthProvider, ProviderLocal)
	}

	sessionType := reflect.TypeOf(SessionInfo{})
	for index := 0; index < sessionType.NumField(); index++ {
		if name := sessionType.Field(index).Name; strings.Contains(strings.ToLower(name), "token") {
			t.Errorf("SessionInfo field %q could hold token data", name)
		}
	}
	encoded := fmt.Sprintf("%+v", sessions)
	for _, login := range logins {
		if strings.Contains(encoded, login.Token) {
			t.Errorf("ListSessions output contains the token %q: %s", login.Token, encoded)
		}
	}
}

func TestRevokeSession(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	first := test.login(t, testEmail, testPassword)
	second := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), first.Token)
	if err != nil {
		t.Fatalf("Authenticate current session: %v", err)
	}
	other, err := test.service.Authenticate(context.Background(), second.Token)
	if err != nil {
		t.Fatalf("Authenticate other session: %v", err)
	}

	if err := test.service.RevokeSession(context.Background(), actor, testClient(), other.SessionID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, err := test.service.Authenticate(context.Background(), second.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Authenticate with the revoked session = %v, want ErrUnauthenticated", err)
	}
	if _, err := test.service.Authenticate(context.Background(), first.Token); err != nil {
		t.Errorf("Authenticate with the current session after revoking another = %v, want nil", err)
	}

	events := authEventsNamed(t, test.database, other.SessionID, "simple_siem.auth.session_revoked")
	if len(events) != 1 {
		t.Fatalf("RevokeSession wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventOutcome != "SUCCESS" || event.ActorType != "USER" {
		t.Errorf("revoke audit = %s/%s, want SUCCESS/USER", event.EventOutcome, event.ActorType)
	}
	if event.ActorID == nil || *event.ActorID != user.ID {
		t.Errorf("revoke audit actor id = %v, want %q", event.ActorID, user.ID)
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != actor.SessionID {
		t.Errorf("revoke audit actor session id = %v, want %q", event.ActorSessionID, actor.SessionID)
	}
	if event.TargetType != "SESSION" || event.TargetID != other.SessionID {
		t.Errorf("revoke audit target = %q/%q, want SESSION/%q", event.TargetType, event.TargetID, other.SessionID)
	}
	if changes := storedChanges(t, event); changes["current"] != false {
		t.Errorf("revoke audit current = %v, want false", changes["current"])
	}
}

func TestRevokeCurrentSession(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	login := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if err := test.service.RevokeSession(context.Background(), actor, testClient(), actor.SessionID); err != nil {
		t.Fatalf("RevokeSession on the current session: %v", err)
	}
	if _, err := test.service.Authenticate(context.Background(), login.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("Authenticate after revoking the current session = %v, want ErrUnauthenticated", err)
	}

	events := authEventsNamed(t, test.database, actor.SessionID, "simple_siem.auth.session_revoked")
	if len(events) != 1 {
		t.Fatalf("revoking the current session wrote %d audit events, want 1", len(events))
	}
	if changes := storedChanges(t, events[0]); changes["current"] != true {
		t.Errorf("revoke audit current = %v, want true", changes["current"])
	}
}

func TestRevokeSessionNotFound(t *testing.T) {
	test := newTestService(t)
	test.createAdmin(t, testEmail)
	first := test.login(t, testEmail, testPassword)
	actor, err := test.service.Authenticate(context.Background(), first.Token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	test.createAdmin(t, "other@example.com")
	otherLogin := test.login(t, "other@example.com", testPassword)
	other, err := test.service.Authenticate(context.Background(), otherLogin.Token)
	if err != nil {
		t.Fatalf("Authenticate the other user: %v", err)
	}
	sessionsBefore := countRows(t, test.database, "sessions")

	if err := test.service.RevokeSession(
		context.Background(), actor, testClient(), other.SessionID,
	); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("RevokeSession on another user's session = %v, want ErrSessionNotFound", err)
	}
	if got := countRows(t, test.database, "sessions"); got != sessionsBefore {
		t.Errorf("sessions = %d after revoking another user's session, want %d", got, sessionsBefore)
	}
	if _, err := test.service.Authenticate(context.Background(), otherLogin.Token); err != nil {
		t.Errorf("Authenticate with the other user's session = %v, want nil", err)
	}

	missing := "0190f8dc-6f43-7f0a-8b2f-9c8c0a2d3e4f"
	if err := test.service.RevokeSession(
		context.Background(), actor, testClient(), missing,
	); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("RevokeSession on a missing session = %v, want ErrSessionNotFound", err)
	}
	if got := countRows(t, test.database, "sessions"); got != sessionsBefore {
		t.Errorf("sessions = %d after revoking a missing session, want %d", got, sessionsBefore)
	}
}

func TestLoginRejectsOverlongPassword(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)

	_, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: strings.Repeat("a", 129)},
		testClient(),
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login with an overlong password = %v, want ErrInvalidCredentials", err)
	}
	if got := countRows(t, test.database, "sessions"); got != 0 {
		t.Errorf("sessions count = %d, want 0", got)
	}
	events := authLoginEvents(t, test.database, user.ID)
	if len(events) != 1 || events[0].EventOutcome != "FAILED" {
		t.Fatalf("overlong login audits = %+v, want one FAILED event", events)
	}
}

func TestLoginDoesNotRehashDisabledUser(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)
	oldHash := oldPasswordHash(t, testPassword)
	if err := test.database.Exec(
		"UPDATE user_identities SET password_hash = ? WHERE user_id = ?", oldHash, user.ID,
	).Error; err != nil {
		t.Fatalf("store old password hash: %v", err)
	}
	if err := test.database.Exec("UPDATE users SET status = 'DISABLED' WHERE id = ?", user.ID).Error; err != nil {
		t.Fatalf("disable user: %v", err)
	}

	if _, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: testPassword},
		testClient(),
	); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login for a disabled user with a t=1 hash = %v, want ErrInvalidCredentials", err)
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.PasswordHash == nil || *identity.PasswordHash != oldHash {
		t.Errorf("stored hash changed for a disabled user: %v", identity.PasswordHash)
	}
}

func TestLoginRehashesOldHash(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)

	oldHash := oldPasswordHash(t, testPassword)
	if err := test.database.Exec(
		"UPDATE user_identities SET password_hash = ? WHERE user_id = ?", oldHash, user.ID,
	).Error; err != nil {
		t.Fatalf("store old password hash: %v", err)
	}

	if _, err := test.service.Login(
		context.Background(),
		LoginRequest{Email: testEmail, Password: testPassword},
		testClient(),
	); err != nil {
		t.Fatalf("Login with a t=1 hash: %v", err)
	}

	var identity Identity
	if err := test.database.Where("user_id = ?", user.ID).First(&identity).Error; err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if identity.PasswordHash == nil || !strings.HasPrefix(*identity.PasswordHash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("stored hash after rehash = %v, want t=2 parameters", identity.PasswordHash)
	}
	if identity.Version != 2 {
		t.Errorf("identity version after rehash = %d, want 2", identity.Version)
	}
}

func oldPasswordHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	key := argon2.IDKey([]byte(password), salt, 1, argonMemory, argonThreads, keyLength)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		1,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func authLoginEvents(t *testing.T, db *gorm.DB, targetID string) []storedAuditEvent {
	t.Helper()
	var events []storedAuditEvent
	for _, event := range auditEventsForTarget(t, db, targetID) {
		if event.EventName == "simple_siem.auth.login" {
			events = append(events, event)
		}
	}
	return events
}

func testClient() ClientInfo {
	return ClientInfo{
		IP:        net.ParseIP("192.0.2.7"),
		UserAgent: "test-agent",
		RequestID: "request-1",
	}
}

func emailHash(email string) []byte {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return sum[:]
}

func storedUser(t *testing.T, db *gorm.DB, userID string) User {
	t.Helper()
	var user User
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		t.Fatalf("read user %q: %v", userID, err)
	}
	return user
}

func TestTruncateUserAgent(t *testing.T) {
	tests := []struct {
		name  string
		agent string
		want  string
	}{
		{"short", "test-agent", "test-agent"},
		{"long ascii", strings.Repeat("a", 600), strings.Repeat("a", 512)},
		{"multibyte at the boundary", strings.Repeat("a", 511) + "é", strings.Repeat("a", 511)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := truncateUserAgent(test.agent); got != test.want {
				t.Errorf("truncateUserAgent returned %d bytes, want %d", len(got), len(test.want))
			}
		})
	}
}

type cancelingProvider struct {
	cancel context.CancelFunc
}

func (provider cancelingProvider) Name() string {
	return ProviderLocal
}

func (provider cancelingProvider) Authenticate(context.Context, LoginRequest) (ExternalIdentity, error) {
	provider.cancel()
	return ExternalIdentity{}, context.Canceled
}

type cancelOnInvalidProvider struct {
	provider IdentityProvider
	cancel   context.CancelFunc
}

func (provider cancelOnInvalidProvider) Name() string {
	return provider.provider.Name()
}

func (provider cancelOnInvalidProvider) Authenticate(ctx context.Context, request LoginRequest) (ExternalIdentity, error) {
	identity, err := provider.provider.Authenticate(ctx, request)
	if errors.Is(err, ErrInvalidCredentials) {
		provider.cancel()
	}
	return identity, err
}

type signalingProvider struct {
	provider IdentityProvider
	entered  chan struct{}
	release  chan struct{}
}

func (provider signalingProvider) Name() string {
	return provider.provider.Name()
}

func (provider signalingProvider) Authenticate(ctx context.Context, request LoginRequest) (ExternalIdentity, error) {
	provider.entered <- struct{}{}
	<-provider.release
	return provider.provider.Authenticate(ctx, request)
}

type fixedProvider struct {
	identity ExternalIdentity
}

func (provider fixedProvider) Name() string {
	return ProviderLocal
}

func (provider fixedProvider) Authenticate(context.Context, LoginRequest) (ExternalIdentity, error) {
	return provider.identity, nil
}

type storedSession struct {
	ID                string    `gorm:"column:id"`
	UserID            string    `gorm:"column:user_id"`
	TokenHash         []byte    `gorm:"column:token_hash"`
	AuthProvider      string    `gorm:"column:auth_provider"`
	IdleExpiresAt     time.Time `gorm:"column:idle_expires_at"`
	AbsoluteExpiresAt time.Time `gorm:"column:absolute_expires_at"`
	LastUsedAt        time.Time `gorm:"column:last_used_at"`
	ClientIP          string    `gorm:"column:client_ip"`
	UserAgent         string    `gorm:"column:user_agent"`
}

type storedAttempt struct {
	Succeeded bool   `gorm:"column:succeeded"`
	ClientIP  string `gorm:"column:client_ip"`
}

type storedAuditEvent struct {
	EventName      string    `gorm:"column:event_name"`
	EventCategory  string    `gorm:"column:event_category"`
	EventOutcome   string    `gorm:"column:event_outcome"`
	ActorType      string    `gorm:"column:actor_type"`
	ActorID        *string   `gorm:"column:actor_id"`
	ActorSessionID *string   `gorm:"column:actor_session_id"`
	RequestID      string    `gorm:"column:request_id"`
	SourceIP       *string   `gorm:"column:source_ip"`
	TargetType     string    `gorm:"column:target_type"`
	TargetID       string    `gorm:"column:target_id"`
	Action         string    `gorm:"column:action"`
	Changes        []byte    `gorm:"column:changes"`
	CreatedAt      time.Time `gorm:"column:created_at"`
}

func auditEventsForTarget(t *testing.T, db *gorm.DB, targetID string) []storedAuditEvent {
	t.Helper()
	var events []storedAuditEvent
	err := db.Raw(`
		SELECT created_at, event_name, event_category, event_outcome, actor_type, actor_id,
		       actor_session_id, request_id, host(source_ip) AS source_ip, target_type,
		       target_id, action, changes
		FROM audit_events
		WHERE target_id = ?
		ORDER BY created_at`, targetID).Scan(&events).Error
	if err != nil {
		t.Fatalf("read audit events for target %q: %v", targetID, err)
	}
	return events
}

func storedChanges(t *testing.T, event storedAuditEvent) map[string]any {
	t.Helper()
	var changes map[string]any
	if err := json.Unmarshal(event.Changes, &changes); err != nil {
		t.Fatalf("decode audit changes %q: %v", event.Changes, err)
	}
	return changes
}

func countRows(t *testing.T, db *gorm.DB, table string) int64 {
	t.Helper()
	var count int64
	if err := db.Raw("SELECT count(*) FROM " + table).Scan(&count).Error; err != nil {
		t.Fatalf("count %s rows: %v", table, err)
	}
	return count
}
