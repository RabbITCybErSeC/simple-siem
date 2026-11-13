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
	"net"
	"slices"
	"strings"
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

func TestLoginRehashesOldHash(t *testing.T) {
	test := newTestService(t)
	user := test.createAdmin(t, testEmail)

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	key := argon2.IDKey([]byte(testPassword), salt, 1, argonMemory, argonThreads, keyLength)
	oldHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		1,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
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
