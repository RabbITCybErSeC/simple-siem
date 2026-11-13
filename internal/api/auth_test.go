package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/api"
	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	authTestEmail    = "admin@example.com"
	authTestPassword = "correct horse battery"

	authenticationRequiredBody = `{"error":{"code":"AUTHENTICATION_REQUIRED","message":"authentication required"}}`
)

func TestRequireSessionRejectsInvalidHeaders(t *testing.T) {
	router, _, _, _ := newAuthRouter(t)
	unknownToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))

	tests := []struct {
		name          string
		authorization string
	}{
		{name: "no header"},
		{name: "basic scheme", authorization: "Basic abc"},
		{name: "missing token", authorization: "Bearer"},
		{name: "two spaces", authorization: "Bearer  two spaces"},
		{name: "short token", authorization: "Bearer short"},
		{name: "unknown token", authorization: "Bearer " + unknownToken},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := map[string]string{}
			if test.authorization != "" {
				headers["Authorization"] = test.authorization
			}

			response := get(router, "/api/v1/me", "", headers)

			assertAuthenticationRequired(t, response)
			if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
				t.Errorf("Content-Type = %q, want JSON", contentType)
			}
		})
	}
}

func TestRequireSessionRejectsExpiredSession(t *testing.T) {
	router, service, database, _ := newAuthRouter(t)
	createTestAdmin(t, service)
	token := loginToken(t, router)

	if err := database.Exec("UPDATE sessions SET idle_expires_at = now() - interval '1 minute'").Error; err != nil {
		t.Fatalf("expire the session: %v", err)
	}

	assertAuthenticationRequired(t, get(router, "/api/v1/me", "", bearer(token)))
}

func TestRequireSessionRejectsDisabledUser(t *testing.T) {
	router, service, database, _ := newAuthRouter(t)
	createTestAdmin(t, service)
	token := loginToken(t, router)

	if err := database.Exec("UPDATE users SET status = 'DISABLED' WHERE email = ?", authTestEmail).Error; err != nil {
		t.Fatalf("disable the user: %v", err)
	}

	assertAuthenticationRequired(t, get(router, "/api/v1/me", "", bearer(token)))
}

func TestMeReturnsCurrentUser(t *testing.T) {
	router, service, database, _ := newAuthRouter(t)
	user := createTestAdmin(t, service)
	token := loginToken(t, router)

	var stored struct {
		CreatedAt time.Time `gorm:"column:created_at"`
		UpdatedAt time.Time `gorm:"column:updated_at"`
		Version   int       `gorm:"column:version"`
	}
	err := database.Raw(
		"SELECT created_at, updated_at, version FROM users WHERE id = ?", user.ID,
	).Scan(&stored).Error
	if err != nil {
		t.Fatalf("read stored user: %v", err)
	}

	response := get(router, "/api/v1/me", "", map[string]string{"Authorization": "bearer " + token})
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me = %d, want 200: %s", response.Code, response.Body)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	var body struct {
		ID          string   `json:"id"`
		Email       string   `json:"email"`
		DisplayName string   `json:"displayName"`
		Status      string   `json:"status"`
		Roles       []string `json:"roles"`
		CreatedAt   string   `json:"createdAt"`
		UpdatedAt   string   `json:"updatedAt"`
		Version     int      `json:"version"`
	}
	decodeJSON(t, response, &body)

	if body.ID != user.ID {
		t.Errorf("user id = %q, want %q", body.ID, user.ID)
	}
	if body.Email != authTestEmail {
		t.Errorf("user email = %q, want %q", body.Email, authTestEmail)
	}
	if body.DisplayName != user.DisplayName {
		t.Errorf("user display name = %q, want %q", body.DisplayName, user.DisplayName)
	}
	if body.Status != auth.StatusActive {
		t.Errorf("user status = %q, want %q", body.Status, auth.StatusActive)
	}
	if !slices.Equal(body.Roles, []string{auth.RoleAdmin}) {
		t.Errorf("user roles = %v, want [%s]", body.Roles, auth.RoleAdmin)
	}
	if want := stored.CreatedAt.UTC().Format(time.RFC3339); body.CreatedAt != want {
		t.Errorf("createdAt = %q, want %q", body.CreatedAt, want)
	}
	if want := stored.UpdatedAt.UTC().Format(time.RFC3339); body.UpdatedAt != want {
		t.Errorf("updatedAt = %q, want %q", body.UpdatedAt, want)
	}
	if body.Version != stored.Version {
		t.Errorf("version = %d, want %d", body.Version, stored.Version)
	}
}

func TestUnknownAPIRouteNeedsNoSession(t *testing.T) {
	router, _, _, _ := newAuthRouter(t)

	response := get(router, "/api/v1/nope", "", nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("GET /api/v1/nope = %d, want 404: %s", response.Code, response.Body)
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	decodeJSON(t, response, &body)
	if body.Error.Code != "NOT_FOUND" {
		t.Errorf("error code = %q, want NOT_FOUND", body.Error.Code)
	}
}

func TestLoginSuccess(t *testing.T) {
	router, service, _, _ := newAuthRouter(t)
	user := createTestAdmin(t, service)

	response := login(router, " Admin@Example.com ", authTestPassword)
	if response.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/login = %d, want 200: %s", response.Code, response.Body)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	var body struct {
		SessionToken string         `json:"sessionToken"`
		ExpiresAt    string         `json:"expiresAt"`
		User         map[string]any `json:"user"`
	}
	decodeJSON(t, response, &body)

	if len(body.SessionToken) != 43 {
		t.Errorf("session token %q has %d characters, want 43", body.SessionToken, len(body.SessionToken))
	}
	rawToken, err := base64.RawURLEncoding.DecodeString(body.SessionToken)
	if err != nil || len(rawToken) != 32 {
		t.Errorf("session token decodes to %d bytes (error %v), want 32", len(rawToken), err)
	}

	expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		t.Fatalf("expiresAt %q is not RFC 3339: %v", body.ExpiresAt, err)
	}
	if until := time.Until(expiresAt); until < 11*time.Hour+50*time.Minute || until > 12*time.Hour+10*time.Minute {
		t.Errorf("expiresAt is %v away, want about 12 hours", until)
	}

	if body.User["id"] != user.ID {
		t.Errorf("login user id = %v, want %q", body.User["id"], user.ID)
	}
	if body.User["email"] != authTestEmail {
		t.Errorf("login user email = %v, want %q", body.User["email"], authTestEmail)
	}
	if body.User["displayName"] != "Admin User" {
		t.Errorf("login user displayName = %v, want Admin User", body.User["displayName"])
	}
	roles, ok := body.User["roles"].([]any)
	if !ok || !slices.Equal(roles, []any{auth.RoleAdmin}) {
		t.Errorf("login user roles = %v, want [%s]", body.User["roles"], auth.RoleAdmin)
	}
	if len(body.User) != 4 {
		t.Errorf("login user fields = %v, want only id, email, displayName, roles", body.User)
	}
}

func TestLoginRejectsWrongPasswordLikeUnknownEmail(t *testing.T) {
	router, service, database, _ := newAuthRouter(t)
	createTestAdmin(t, service)

	wrongPassword := login(router, authTestEmail, "the wrong password")
	unknownEmail := login(router, "nobody@example.com", "the wrong password")

	responses := []struct {
		name     string
		response *httptest.ResponseRecorder
	}{
		{name: "wrong password", response: wrongPassword},
		{name: "unknown email", response: unknownEmail},
	}
	for _, test := range responses {
		if test.response.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401: %s", test.name, test.response.Code, test.response.Body)
		}
		if got := test.response.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", test.name, got)
		}
	}
	if want := `{"error":{"code":"AUTHENTICATION_REQUIRED","message":"invalid email or password"}}`; wrongPassword.Body.String() != want {
		t.Errorf("wrong password body = %s, want %s", wrongPassword.Body, want)
	}
	if wrongPassword.Body.String() != unknownEmail.Body.String() {
		t.Errorf("wrong password and unknown email bodies differ: %s and %s", wrongPassword.Body, unknownEmail.Body)
	}

	var sessions int64
	if err := database.Raw("SELECT count(*) FROM sessions").Scan(&sessions).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("failed logins created %d sessions, want 0", sessions)
	}
}

func TestLoginRejectsMalformedBodies(t *testing.T) {
	router, _, _, _ := newAuthRouter(t)
	const secret = "request-body-secret-3f9c"
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid JSON", body: `{"email":"admin@example.com","password":"` + secret + `"`},
		{name: "unknown field", body: `{"email":"admin@example.com","password":"` + secret + `","remember":true}`},
		{name: "missing password", body: `{"email":"` + secret + `"}`},
		{
			name: "trailing value",
			body: `{"email":"admin@example.com","password":"` + secret + `"}{"email":"other@example.com"}`,
		},
		{
			name: "oversized body",
			body: `{"email":"admin@example.com","password":"` + secret + strings.Repeat("a", 5000) + `"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := sendJSON(router, http.MethodPost, "/api/v1/auth/login", "", test.body)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body)
			}
			want := `{"error":{"code":"VALIDATION_ERROR","message":"invalid request body"}}`
			if got := response.Body.String(); got != want {
				t.Errorf("body = %s, want %s", got, want)
			}
			if strings.Contains(response.Body.String(), secret) {
				t.Errorf("body echoes the input: %s", response.Body)
			}
		})
	}
}

func TestLoginRateLimited(t *testing.T) {
	router, service, _, _ := newAuthRouter(t)
	createTestAdmin(t, service)

	for attempt := 1; attempt <= 10; attempt++ {
		response := login(router, authTestEmail, "the wrong password")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d = %d, want 401: %s", attempt, response.Code, response.Body)
		}
	}

	response := login(router, authTestEmail, "the wrong password")
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited login = %d, want 429: %s", response.Code, response.Body)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	retryAfter, err := strconv.Atoi(response.Header().Get("Retry-After"))
	if err != nil || retryAfter < 1 {
		t.Errorf("Retry-After = %q, want at least 1 whole second (error %v)", response.Header().Get("Retry-After"), err)
	}
	want := `{"error":{"code":"RATE_LIMITED","message":"too many failed logins"}}`
	if got := response.Body.String(); got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

func TestLogout(t *testing.T) {
	router, service, database, _ := newAuthRouter(t)
	createTestAdmin(t, service)
	token := loginToken(t, router)

	before := countAuditEvents(t, database)

	response := send(router, http.MethodPost, "/api/v1/auth/logout", "", bearer(token))
	if response.Code != http.StatusNoContent {
		t.Fatalf("POST /api/v1/auth/logout = %d, want 204: %s", response.Code, response.Body)
	}
	if response.Body.Len() != 0 {
		t.Errorf("logout body = %s, want empty", response.Body)
	}

	after := countAuditEvents(t, database)
	if after != before+1 {
		t.Errorf("logout wrote %d audit events, want 1", after-before)
	}

	assertAuthenticationRequired(t, get(router, "/api/v1/me", "", bearer(token)))

	response = send(router, http.MethodPost, "/api/v1/auth/logout", "", nil)
	assertAuthenticationRequired(t, response)
	if got := countAuditEvents(t, database); got != after {
		t.Errorf("logout without a session wrote %d audit events, want 0", got-after)
	}
}

func TestProviders(t *testing.T) {
	router, _, _, _ := newAuthRouter(t)

	response := get(router, "/api/v1/auth/providers", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/providers = %d, want 200: %s", response.Code, response.Body)
	}
	if got, want := response.Body.String(), `{"data":[{"id":"local"}]}`; got != want {
		t.Errorf("providers body = %s, want %s", got, want)
	}
}

func TestLoginNeverLogsSecrets(t *testing.T) {
	router, service, database, logs := newAuthRouter(t)
	createTestAdmin(t, service)

	success := login(router, authTestEmail, authTestPassword)
	if success.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200: %s", success.Code, success.Body)
	}
	var body struct {
		SessionToken string `json:"sessionToken"`
	}
	decodeJSON(t, success, &body)

	const wrongPassword = "wrong-password-secret-8b1e"
	login(router, authTestEmail, wrongPassword)
	login(router, "nobody@example.com", wrongPassword)

	var auditChanges string
	err := database.Raw(
		"SELECT COALESCE(jsonb_agg(changes)::text, '') FROM audit_events",
	).Scan(&auditChanges).Error
	if err != nil {
		t.Fatalf("read audit changes: %v", err)
	}

	secrets := map[string]string{
		"password":       authTestPassword,
		"session token":  body.SessionToken,
		"failed attempt": wrongPassword,
	}
	for name, secret := range secrets {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("request log contains the %s: %s", name, logs)
		}
		if strings.Contains(auditChanges, secret) {
			t.Errorf("audit changes contain the %s: %s", name, auditChanges)
		}
	}
}

func newAuthRouter(t *testing.T) (*gin.Engine, *auth.Service, *gorm.DB, *bytes.Buffer) {
	t.Helper()
	database := databasetest.New(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	service, err := auth.NewService(
		context.Background(),
		database,
		auth.Settings{IdleTimeout: 30 * time.Minute, AbsoluteLifetime: 12 * time.Hour},
		logger,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	router := api.NewRouter(api.Dependencies{
		Logger: logger,
		Auth:   service,
	})
	return router, service, database, &logs
}

func createTestAdmin(t *testing.T, service *auth.Service) auth.User {
	t.Helper()
	user, err := service.CreateAdmin(context.Background(), authTestEmail, "Admin User", authTestPassword)
	if err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	return user
}

func login(router http.Handler, email, password string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	return sendJSON(router, http.MethodPost, "/api/v1/auth/login", "", body)
}

func loginToken(t *testing.T, router http.Handler) string {
	t.Helper()
	response := login(router, authTestEmail, authTestPassword)
	if response.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200: %s", response.Code, response.Body)
	}
	var body struct {
		SessionToken string `json:"sessionToken"`
	}
	decodeJSON(t, response, &body)
	return body.SessionToken
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func countAuditEvents(t *testing.T, database *gorm.DB) int64 {
	t.Helper()
	var count int64
	if err := database.Raw("SELECT count(*) FROM audit_events").Scan(&count).Error; err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	return count
}

func sendJSON(router http.Handler, method, target, remoteAddress, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if remoteAddress != "" {
		request.RemoteAddr = remoteAddress
	}
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func assertAuthenticationRequired(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", response.Code, response.Body)
	}
	if got := response.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", got)
	}
	if got := response.Body.String(); got != authenticationRequiredBody {
		t.Errorf("body = %s, want %s", got, authenticationRequiredBody)
	}
}
