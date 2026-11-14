package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
)

const accountTestNewPassword = "a whole new password"

type sessionBody struct {
	ID                string  `json:"id"`
	CreatedAt         string  `json:"createdAt"`
	LastUsedAt        string  `json:"lastUsedAt"`
	IdleExpiresAt     string  `json:"idleExpiresAt"`
	AbsoluteExpiresAt string  `json:"absoluteExpiresAt"`
	ClientIP          *string `json:"clientIp"`
	UserAgent         string  `json:"userAgent"`
	AuthProvider      string  `json:"authProvider"`
	Current           bool    `json:"current"`
}

type sessionListBody struct {
	Data []sessionBody `json:"data"`
}

func TestChangePassword(t *testing.T) {
	router, service, _, logs := newAPIRouter(t)
	createTestAdmin(t, service)
	currentToken := loginToken(t, router)
	otherToken := loginToken(t, router)

	response := sendJSONWithHeaders(router, http.MethodPost, "/api/v1/me/password", bearer(currentToken),
		fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, authTestPassword, accountTestNewPassword))
	if response.Code != http.StatusNoContent {
		t.Fatalf("POST /api/v1/me/password = %d, want 204: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)

	if response := get(router, "/api/v1/me", "", bearer(currentToken)); response.Code != http.StatusOK {
		t.Errorf("GET /api/v1/me with the current session = %d, want 200: %s", response.Code, response.Body)
	}
	if response := get(router, "/api/v1/me", "", bearer(otherToken)); response.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/me with the revoked session = %d, want 401: %s", response.Code, response.Body)
	}
	if response := login(router, authTestEmail, authTestPassword); response.Code != http.StatusUnauthorized {
		t.Errorf("Login with the old password = %d, want 401: %s", response.Code, response.Body)
	}
	if response := login(router, authTestEmail, accountTestNewPassword); response.Code != http.StatusOK {
		t.Errorf("Login with the new password = %d, want 200: %s", response.Code, response.Body)
	}

	logged := logs.String()
	for _, password := range []string{authTestPassword, accountTestNewPassword} {
		if strings.Contains(logged, password) {
			t.Errorf("logs contain the password %q: %s", password, logged)
		}
	}
}

func TestChangePasswordRejectsWrongCurrentPassword(t *testing.T) {
	const wrongPassword = "the wrong current password"
	router, service, _, logs := newAPIRouter(t)
	createTestAdmin(t, service)
	token := loginToken(t, router)

	response := sendJSONWithHeaders(router, http.MethodPost, "/api/v1/me/password", bearer(token),
		fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, wrongPassword, accountTestNewPassword))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v1/me/password with a wrong current password = %d, want 400: %s",
			response.Code, response.Body)
	}
	assertNoStore(t, response)
	want := `{"error":{"code":"VALIDATION_ERROR","message":"current password is incorrect"}}`
	if got := response.Body.String(); got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
	if response := login(router, authTestEmail, authTestPassword); response.Code != http.StatusOK {
		t.Errorf("Login with the unchanged password = %d, want 200: %s", response.Code, response.Body)
	}

	logged := logs.String()
	for _, password := range []string{wrongPassword, accountTestNewPassword} {
		if strings.Contains(logged, password) {
			t.Errorf("logs contain the password %q: %s", password, logged)
		}
	}
}

func TestChangePasswordRateLimited(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	createTestAdmin(t, service)
	token := loginToken(t, router)

	hash := sha256.Sum256([]byte(authTestEmail))
	for attempt := 0; attempt < 10; attempt++ {
		err := database.Exec(
			"INSERT INTO login_attempts (email_hash, client_ip, succeeded, created_at) VALUES (decode(?, 'hex'), ?::inet, false, ?)",
			hex.EncodeToString(hash[:]), fmt.Sprintf("192.0.2.%d", attempt+10), time.Now().Add(-time.Minute),
		).Error
		if err != nil {
			t.Fatalf("insert failed login attempt: %v", err)
		}
	}

	response := sendJSONWithHeaders(router, http.MethodPost, "/api/v1/me/password", bearer(token),
		fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, authTestPassword, accountTestNewPassword))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("POST /api/v1/me/password over the limit = %d, want 429: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	retryAfter, err := strconv.Atoi(response.Header().Get("Retry-After"))
	if err != nil || retryAfter < 1 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", response.Header().Get("Retry-After"))
	}
	assertErrorCode(t, response, "RATE_LIMITED", "too many failed logins")
	if response := get(router, "/api/v1/me", "", bearer(token)); response.Code != http.StatusOK {
		t.Errorf("GET /api/v1/me after a rate-limited change = %d, want 200: %s", response.Code, response.Body)
	}
}

func TestChangePasswordRejectsShortNewPassword(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	createTestAdmin(t, service)
	token := loginToken(t, router)

	response := sendJSONWithHeaders(router, http.MethodPost, "/api/v1/me/password", bearer(token),
		fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, authTestPassword, strings.Repeat("a", 11)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("POST /api/v1/me/password with an 11-character password = %d, want 400: %s",
			response.Code, response.Body)
	}
	assertNoStore(t, response)
	want := `{"error":{"code":"VALIDATION_ERROR","message":"` + auth.ErrPasswordLength.Error() + `"}}`
	if got := response.Body.String(); got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
	if response := login(router, authTestEmail, authTestPassword); response.Code != http.StatusOK {
		t.Errorf("Login after a short new password = %d, want 200: %s", response.Code, response.Body)
	}
}

func TestChangePasswordRejectsMalformedBodies(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	createTestAdmin(t, service)
	token := loginToken(t, router)

	tests := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"empty object", `{}`},
		{"missing new password", `{"currentPassword":"current horse battery"}`},
		{"missing current password", `{"newPassword":"another horse battery"}`},
		{"wrong field type", `{"currentPassword":1,"newPassword":"another horse battery"}`},
		{"unknown field", `{"currentPassword":"x","newPassword":"another horse battery","extra":1}`},
		{"not json", `not json`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := sendJSONWithHeaders(
				router, http.MethodPost, "/api/v1/me/password", bearer(token), test.body,
			)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("POST /api/v1/me/password with %s = %d, want 400: %s",
					test.name, response.Code, response.Body)
			}
			assertNoStore(t, response)
			assertErrorCode(t, response, "VALIDATION_ERROR", "invalid request body")
		})
	}
}

func TestListSessions(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	createTestAdmin(t, service)
	firstToken := loginWithUserAgent(t, router, authTestEmail, authTestPassword, "device-one")
	secondToken := loginWithUserAgent(t, router, authTestEmail, authTestPassword, "device-two")
	thirdToken := loginWithUserAgent(t, router, authTestEmail, authTestPassword, "device-three")

	headers := bearer(firstToken)
	listed, _ := listOwnSessions(t, router, headers)
	if len(listed.Data) != 3 {
		t.Fatalf("GET /api/v1/me/sessions returned %d sessions, want 3", len(listed.Data))
	}
	currentID := currentSessionID(t, listed)
	others := make([]string, 0, 2)
	for _, session := range listed.Data {
		if !session.Current {
			others = append(others, session.ID)
		}
	}
	if len(others) != 2 {
		t.Fatalf("non-current sessions = %v, want 2", others)
	}

	if err := database.Exec(
		"UPDATE sessions SET created_at = now() - interval '3 minutes' WHERE id = ?", currentID,
	).Error; err != nil {
		t.Fatalf("age the current session: %v", err)
	}
	if err := database.Exec(
		"UPDATE sessions SET created_at = now() - interval '2 minutes' WHERE id = ?", others[0],
	).Error; err != nil {
		t.Fatalf("age the newer other session: %v", err)
	}
	if err := database.Exec(`
		UPDATE sessions
		SET created_at = now() - interval '1 minute', idle_expires_at = now() - interval '1 minute'
		WHERE id = ?`, others[1]).Error; err != nil {
		t.Fatalf("expire the older other session: %v", err)
	}

	listed, response := listOwnSessions(t, router, headers)
	if len(listed.Data) != 2 {
		t.Fatalf("GET /api/v1/me/sessions returned %d sessions, want the 2 live ones", len(listed.Data))
	}
	if listed.Data[0].ID != others[0] || listed.Data[1].ID != currentID {
		t.Errorf("session order = %q, %q, want the newer session first", listed.Data[0].ID, listed.Data[1].ID)
	}
	if listed.Data[0].Current || !listed.Data[1].Current {
		t.Errorf("current flags = %v, %v, want false, true", listed.Data[0].Current, listed.Data[1].Current)
	}

	userAgents := map[string]bool{}
	for _, session := range listed.Data {
		for _, value := range []string{
			session.CreatedAt, session.LastUsedAt, session.IdleExpiresAt, session.AbsoluteExpiresAt,
		} {
			if _, err := time.Parse(time.RFC3339, value); err != nil {
				t.Errorf("timestamp %q is not RFC 3339: %v", value, err)
			}
			if !strings.HasSuffix(value, "Z") {
				t.Errorf("timestamp %q is not UTC", value)
			}
		}
		if session.ID == "" {
			t.Error("session has no id")
		}
		if session.ClientIP == nil || *session.ClientIP != "192.0.2.1" {
			t.Errorf("clientIp = %v, want 192.0.2.1", session.ClientIP)
		}
		if session.AuthProvider != auth.ProviderLocal {
			t.Errorf("authProvider = %q, want %q", session.AuthProvider, auth.ProviderLocal)
		}
		if session.UserAgent == "" {
			t.Error("session has no user agent")
		}
		userAgents[session.UserAgent] = true
	}
	if len(userAgents) != 2 {
		t.Errorf("session user agents = %v, want two distinct devices", userAgents)
	}
	knownAgents := map[string]bool{"device-one": true, "device-two": true, "device-three": true}
	for agent := range userAgents {
		if !knownAgents[agent] {
			t.Errorf("session user agent = %q, want one of the login devices", agent)
		}
	}

	raw := response.Body.String()
	if !strings.Contains(raw, `"data":[`) {
		t.Errorf("sessions response data is not a JSON array: %s", raw)
	}
	for _, token := range []string{firstToken, secondToken, thirdToken} {
		if strings.Contains(raw, token) {
			t.Errorf("sessions response contains the token %q: %s", token, raw)
		}
	}
}

func TestRevokeSession(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	createTestAdmin(t, service)
	firstToken := loginToken(t, router)
	secondToken := loginToken(t, router)
	listed, _ := listOwnSessions(t, router, bearer(firstToken))
	otherID := otherSessionID(t, listed)

	response := revokeOwnSession(router, bearer(firstToken), otherID)
	if response.Code != http.StatusNoContent {
		t.Fatalf("POST /api/v1/me/sessions/:id/revoke = %d, want 204: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	if response := get(router, "/api/v1/me", "", bearer(secondToken)); response.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/me with the revoked session = %d, want 401: %s", response.Code, response.Body)
	}
	if response := get(router, "/api/v1/me", "", bearer(firstToken)); response.Code != http.StatusOK {
		t.Errorf("GET /api/v1/me with the current session = %d, want 200: %s", response.Code, response.Body)
	}
}

func TestRevokeSessionNotFound(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	createTestAdmin(t, service)
	token := loginToken(t, router)

	const otherPassword = "other correct horse"
	if _, err := service.CreateAdmin(
		context.Background(), "other@example.com", "Other User", otherPassword,
	); err != nil {
		t.Fatalf("CreateAdmin for the other user: %v", err)
	}
	otherToken := loginTokenFor(t, router, "other@example.com", otherPassword)
	otherListed, _ := listOwnSessions(t, router, bearer(otherToken))
	foreignID := otherListed.Data[0].ID

	tests := []struct {
		name      string
		sessionID string
	}{
		{"another user's session", foreignID},
		{"missing session", newTestUUID()},
		{"malformed id", "not-a-uuid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := revokeOwnSession(router, bearer(token), test.sessionID)
			if response.Code != http.StatusNotFound {
				t.Fatalf("revoke %s = %d, want 404: %s", test.name, response.Code, response.Body)
			}
			assertNoStore(t, response)
			assertErrorCode(t, response, "NOT_FOUND", "session not found")
		})
	}

	if response := get(router, "/api/v1/me", "", bearer(otherToken)); response.Code != http.StatusOK {
		t.Errorf("GET /api/v1/me for the other user = %d, want 200: %s", response.Code, response.Body)
	}
}

func TestRevokeCurrentBrowserSession(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	createTestAdmin(t, service)
	cookie := responseCookie(t, browserLogin(router, authTestOrigin))
	cookieHeaders := map[string]string{"Cookie": cookieHeader(cookie)}
	listed, _ := listOwnSessions(t, router, cookieHeaders)
	currentID := currentSessionID(t, listed)

	headers := map[string]string{
		"Cookie":          cookieHeader(cookie),
		testBrowserHeader: testBrowserHeaderValue,
		"Origin":          authTestOrigin,
	}
	response := revokeOwnSession(router, headers, currentID)
	if response.Code != http.StatusNoContent {
		t.Fatalf("revoke the current browser session = %d, want 204: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	cleared := responseCookie(t, response)
	if cleared.MaxAge >= 0 {
		t.Errorf("clearing cookie MaxAge = %d, want negative", cleared.MaxAge)
	}
	if response := get(router, "/api/v1/me", "", cookieHeaders); response.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/me with the old cookie = %d, want 401: %s", response.Code, response.Body)
	}
}

func loginWithUserAgent(t *testing.T, router http.Handler, email, password, userAgent string) string {
	t.Helper()
	response := sendJSONWithHeaders(router, http.MethodPost, "/api/v1/auth/login", map[string]string{
		"User-Agent": userAgent,
	}, fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
	if response.Code != http.StatusOK {
		t.Fatalf("Login(%q) with user agent %q = %d: %s", email, userAgent, response.Code, response.Body)
	}
	var body struct {
		SessionToken string `json:"sessionToken"`
	}
	decodeJSON(t, response, &body)
	return body.SessionToken
}

func listOwnSessions(t *testing.T, router http.Handler, headers map[string]string) (sessionListBody, *httptest.ResponseRecorder) {
	t.Helper()
	response := get(router, "/api/v1/me/sessions", "", headers)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me/sessions = %d, want 200: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var body sessionListBody
	decodeJSON(t, response, &body)
	return body, response
}

func currentSessionID(t *testing.T, listed sessionListBody) string {
	t.Helper()
	current := ""
	for _, session := range listed.Data {
		if !session.Current {
			continue
		}
		if current != "" {
			t.Fatalf("more than one session is marked current: %+v", listed.Data)
		}
		current = session.ID
	}
	if current == "" {
		t.Fatalf("no session is marked current: %+v", listed.Data)
	}
	return current
}

func otherSessionID(t *testing.T, listed sessionListBody) string {
	t.Helper()
	for _, session := range listed.Data {
		if !session.Current {
			return session.ID
		}
	}
	t.Fatalf("no non-current session in %+v", listed.Data)
	return ""
}

func revokeOwnSession(router http.Handler, headers map[string]string, sessionID string) *httptest.ResponseRecorder {
	return sendJSONWithHeaders(
		router, http.MethodPost, "/api/v1/me/sessions/"+sessionID+"/revoke", headers, "",
	)
}
