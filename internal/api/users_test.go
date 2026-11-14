package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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
	analystEmail    = "analyst@example.com"
	analystPassword = "analyst horse battery"
)

type userBody struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Status      string   `json:"status"`
	Roles       []string `json:"roles"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
	Version     int      `json:"version"`
}

type paginationBody struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"pageSize"`
	TotalItems int64 `json:"totalItems"`
	TotalPages int   `json:"totalPages"`
}

type userListBody struct {
	Data       []userBody     `json:"data"`
	Pagination paginationBody `json:"pagination"`
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func TestCreateUser(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)

	response := sendJSONWithHeaders(router, http.MethodPost, "/api/v1/users", bearer(token), `{
		"email": "  Alice@Example.com ", "displayName": "Alice", "roles": ["ANALYST"]
	}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/users = %d, want 201: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var created userBody
	decodeJSON(t, response, &created)

	if created.ID == "" {
		t.Error("created user has no id")
	}
	if created.Email != "alice@example.com" {
		t.Errorf("created email = %q, want alice@example.com", created.Email)
	}
	if created.DisplayName != "Alice" {
		t.Errorf("created displayName = %q, want Alice", created.DisplayName)
	}
	if created.Status != "INVITED" {
		t.Errorf("created status = %q, want INVITED", created.Status)
	}
	if len(created.Roles) != 1 || created.Roles[0] != "ANALYST" {
		t.Errorf("created roles = %v, want [ANALYST]", created.Roles)
	}
	if created.Version != 1 {
		t.Errorf("created version = %d, want 1", created.Version)
	}
	for _, value := range []string{created.CreatedAt, created.UpdatedAt} {
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			t.Errorf("timestamp %q is not RFC 3339: %v", value, err)
		}
	}

	var storedActor struct {
		ActorID *string `gorm:"column:actor_id"`
	}
	err := database.Raw(`
		SELECT actor_id::text AS actor_id FROM audit_events
		WHERE event_name = 'simple_siem.user.created' AND target_id = ?`, created.ID).Scan(&storedActor).Error
	if err != nil {
		t.Fatalf("read user.created audit event: %v", err)
	}
	if storedActor.ActorID == nil || *storedActor.ActorID != admin.UserID {
		t.Errorf("user.created actor = %v, want %q", storedActor.ActorID, admin.UserID)
	}
}

func TestListUsersPagination(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)

	// The admin plus these 119 users make the 120-user example of the API
	// specification.
	for index := 0; index < 119; index++ {
		apiCreateUser(t, service, admin, fmt.Sprintf("user%03d@example.com", index), "User", "READ_ONLY")
	}

	response := get(router, "/api/v1/users?page=2&pageSize=50", "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/users = %d, want 200: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var list userListBody
	decodeJSON(t, response, &list)

	if len(list.Data) != 50 {
		t.Errorf("page 2 returned %d users, want 50", len(list.Data))
	}
	if list.Pagination != (paginationBody{Page: 2, PageSize: 50, TotalItems: 120, TotalPages: 3}) {
		t.Errorf("pagination = %+v, want page 2 of 3 with 120 users", list.Pagination)
	}
}

func TestListUsersValidation(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)
	apiCreateUser(t, service, admin, "invited@example.com", "Invited")

	tests := []struct {
		name        string
		query       string
		wantMessage string
	}{
		{name: "unknown parameter", query: "?sort=email", wantMessage: "sort"},
		{name: "page size over the maximum", query: "?pageSize=1000", wantMessage: "pageSize"},
		{name: "zero page", query: "?page=0", wantMessage: "page"},
		{name: "page over the maximum", query: "?page=9223372036854775807", wantMessage: "page"},
		{name: "bad status", query: "?status=ROOT", wantMessage: "status"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := get(router, "/api/v1/users"+test.query, "", bearer(token))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("GET /api/v1/users%s = %d, want 400: %s", test.query, response.Code, response.Body)
			}
			assertNoStore(t, response)
			var body errorBody
			decodeJSON(t, response, &body)
			if body.Error.Code != "VALIDATION_ERROR" || !strings.Contains(body.Error.Message, test.wantMessage) {
				t.Errorf("error = %s/%q, want VALIDATION_ERROR naming %q",
					body.Error.Code, body.Error.Message, test.wantMessage)
			}
		})
	}

	response := get(router, "/api/v1/users?status=INVITED", "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/users?status=INVITED = %d, want 200: %s", response.Code, response.Body)
	}
	var list userListBody
	decodeJSON(t, response, &list)
	if len(list.Data) != 1 || list.Data[0].Status != "INVITED" {
		t.Errorf("INVITED filter returned %d users with status %v", len(list.Data), list.Data)
	}
}

func TestGetUser(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)
	created := apiCreateUser(t, service, admin, "reader@example.com", "Reader", "READ_ONLY")

	response := get(router, "/api/v1/users/"+created.User.ID, "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/users/:id = %d, want 200: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var body userBody
	decodeJSON(t, response, &body)
	if body.ID != created.User.ID || body.Email != "reader@example.com" ||
		len(body.Roles) != 1 || body.Roles[0] != "READ_ONLY" {
		t.Errorf("GET user = %+v, want the created user", body)
	}

	for _, userID := range []string{"not-a-uuid", newTestUUID()} {
		response := get(router, "/api/v1/users/"+userID, "", bearer(token))
		if response.Code != http.StatusNotFound {
			t.Fatalf("GET /api/v1/users/%s = %d, want 404: %s", userID, response.Code, response.Body)
		}
		assertErrorCode(t, response, "NOT_FOUND", "user not found")
	}
}

func TestUpdateUser(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)
	alice := apiCreateUser(t, service, admin, "alice@example.com", "Alice")
	bob := apiCreateUser(t, service, admin, "bob@example.com", "Bob")

	response := sendJSONWithHeaders(router, http.MethodPatch, "/api/v1/users/"+alice.User.ID, bearer(token),
		`{"displayName":"Alice Updated","version":1}`)
	if response.Code != http.StatusOK {
		t.Fatalf("PATCH = %d, want 200: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var updated userBody
	decodeJSON(t, response, &updated)
	if updated.DisplayName != "Alice Updated" || updated.Version != 2 {
		t.Errorf("patched user = %+v, want the new name at version 2", updated)
	}

	response = sendJSONWithHeaders(router, http.MethodPatch, "/api/v1/users/"+alice.User.ID, bearer(token),
		`{"displayName":"Stale","version":1}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale PATCH = %d, want 409: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "VERSION_CONFLICT", "")

	response = sendJSONWithHeaders(router, http.MethodPatch, "/api/v1/users/"+bob.User.ID, bearer(token),
		`{"email":"ALICE@example.com","version":1}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate email PATCH = %d, want 409: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "STATE_CONFLICT", "email already in use")

	response = sendJSONWithHeaders(router, http.MethodPatch, "/api/v1/users/"+alice.User.ID, bearer(token),
		`{"displayName":"No version"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("PATCH without version = %d, want 400: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "VALIDATION_ERROR", "version")
}

func TestDisableAndEnableUser(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)
	target := apiCreateUser(t, service, admin, "target@example.com", "Target", "READ_ONLY")

	response := sendJSONWithHeaders(router, http.MethodPost, "/api/v1/users/"+target.User.ID+"/disable", bearer(token), `{"version":1}`)
	if response.Code != http.StatusOK {
		t.Fatalf("disable = %d, want 200: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var disabled userBody
	decodeJSON(t, response, &disabled)
	if disabled.Status != "DISABLED" || disabled.Version != 2 {
		t.Errorf("disabled user = %+v, want DISABLED at version 2", disabled)
	}

	response = sendJSONWithHeaders(router, http.MethodPost, "/api/v1/users/"+target.User.ID+"/enable", bearer(token), `{"version":1}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale enable = %d, want 409: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "VERSION_CONFLICT", "")

	response = sendJSONWithHeaders(router, http.MethodPost, "/api/v1/users/"+target.User.ID+"/enable", bearer(token), `{"version":2}`)
	if response.Code != http.StatusOK {
		t.Fatalf("enable = %d, want 200: %s", response.Code, response.Body)
	}
	var enabled userBody
	decodeJSON(t, response, &enabled)
	if enabled.Status != "INVITED" || enabled.Version != 3 {
		t.Errorf("enabled user = %+v, want INVITED at version 3", enabled)
	}

	response = sendJSONWithHeaders(router, http.MethodPost, "/api/v1/users/"+target.User.ID+"/enable", bearer(token), `{"version":2}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("repeated enable = %d, want 409: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "STATE_CONFLICT", "not disabled")

	response = sendJSONWithHeaders(router, http.MethodPost, "/api/v1/users/"+admin.UserID+"/disable", bearer(token), `{"version":1}`)
	if response.Code != http.StatusConflict {
		t.Fatalf("self disable = %d, want 409: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "STATE_CONFLICT", "cannot disable your own account")
}

func TestAssignAndRemoveRole(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)
	target := apiCreateUser(t, service, admin, "target@example.com", "Target")

	response := sendJSONWithHeaders(router, http.MethodPost, "/api/v1/users/"+target.User.ID+"/roles", bearer(token), `{"role":"ANALYST"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("assign role = %d, want 200: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var assigned userBody
	decodeJSON(t, response, &assigned)
	if len(assigned.Roles) != 1 || assigned.Roles[0] != "ANALYST" || assigned.Version != 2 {
		t.Errorf("assigned user = %+v, want [ANALYST] at version 2", assigned)
	}

	response = sendJSONWithHeaders(router, http.MethodPost, "/api/v1/users/"+target.User.ID+"/roles", bearer(token), `{"role":"ROOT"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown role = %d, want 400: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "VALIDATION_ERROR", "unknown role")

	response = send(router, http.MethodDelete, "/api/v1/users/"+target.User.ID+"/roles/ANALYST", "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("remove role = %d, want 200: %s", response.Code, response.Body)
	}
	var removed userBody
	decodeJSON(t, response, &removed)
	if len(removed.Roles) != 0 || removed.Version != 3 {
		t.Errorf("removed user = %+v, want no roles at version 3", removed)
	}

	response = send(router, http.MethodDelete, "/api/v1/users/"+admin.UserID+"/roles/ADMIN", "", bearer(token))
	if response.Code != http.StatusConflict {
		t.Fatalf("remove last admin = %d, want 409: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "STATE_CONFLICT", "the last active admin cannot be removed")
}

func TestRoleList(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	_, token := apiAdmin(t, router, service)
	response := get(router, "/api/v1/roles", "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/roles = %d, want 200: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var body struct {
		Data []struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Permissions []string `json:"permissions"`
		} `json:"data"`
	}
	decodeJSON(t, response, &body)
	if len(body.Data) != 5 {
		t.Fatalf("roles = %d, want 5", len(body.Data))
	}
	names := []string{"ADMIN", "ANALYST", "READ_ONLY", "SECURITY_ENGINEER", "SERVICE"}
	for index, role := range body.Data {
		if role.Name != names[index] || role.Description == "" {
			t.Errorf("role %d = %q/%q, want name %q with a description", index, role.Name, role.Description, names[index])
		}
	}
	if body.Data[4].Permissions == nil || len(body.Data[4].Permissions) != 0 {
		t.Errorf("SERVICE permissions = %v, want an empty array", body.Data[4].Permissions)
	}
}

func TestNonAdminCannotChangeAdminsOverHTTP(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	admin, _ := apiAdmin(t, router, service)
	apiInsertHelpdeskRole(t, database)
	helpdesk := apiCreateUser(t, service, admin, "helpdesk@example.com", "Help Desk", "HELPDESK")
	const helpdeskPassword = "helpdesk horse battery"
	apiActivateUser(t, service, admin, helpdesk.User.ID, helpdeskPassword)
	token := loginTokenFor(t, router, "helpdesk@example.com", helpdeskPassword)

	response := send(router, http.MethodPost, "/api/v1/users/"+admin.UserID+"/password-reset", "", bearer(token))
	if response.Code != http.StatusForbidden {
		t.Fatalf("helpdesk reset token for an admin = %d, want 403: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	assertErrorCode(t, response, "FORBIDDEN", "only an admin can change an admin")

	response = sendJSONWithHeaders(
		router, http.MethodPost, "/api/v1/users/"+helpdesk.User.ID+"/roles", bearer(token), `{"role":"ADMIN"}`,
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("helpdesk assigning ADMIN = %d, want 403: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	assertErrorCode(t, response, "FORBIDDEN", "only an admin can change an admin")
}

// apiInsertHelpdeskRole adds a custom role with user administration
// permissions but without ADMIN, directly because the default mapping is
// fixed by migration.
func apiInsertHelpdeskRole(t *testing.T, database *gorm.DB) {
	t.Helper()
	if err := database.Exec(
		"INSERT INTO roles (name, description) VALUES ('HELPDESK', 'Help desk')",
	).Error; err != nil {
		t.Fatalf("insert HELPDESK role: %v", err)
	}
	if err := database.Exec(`
		INSERT INTO role_permissions (role_name, permission) VALUES
		('HELPDESK', 'user:write'), ('HELPDESK', 'role:assign')`).Error; err != nil {
		t.Fatalf("grant HELPDESK permissions: %v", err)
	}
}

func TestCreateResetToken(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)
	target := apiCreateUser(t, service, admin, "invited@example.com", "Invited")

	response := send(router, http.MethodPost, "/api/v1/users/"+target.User.ID+"/password-reset", "", bearer(token))
	if response.Code != http.StatusCreated {
		t.Fatalf("POST password-reset = %d, want 201: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var body struct {
		ResetToken string `json:"resetToken"`
		ExpiresAt  string `json:"expiresAt"`
	}
	decodeJSON(t, response, &body)
	rawToken, err := base64.RawURLEncoding.DecodeString(body.ResetToken)
	if err != nil || len(rawToken) != 32 {
		t.Errorf("reset token decodes to %d bytes (error %v), want 32", len(rawToken), err)
	}
	expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		t.Fatalf("expiresAt %q is not RFC 3339: %v", body.ExpiresAt, err)
	}
	if until := time.Until(expiresAt); until < 23*time.Hour+50*time.Minute || until > 24*time.Hour+10*time.Minute {
		t.Errorf("expiresAt is %v away, want about 24 hours", until)
	}

	response = send(router, http.MethodPost, "/api/v1/users/not-a-uuid/password-reset", "", bearer(token))
	if response.Code != http.StatusNotFound {
		t.Fatalf("reset token for a malformed id = %d, want 404: %s", response.Code, response.Body)
	}
}

func TestUseResetToken(t *testing.T) {
	router, service, database, logs := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)
	invited := apiCreateUser(t, service, admin, "invited@example.com", "Invited")

	created := send(router, http.MethodPost, "/api/v1/users/"+invited.User.ID+"/password-reset", "", bearer(token))
	if created.Code != http.StatusCreated {
		t.Fatalf("POST password-reset = %d, want 201: %s", created.Code, created.Body)
	}
	assertNoStore(t, created)
	var reset struct {
		ResetToken string `json:"resetToken"`
		ExpiresAt  string `json:"expiresAt"`
	}
	decodeJSON(t, created, &reset)
	resetResponseBody := created.Body.String()

	const newPassword = "activated horse battery"
	response := sendJSON(router, http.MethodPost, "/api/v1/auth/password-reset", "", fmt.Sprintf(
		`{"token":%q,"password":"short"}`, reset.ResetToken,
	))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("short password = %d, want 400: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "VALIDATION_ERROR", "password must be 12 to 128 characters")
	assertNoStore(t, response)

	response = sendJSON(router, http.MethodPost, "/api/v1/auth/password-reset", "", fmt.Sprintf(
		`{"token":%q,"password":%q}`, reset.ResetToken, newPassword,
	))
	if response.Code != http.StatusNoContent {
		t.Fatalf("password-reset = %d, want 204: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	if response.Body.Len() != 0 {
		t.Errorf("password-reset body = %s, want empty", response.Body)
	}
	loginTokenFor(t, router, "invited@example.com", newPassword)

	response = sendJSON(router, http.MethodPost, "/api/v1/auth/password-reset", "", fmt.Sprintf(
		`{"token":%q,"password":%q}`, reset.ResetToken, newPassword,
	))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("reused token = %d, want 400: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "VALIDATION_ERROR", "invalid or expired token")

	var auditChanges string
	if err := database.Raw("SELECT COALESCE(string_agg(changes::text, ' '), '') FROM audit_events").Scan(&auditChanges).Error; err != nil {
		t.Fatalf("read audit changes: %v", err)
	}
	if strings.Contains(logs.String(), reset.ResetToken) {
		t.Error("request log contains the reset token")
	}
	if strings.Contains(logs.String(), resetResponseBody) {
		t.Error("request log contains the reset-token response body")
	}
	if strings.Contains(auditChanges, reset.ResetToken) {
		t.Error("audit changes contain the reset token")
	}
	if strings.Contains(auditChanges, resetResponseBody) {
		t.Error("audit changes contain the reset-token response body")
	}
}

func TestResetTokenFailuresAreIndistinguishable(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	admin, _ := apiAdmin(t, router, service)
	invited := apiCreateUser(t, service, admin, "invited@example.com", "Invited")

	usedToken, _, err := service.CreateResetToken(context.Background(), admin, apiTestClient(), invited.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}
	const activePassword = "active horse battery"
	if err := service.UseResetToken(context.Background(), usedToken, activePassword, apiTestClient()); err != nil {
		t.Fatalf("UseResetToken: %v", err)
	}

	expiredToken, _, err := service.CreateResetToken(context.Background(), admin, apiTestClient(), invited.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken for expiry: %v", err)
	}
	if err := database.Exec(
		"UPDATE password_reset_tokens SET expires_at = now() - interval '1 hour' WHERE used_at IS NULL",
	).Error; err != nil {
		t.Fatalf("expire the reset token: %v", err)
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("generate unknown token: %v", err)
	}
	unknownToken := base64.RawURLEncoding.EncodeToString(randomBytes)

	tokens := map[string]string{
		"used":    usedToken,
		"expired": expiredToken,
		"unknown": unknownToken,
	}
	responses := map[string]*httptest.ResponseRecorder{}
	for name, resetToken := range tokens {
		responses[name] = sendJSON(router, http.MethodPost, "/api/v1/auth/password-reset", "", fmt.Sprintf(
			`{"token":%q,"password":%q}`, resetToken, "replacement horse battery",
		))
		if responses[name].Code != http.StatusBadRequest {
			t.Fatalf("%s token = %d, want 400: %s", name, responses[name].Code, responses[name].Body)
		}
		assertNoStore(t, responses[name])
		assertErrorCode(t, responses[name], "VALIDATION_ERROR", "invalid or expired token")
	}

	want := `{"error":{"code":"VALIDATION_ERROR","message":"invalid or expired token"}}`
	if got := responses["used"].Body.String(); got != want {
		t.Errorf("used token body = %s, want %s", got, want)
	}
	if !bytes.Equal(responses["used"].Body.Bytes(), responses["expired"].Body.Bytes()) {
		t.Errorf("used and expired bodies differ: %s and %s", responses["used"].Body, responses["expired"].Body)
	}
	if !bytes.Equal(responses["used"].Body.Bytes(), responses["unknown"].Body.Bytes()) {
		t.Errorf("used and unknown bodies differ: %s and %s", responses["used"].Body, responses["unknown"].Body)
	}

	loginTokenFor(t, router, "invited@example.com", activePassword)
	wrongPassword := login(router, "invited@example.com", "replacement horse battery")
	if wrongPassword.Code != http.StatusUnauthorized {
		t.Errorf("an invalid reset token changed the password: login = %d, want 401", wrongPassword.Code)
	}
}

func TestAnalystCannotListUsers(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	admin, _ := apiAdmin(t, router, service)
	analyst := apiCreateUser(t, service, admin, analystEmail, "Analyst", "ANALYST")
	apiActivateUser(t, service, admin, analyst.User.ID, analystPassword)
	analystToken := loginTokenFor(t, router, analystEmail, analystPassword)

	response := get(router, "/api/v1/users", "", bearer(analystToken))
	if response.Code != http.StatusForbidden {
		t.Fatalf("analyst GET /api/v1/users = %d, want 403: %s", response.Code, response.Body)
	}
	assertErrorCode(t, response, "FORBIDDEN", "permission denied")
}

func newAPIRouter(t *testing.T) (*gin.Engine, *auth.Service, *gorm.DB, *bytes.Buffer) {
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
		Logger:        logger,
		Auth:          service,
		AuditDatabase: database,
		PublicURL:     authTestPublicURL,
	})
	return router, service, database, &logs
}

func apiAdmin(t *testing.T, router http.Handler, service *auth.Service) (auth.Actor, string) {
	t.Helper()
	createTestAdmin(t, service)
	token := loginToken(t, router)
	actor, err := service.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate admin: %v", err)
	}
	return actor, token
}

func apiCreateUser(t *testing.T, service *auth.Service, actor auth.Actor, email, displayName string, roles ...string) auth.UserWithRoles {
	t.Helper()
	created, err := service.CreateUser(
		context.Background(),
		actor,
		apiTestClient(),
		auth.CreateUserRequest{Email: email, DisplayName: displayName, Roles: roles},
	)
	if err != nil {
		t.Fatalf("CreateUser(%q): %v", email, err)
	}
	return created
}

func apiActivateUser(t *testing.T, service *auth.Service, actor auth.Actor, userID, password string) {
	t.Helper()
	resetToken, _, err := service.CreateResetToken(context.Background(), actor, apiTestClient(), userID)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}
	if err := service.UseResetToken(context.Background(), resetToken, password, apiTestClient()); err != nil {
		t.Fatalf("UseResetToken: %v", err)
	}
}

func apiTestClient() auth.ClientInfo {
	return auth.ClientInfo{
		IP:        net.ParseIP("192.0.2.7"),
		UserAgent: "test-agent",
		RequestID: "request-1",
	}
}

func assertNoStore(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func assertErrorCode(t *testing.T, response *httptest.ResponseRecorder, code, message string) {
	t.Helper()
	var body errorBody
	decodeJSON(t, response, &body)
	if body.Error.Code != code {
		t.Errorf("error code = %q, want %q", body.Error.Code, code)
	}
	if message != "" && !strings.Contains(body.Error.Message, message) {
		t.Errorf("error message = %q, want it to contain %q", body.Error.Message, message)
	}
}
