package api_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

// publicRoutes and authenticatedOnlyRoutes are the deliberate exceptions to
// the deny-by-default walk. A new route must gain a permission check or be
// added to one of these lists on purpose.
var publicRoutes = map[string]bool{
	"GET /api/v1/auth/providers":       true,
	"POST /api/v1/auth/login":          true,
	"POST /api/v1/auth/password-reset": true,
}

var authenticatedOnlyRoutes = map[string]bool{
	"POST /api/v1/auth/logout":                   true,
	"GET /api/v1/me":                             true,
	"POST /api/v1/me/password":                   true,
	"GET /api/v1/me/sessions":                    true,
	"POST /api/v1/me/sessions/:sessionId/revoke": true,
}

func TestAPIRoutesDenyByDefault(t *testing.T) {
	router, service, _, _ := newAuthRouter(t)
	createTestAdmin(t, service)
	adminToken := loginToken(t, router)
	admin, err := service.Authenticate(context.Background(), adminToken)
	if err != nil {
		t.Fatalf("Authenticate admin: %v", err)
	}

	client := auth.ClientInfo{IP: net.ParseIP("192.0.2.7"), UserAgent: "test-agent"}
	roleless, err := service.CreateUser(context.Background(), admin, client, auth.CreateUserRequest{
		Email: "roleless@example.com", DisplayName: "Roleless User",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	const rolelessPassword = "roleless horse battery"
	resetToken, _, err := service.CreateResetToken(context.Background(), admin, client, roleless.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}
	if err := service.UseResetToken(context.Background(), resetToken, rolelessPassword, client); err != nil {
		t.Fatalf("UseResetToken: %v", err)
	}
	rolelessToken := loginTokenFor(t, router, roleless.User.Email, rolelessPassword)

	routes := []gin.RouteInfo{}
	for _, route := range router.Routes() {
		if strings.HasPrefix(route.Path, "/api/v1") {
			routes = append(routes, route)
		}
	}

	visited := 0
	for _, route := range routes {
		key := route.Method + " " + route.Path
		response := walkRequest(router, route, "")
		if publicRoutes[key] {
			if response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden {
				t.Errorf("%s is public but returned %d: %s", key, response.Code, response.Body)
			}
			continue
		}
		visited++
		assertAuthenticationRequired(t, response)
	}
	if visited < 2 {
		t.Fatalf("deny-by-default walk visited %d routes, want at least 2", visited)
	}

	for _, route := range routes {
		key := route.Method + " " + route.Path
		if publicRoutes[key] || key == "POST /api/v1/auth/logout" {
			continue
		}
		response := walkRequest(router, route, rolelessToken)
		if authenticatedOnlyRoutes[key] {
			if response.Code == http.StatusUnauthorized || response.Code == http.StatusForbidden {
				t.Errorf("%s returned %d with a role-less session: %s", key, response.Code, response.Body)
			}
			continue
		}
		if response.Code != http.StatusForbidden {
			t.Errorf("%s returned %d for a role-less session, want 403: %s", key, response.Code, response.Body)
		}
	}

	// Logout runs last because it revokes the session the rest of the walk uses.
	response := send(router, http.MethodPost, "/api/v1/auth/logout", "", bearer(rolelessToken))
	if response.Code != http.StatusNoContent {
		t.Errorf("POST /api/v1/auth/logout returned %d with a role-less session, want 204: %s",
			response.Code, response.Body)
	}
}

// walkRequest calls one route with a concrete path and a JSON body where the
// method has one. An empty token sends no credentials.
func walkRequest(router http.Handler, route gin.RouteInfo, token string) *httptest.ResponseRecorder {
	method := route.Method
	target := concretePath(route.Path)
	body := ""
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		body = "{}"
	}
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// concretePath substitutes route parameters, so Gin matches the template
// instead of falling through to NoRoute.
func concretePath(routePath string) string {
	segments := strings.Split(routePath, "/")
	for index, segment := range segments {
		switch {
		case segment == ":role":
			segments[index] = "ANALYST"
		case strings.HasPrefix(segment, ":"):
			segments[index] = newTestUUID()
		}
	}
	return strings.Join(segments, "/")
}

func newTestUUID() string {
	var identifier [16]byte
	// crypto/rand.Read never returns an error since Go 1.24.
	_, _ = rand.Read(identifier[:])
	identifier[6] = (identifier[6] & 0x0f) | 0x40
	identifier[8] = (identifier[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		identifier[0:4], identifier[4:6], identifier[6:8], identifier[8:10], identifier[10:16])
}

func loginTokenFor(t *testing.T, router http.Handler, email, password string) string {
	t.Helper()
	response := login(router, email, password)
	if response.Code != http.StatusOK {
		t.Fatalf("Login(%q) = %d: %s", email, response.Code, response.Body)
	}
	var body struct {
		SessionToken string `json:"sessionToken"`
	}
	decodeJSON(t, response, &body)
	return body.SessionToken
}
