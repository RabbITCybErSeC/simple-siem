package web_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/api"
	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
)

const (
	contractPublicURL   = "http://127.0.0.1:8090"
	contractEmail       = "analyst@example.test"
	contractPassword    = "correct horse battery staple"
	contractDisplayName = "Alice Analyst"
	contractDirectory   = "src/api/contract"
	regenerateCommand   = `make test GO_TEST_ARGS="-run TestAPIContract ./web -args -update"`
)

var update = flag.Bool("update", false, "rewrite the API contract golden files")

// TestAPIContract records the browser login, /me, and error responses from the
// real handlers and compares their shape with the files the frontend types are
// checked against.
func TestAPIContract(t *testing.T) {
	router, service := newContractRouter(t)
	if _, err := service.CreateAdmin(
		context.Background(), contractEmail, contractDisplayName, contractPassword,
	); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}

	loginResponse := postLogin(router, contractPassword)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/login = %d, want 200: %s", loginResponse.Code, loginResponse.Body)
	}
	assertNoSessionToken(t, loginResponse.Body.Bytes())
	checkContract(t, "login", loginResponse.Body.Bytes())

	sessionCookie := findSessionCookie(t, loginResponse)
	meResponse := getMe(router, sessionCookie)
	if meResponse.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/me = %d, want 200: %s", meResponse.Code, meResponse.Body)
	}
	checkContract(t, "me", meResponse.Body.Bytes())

	errorResponse := postLogin(router, "wrong password")
	if errorResponse.Code != http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/auth/login with a wrong password = %d, want 401: %s", errorResponse.Code, errorResponse.Body)
	}
	checkContract(t, "error", errorResponse.Body.Bytes())
}

func newContractRouter(t *testing.T) (http.Handler, *auth.Service) {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	service, err := auth.NewService(
		context.Background(),
		databasetest.New(t),
		auth.Settings{IdleTimeout: 30 * time.Minute, AbsoluteLifetime: 12 * time.Hour},
		logger,
	)
	if err != nil {
		t.Fatalf("auth.NewService: %v", err)
	}
	router := api.NewRouter(api.Dependencies{
		Logger:      logger,
		Auth:        service,
		PublicURL:   contractPublicURL,
		Development: true,
	})
	return router, service
}

func postLogin(router http.Handler, password string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, contractEmail, password)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Requested-With", "simple-siem")
	request.Header.Set("Origin", contractPublicURL)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func getMe(router http.Handler, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func findSessionCookie(t *testing.T, response *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "simple_siem_session" {
			return cookie
		}
	}
	t.Fatalf("login set no simple_siem_session cookie: %s", response.Header())
	return nil
}

// assertNoSessionToken keeps a bearer token out of a golden file: the browser
// login puts the token in the cookie, not in the body.
func assertNoSessionToken(t *testing.T, body []byte) {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if _, found := response["sessionToken"]; found {
		t.Fatalf("browser login body contains sessionToken: %s", body)
	}
}

// checkContract normalizes volatile values and compares the response with its
// golden file, or rewrites the file with -update.
func checkContract(t *testing.T, name string, body []byte) {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode %s response: %v", name, err)
	}
	normalized, err := json.MarshalIndent(normalize(decoded), "", "  ")
	if err != nil {
		t.Fatalf("encode %s response: %v", name, err)
	}
	normalized = append(normalized, '\n')

	path := filepath.Join(contractDirectory, name+".json")
	if *update {
		if err := os.MkdirAll(contractDirectory, 0o755); err != nil {
			t.Fatalf("create %s: %v", contractDirectory, err)
		}
		if err := os.WriteFile(path, normalized, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing contract file %s; regenerate it with: %s", path, regenerateCommand)
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(want) != string(normalized) {
		t.Fatalf(
			"%s is stale; review the shape change and run: %s\ndiff:\n%s",
			path, regenerateCommand, firstDifference(string(want), string(normalized)),
		)
	}
}

// normalize replaces volatile values with fixed placeholders of the same JSON
// type, leaving keys and every other value untouched.
func normalize(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			switch key {
			case "id":
				typed[key] = "user_id"
			case "displayName":
				typed[key] = "User Name"
			case "expiresAt", "createdAt", "updatedAt":
				typed[key] = "2026-01-01T00:00:00Z"
			default:
				typed[key] = normalize(item)
			}
		}
		return typed
	case []any:
		for index, item := range typed {
			typed[index] = normalize(item)
		}
		return typed
	default:
		return value
	}
}

func firstDifference(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")
	for index := 0; index < max(len(wantLines), len(gotLines)); index++ {
		wantLine, gotLine := "", ""
		if index < len(wantLines) {
			wantLine = wantLines[index]
		}
		if index < len(gotLines) {
			gotLine = gotLines[index]
		}
		if wantLine != gotLine {
			return fmt.Sprintf("line %d:\n- %s\n+ %s", index+1, wantLine, gotLine)
		}
	}
	return "(no line differs)"
}
