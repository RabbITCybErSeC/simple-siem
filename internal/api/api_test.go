package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/api"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/gin-gonic/gin"
)

const (
	testVersion = "v1.2.3"
	testCommit  = "abc1234"
)

func TestHealthzIgnoresDatabase(t *testing.T) {
	router, _ := newTestRouter(t, fakeReadiness{err: errors.New("database is down")}, nil, nil)

	response := get(router, "/healthz", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /healthz with the database down = %d, want 200: %s", response.Code, response.Body)
	}
	var body struct {
		Status string `json:"status"`
	}
	decodeJSON(t, response, &body)
	if body.Status != "ok" {
		t.Errorf("GET /healthz status = %q, want ok", body.Status)
	}
}

// TestReadyzPingsPostgreSQL proves the real *sql.DB satisfies the readiness
// check; the other readiness cases use a fake.
func TestReadyzPingsPostgreSQL(t *testing.T) {
	db := databasetest.New(t)
	sqlDatabase, err := db.DB()
	if err != nil {
		t.Fatalf("get database connection pool: %v", err)
	}
	router, _ := newTestRouter(t, sqlDatabase, nil, nil)

	response := get(router, "/readyz", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /readyz with the database up = %d, want 200: %s", response.Code, response.Body)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	decodeJSON(t, response, &body)
	if body.Status != "ready" {
		t.Errorf("GET /readyz status = %q, want ready", body.Status)
	}
	if len(body.Checks) != 0 {
		t.Errorf("GET /readyz checks = %v, want none", body.Checks)
	}

	if err := sqlDatabase.Close(); err != nil {
		t.Fatalf("close database connection pool: %v", err)
	}
	response = get(router, "/readyz", "", nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with the database down = %d, want 503: %s", response.Code, response.Body)
	}
	body = struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}{}
	decodeJSON(t, response, &body)
	if body.Status != "unavailable" {
		t.Errorf("GET /readyz status = %q, want unavailable", body.Status)
	}
	if want := map[string]string{"database": "unreachable"}; !reflect.DeepEqual(body.Checks, want) {
		t.Errorf("GET /readyz checks = %v, want %v", body.Checks, want)
	}
	raw := response.Body.String()
	for _, leaked := range []string{os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_PASSWORD"), "database is closed", "sql:"} {
		if leaked != "" && strings.Contains(raw, leaked) {
			t.Errorf("GET /readyz body leaks %q: %s", leaked, raw)
		}
	}
}

func TestReadyzWithReadinessChecker(t *testing.T) {
	const checkError = "dial tcp db.internal:5432: password authentication failed for hunter2"
	tests := []struct {
		name       string
		checker    fakeReadiness
		wantStatus int
	}{
		{name: "database answers", checker: fakeReadiness{}, wantStatus: http.StatusOK},
		{name: "database fails", checker: fakeReadiness{err: errors.New(checkError)}, wantStatus: http.StatusServiceUnavailable},
		{name: "database hangs", checker: fakeReadiness{delay: time.Hour}, wantStatus: http.StatusServiceUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := api.NewRouter(api.Dependencies{
				Database: test.checker,
				Logger:   slog.New(slog.NewJSONHandler(io.Discard, nil)),
			})

			started := time.Now()
			response := get(router, "/readyz", "", nil)
			elapsed := time.Since(started)

			if response.Code != test.wantStatus {
				t.Fatalf("GET /readyz = %d, want %d: %s", response.Code, test.wantStatus, response.Body)
			}
			if elapsed > 2*time.Second {
				t.Errorf("GET /readyz took %s, want about 1 second at most", elapsed)
			}
			for _, leaked := range []string{"db.internal", "hunter2", "dial tcp"} {
				if strings.Contains(response.Body.String(), leaked) {
					t.Errorf("GET /readyz body leaks %q: %s", leaked, response.Body)
				}
			}
		})
	}
}

func TestVersion(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, nil)

	response := get(router, "/version", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /version = %d, want 200: %s", response.Code, response.Body)
	}
	var body struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	decodeJSON(t, response, &body)
	if body.Version != testVersion || body.Commit != testCommit {
		t.Errorf("GET /version = %+v, want version %q and commit %q", body, testVersion, testCommit)
	}
}

func TestRequestIDs(t *testing.T) {
	generated := regexp.MustCompile(`^[0-9a-f]{32}$`)
	tests := []struct {
		name      string
		incoming  string
		wantReuse bool
	}{
		{name: "valid id", incoming: "abc-123", wantReuse: true},
		{name: "maximum length", incoming: strings.Repeat("a", 64), wantReuse: true},
		{name: "too long", incoming: strings.Repeat("a", 65)},
		{name: "two hundred characters", incoming: strings.Repeat("b", 200)},
		{name: "newline", incoming: "abc\n123"},
		{name: "space", incoming: "abc 123"},
		{name: "slash", incoming: "abc/123"},
		{name: "empty", incoming: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router, logs := newTestRouter(t, nil, nil, nil)
			response := get(router, "/healthz", "", map[string]string{"X-Request-Id": test.incoming})

			requestID := response.Header().Get("X-Request-Id")
			if requestID == "" {
				t.Fatalf("response has no X-Request-Id header")
			}
			if test.wantReuse {
				if requestID != test.incoming {
					t.Errorf("response request id = %q, want the incoming %q", requestID, test.incoming)
				}
			} else {
				if requestID == test.incoming {
					t.Errorf("response reused the invalid incoming request id %q", test.incoming)
				}
				if !generated.MatchString(requestID) {
					t.Errorf("generated request id %q is not 16 random bytes in hex", requestID)
				}
			}

			record := logRecord(t, logs, "route")
			if record["request_id"] != requestID {
				t.Errorf("log request_id = %v, want %q", record["request_id"], requestID)
			}
			if !test.wantReuse && test.incoming != "" && strings.Contains(logs.String(), test.incoming) {
				t.Errorf("request log contains the rejected incoming id %q: %s", test.incoming, logs)
			}
		})
	}
}

func TestRequestIDIsAvailableToHandlers(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, nil)
	router.GET("/request-id", func(c *gin.Context) {
		requestID, exists := c.Get(api.RequestIDKey)
		if !exists {
			c.String(http.StatusInternalServerError, "request id missing")
			return
		}
		c.String(http.StatusOK, requestID.(string))
	})

	response := get(router, "/request-id", "", map[string]string{"X-Request-Id": "abc-123"})
	if response.Code != http.StatusOK {
		t.Fatalf("GET /request-id = %d, want 200: %s", response.Code, response.Body)
	}
	if response.Body.String() != "abc-123" {
		t.Errorf("handler request id = %q, want abc-123", response.Body)
	}
	if response.Header().Get("X-Request-Id") != "abc-123" {
		t.Errorf("response X-Request-Id = %q, want abc-123", response.Header().Get("X-Request-Id"))
	}
}

func TestUnknownAPIRoute(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, nil)

	for _, target := range []string{"/api/v1/nope", "/api/v1"} {
		response := get(router, target, "", nil)
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404: %s", target, response.Code, response.Body)
			continue
		}
		if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
			t.Errorf("GET %s Content-Type = %q, want JSON", target, contentType)
		}
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		decodeJSON(t, response, &body)
		if body.Error.Code != "NOT_FOUND" {
			t.Errorf("GET %s error code = %q, want NOT_FOUND", target, body.Error.Code)
		}
		if response.Header().Get("X-Request-Id") == "" {
			t.Errorf("GET %s response has no X-Request-Id header", target)
		}
	}
}

func TestPanicRecovery(t *testing.T) {
	router, logs := newTestRouter(t, nil, nil, nil)
	const panicValue = "secret panic value"
	router.GET("/panic", func(*gin.Context) {
		panic(panicValue)
	})

	response := get(router, "/panic", "", nil)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("GET /panic = %d, want 500: %s", response.Code, response.Body)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"code":"INTERNAL_ERROR"`) {
		t.Errorf("panic response body = %s, want code INTERNAL_ERROR", body)
	}
	for _, leaked := range []string{panicValue, "goroutine ", "runtime/debug"} {
		if strings.Contains(body, leaked) {
			t.Errorf("panic response body leaks %q: %s", leaked, body)
		}
	}

	requestID := response.Header().Get("X-Request-Id")
	if requestID == "" {
		t.Fatal("panic response has no X-Request-Id header")
	}

	records := logRecords(t, logs)
	if len(records) != 2 {
		t.Errorf("GET /panic wrote %d log lines, want one request line and one recovery line: %s", len(records), logs)
	}
	requestRecord := logRecord(t, logs, "route")
	if requestRecord["route"] != "/panic" {
		t.Errorf("panic request log route = %v, want /panic", requestRecord["route"])
	}
	if requestRecord["status"] != float64(http.StatusInternalServerError) {
		t.Errorf("panic request log status = %v, want 500", requestRecord["status"])
	}
	if requestRecord["request_id"] != requestID {
		t.Errorf("panic request log request_id = %v, want %q", requestRecord["request_id"], requestID)
	}

	record := logRecord(t, logs, "stack")
	if record["request_id"] != requestID {
		t.Errorf("recovery log request_id = %v, want %q", record["request_id"], requestID)
	}
	if record["panic"] != panicValue {
		t.Errorf("recovery log panic = %v, want %q", record["panic"], panicValue)
	}
	stack, ok := record["stack"].(string)
	if !ok || !strings.Contains(stack, "goroutine ") || !strings.Contains(stack, "TestPanicRecovery") {
		t.Errorf("recovery log stack does not contain the panic stack: %v", record["stack"])
	}
}

func TestTrustedProxies(t *testing.T) {
	const (
		peer             = "192.0.2.1:4567"
		peerAddress      = "192.0.2.1"
		forwardedAddress = "203.0.113.9"
	)
	tests := []struct {
		name           string
		trustedProxies []string
		wantAddress    string
	}{
		{name: "untrusted peer", wantAddress: peerAddress},
		{name: "trusted address", trustedProxies: []string{peerAddress}, wantAddress: forwardedAddress},
		{name: "trusted range", trustedProxies: []string{"192.0.2.0/24"}, wantAddress: forwardedAddress},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router, logs := newTestRouter(t, nil, test.trustedProxies, nil)
			response := get(router, "/healthz", peer, map[string]string{"X-Forwarded-For": forwardedAddress})
			if response.Code != http.StatusOK {
				t.Fatalf("GET /healthz = %d, want 200: %s", response.Code, response.Body)
			}
			record := logRecord(t, logs, "route")
			if record["client_address"] != test.wantAddress {
				t.Errorf("logged client address = %v, want %q", record["client_address"], test.wantAddress)
			}
		})
	}
}

func TestRequestLogLine(t *testing.T) {
	router, logs := newTestRouter(t, nil, nil, nil)

	response := get(router, "/healthz?token=query-secret-9f3a", "", map[string]string{
		"X-Request-Id":  "fixed-id-1",
		"Authorization": "Bearer header-secret-7c2b",
		"Cookie":        "session=cookie-secret-4d8e",
	})
	if response.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200: %s", response.Code, response.Body)
	}

	records := logRecords(t, logs)
	if len(records) != 1 {
		t.Fatalf("GET /healthz wrote %d log lines, want 1: %s", len(records), logs)
	}
	record := records[0]
	fields := []struct {
		name string
		got  any
		want any
	}{
		{"method", record["method"], http.MethodGet},
		{"route", record["route"], "/healthz"},
		{"status", record["status"], float64(http.StatusOK)},
		{"request_id", record["request_id"], "fixed-id-1"},
		{"client_address", record["client_address"], "192.0.2.1"},
	}
	for _, field := range fields {
		if field.got != field.want {
			t.Errorf("request log %s = %v, want %v", field.name, field.got, field.want)
		}
	}
	if _, ok := record["duration"]; !ok {
		t.Errorf("request log has no duration: %s", logs)
	}

	raw := logs.String()
	for _, leaked := range []string{
		"query-secret-9f3a",
		"abc",
		"Authorization",
		"Bearer header-secret-7c2b",
		"Cookie",
		"cookie-secret-4d8e",
	} {
		if strings.Contains(raw, leaked) {
			t.Errorf("request log contains %q: %s", leaked, raw)
		}
	}
}

func newTestRouter(t *testing.T, database api.ReadinessChecker, trustedProxies []string, files fs.FS) (*gin.Engine, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	router := api.NewRouter(api.Dependencies{
		Database:       database,
		Logger:         logger,
		Web:            files,
		TrustedProxies: trustedProxies,
		Version:        testVersion,
		Commit:         testCommit,
	})
	return router, &logs
}

func get(router http.Handler, target, remoteAddress string, headers map[string]string) *httptest.ResponseRecorder {
	return send(router, http.MethodGet, target, remoteAddress, headers)
}

func send(router http.Handler, method, target, remoteAddress string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	if remoteAddress != "" {
		request.RemoteAddr = remoteAddress
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func decodeJSON(t *testing.T, response *httptest.ResponseRecorder, value any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), value); err != nil {
		t.Fatalf("decode response body %q: %v", response.Body, err)
	}
}

func logRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(logs.Bytes()))
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode log line %q: %v", scanner.Text(), err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read logs: %v", err)
	}
	return records
}

func logRecord(t *testing.T, logs *bytes.Buffer, key string) map[string]any {
	t.Helper()
	for _, record := range logRecords(t, logs) {
		if _, ok := record[key]; ok {
			return record
		}
	}
	t.Fatalf("no log line has field %q: %s", key, logs)
	return nil
}

// fakeReadiness stands in for the database ping. A delay longer than the
// request's deadline blocks until that deadline, as a real driver does.
type fakeReadiness struct {
	err   error
	delay time.Duration
}

func (readiness fakeReadiness) PingContext(ctx context.Context) error {
	if readiness.delay == 0 {
		return readiness.err
	}
	timer := time.NewTimer(readiness.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return readiness.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
