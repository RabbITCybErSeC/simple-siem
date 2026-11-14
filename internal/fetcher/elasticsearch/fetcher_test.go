package elasticsearch

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher"
)

func TestSearchBaseGoldenBody(t *testing.T) {
	bound := map[string]any{
		"query":   map[string]any{"term": map[string]any{"event.category": "authentication"}},
		"_source": []any{"@timestamp", "user.name"},
	}
	window := fetcher.Window{
		Start: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 11, 13, 11, 0, 0, 0, time.UTC),
	}

	base := searchBase(bound, "event.ingested", window)

	const want = `{"_source":["@timestamp","user.name"],"query":{"bool":{"filter":[{"term":{"event.category":"authentication"}},{"range":{"event.ingested":{"format":"strict_date_optional_time_nanos","gte":"2026-11-13T10:00:00Z","lt":"2026-11-13T11:00:00Z"}}}]}},"sort":[{"event.ingested":{"format":"strict_date_optional_time_nanos","order":"asc"}},{"_shard_doc":"asc"}],"track_total_hits":false}`
	if got := marshalBody(t, base); got != want {
		t.Errorf("searchBase() =\n%s\nwant\n%s", got, want)
	}

	sum := sha256.Sum256([]byte(want))
	if got, expected := fetcher.RenderedHash(base), hex.EncodeToString(sum[:]); got != expected {
		t.Errorf("RenderedHash(searchBase()) = %q, want %q", got, expected)
	}
}

func TestSearchBaseWithoutSource(t *testing.T) {
	bound := map[string]any{"query": map[string]any{"term": map[string]any{"a": "b"}}}
	base := searchBase(bound, "event.ingested", fetcher.Window{Start: time.Now(), End: time.Now().Add(time.Hour)})
	if _, exists := base["_source"]; exists {
		t.Errorf("searchBase() has _source without a template _source: %#v", base)
	}
}

func TestSearchPageGoldenBody(t *testing.T) {
	base := map[string]any{
		"query": map[string]any{"term": map[string]any{"a": "b"}},
		"sort":  []any{map[string]any{"event.ingested": map[string]any{"order": "asc"}}},
	}

	t.Run("first page", func(t *testing.T) {
		page := searchPage(base, 7, "pit-1", time.Minute, nil)
		const want = `{"pit":{"id":"pit-1","keep_alive":"60000ms"},"query":{"term":{"a":"b"}},"size":7,"sort":[{"event.ingested":{"order":"asc"}}]}`
		if got := marshalBody(t, page); got != want {
			t.Errorf("searchPage() =\n%s\nwant\n%s", got, want)
		}
	})

	t.Run("later page keeps the raw sort cursor", func(t *testing.T) {
		searchAfter := []json.RawMessage{
			json.RawMessage(`"2026-11-13T10:30:00.123456789Z"`),
			json.RawMessage(`4294967298`),
		}
		page := searchPage(base, 7, "pit-2", time.Minute, searchAfter)
		const want = `{"pit":{"id":"pit-2","keep_alive":"60000ms"},"query":{"term":{"a":"b"}},"search_after":["2026-11-13T10:30:00.123456789Z",4294967298],"size":7,"sort":[{"event.ingested":{"order":"asc"}}]}`
		if got := marshalBody(t, page); got != want {
			t.Errorf("searchPage() =\n%s\nwant\n%s", got, want)
		}
	})
}

func marshalBody(t *testing.T, body map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(encoded)
}

func TestFetchAuthHeader(t *testing.T) {
	tests := []struct {
		name          string
		auth          config.FetcherAuth
		environment   map[string]string
		authorization string
	}{
		{
			name:          "api key",
			auth:          config.FetcherAuth{APIKey: &config.SecretRef{Name: "TEST_API_KEY"}},
			environment:   map[string]string{"TEST_API_KEY": "api-key-value"},
			authorization: "ApiKey api-key-value",
		},
		{
			name: "basic auth",
			auth: config.FetcherAuth{
				Username: &config.SecretRef{Name: "TEST_USERNAME"},
				Password: &config.SecretRef{Name: "TEST_PASSWORD"},
			},
			environment:   map[string]string{"TEST_USERNAME": "test-user", "TEST_PASSWORD": "test-password"},
			authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte("test-user:test-password")),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorization := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				authorization <- request.Header.Get("Authorization")
				writer.WriteHeader(http.StatusUnauthorized)
			}))
			t.Cleanup(server.Close)

			instance := testInstance(server.URL)
			instance.Auth = test.auth
			fetcherClient := newTestFetcher(t, instance, test.environment)

			status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
			requireFailure(t, status, err, fetcher.ErrorCodeAuthFailed, false)
			if got := <-authorization; got != test.authorization {
				t.Errorf("Authorization = %q, want %q", got, test.authorization)
			}
			for _, secret := range []string{"api-key-value", "test-password"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("Fetch() error %q contains the secret %q", err, secret)
				}
			}
		})
	}
}

func TestNewRejectsMissingOrInvalidSecrets(t *testing.T) {
	t.Run("missing api key", func(t *testing.T) {
		_, err := New(testInstance("http://127.0.0.1:9200"), func(string) string { return "" })
		if err == nil || !strings.Contains(err.Error(), "TEST_API_KEY") {
			t.Fatalf("New() error = %v, want it to name TEST_API_KEY", err)
		}
	})

	t.Run("missing basic password", func(t *testing.T) {
		instance := testInstance("http://127.0.0.1:9200")
		instance.Auth = config.FetcherAuth{
			Username: &config.SecretRef{Name: "TEST_USERNAME"},
			Password: &config.SecretRef{Name: "TEST_PASSWORD"},
		}
		_, err := New(instance, testEnvironment(map[string]string{"TEST_USERNAME": "user"}))
		if err == nil || !strings.Contains(err.Error(), "TEST_PASSWORD") {
			t.Fatalf("New() error = %v, want it to name TEST_PASSWORD", err)
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		instance := testInstance("http://127.0.0.1:9200")
		instance.Auth = config.FetcherAuth{}
		_, err := New(instance, func(string) string { return "" })
		if err == nil {
			t.Fatal("New() error = nil, want a credentials error")
		}
	})

	t.Run("invalid ca bundle", func(t *testing.T) {
		instance := testInstance("https://127.0.0.1:9200")
		instance.TLS.CARef = &config.SecretRef{Name: "TEST_CA"}
		_, err := New(instance, testEnvironment(map[string]string{
			"TEST_API_KEY": "test-key",
			"TEST_CA":      "not a certificate",
		}))
		if err == nil || !strings.Contains(err.Error(), "no certificates parsed") {
			t.Fatalf("New() error = %v, want a CA parse error", err)
		}
	})
}

func TestFetchTLSVerification(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	t.Run("unknown certificate authority", func(t *testing.T) {
		fetcherClient := newTestFetcher(t, testInstance(server.URL), apiKeyEnvironment())
		status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
		requireFailure(t, status, err, fetcher.ErrorCodeTLSFailed, false)
		if got := requests.Load(); got != 0 {
			t.Errorf("backend received %d requests, want 0", got)
		}
	})

	t.Run("configured ca bundle", func(t *testing.T) {
		certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		instance := testInstance(server.URL)
		instance.TLS.CARef = &config.SecretRef{Name: "TEST_CA"}
		environment := apiKeyEnvironment()
		environment["TEST_CA"] = string(certificate)
		fetcherClient := newTestFetcher(t, instance, environment)

		status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
		requireFailure(t, status, err, fetcher.ErrorCodeAuthFailed, false)
		if got := requests.Load(); got != 1 {
			t.Errorf("backend received %d requests, want 1", got)
		}
	})
}

func TestFetchTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)

	instance := testInstance(server.URL)
	instance.Defaults.Timeout = config.Duration(50 * time.Millisecond)
	fetcherClient := newTestFetcher(t, instance, apiKeyEnvironment())

	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
	requireFailure(t, status, err, fetcher.ErrorCodeTimeout, true)
}

func TestFetchMapsResponseStatus(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		code        fetcher.ErrorCode
		retryable   bool
		wantMessage []string
	}{
		{
			name:   "unauthorized",
			status: http.StatusUnauthorized,
			body:   `{"error":{"type":"security_exception","reason":"unable to authenticate"}}`,
			code:   fetcher.ErrorCodeAuthFailed,
		},
		{
			name:      "service unavailable",
			status:    http.StatusServiceUnavailable,
			code:      fetcher.ErrorCodeBackendUnavailable,
			retryable: true,
		},
		{
			name:      "internal server error",
			status:    http.StatusInternalServerError,
			code:      fetcher.ErrorCodeBackendUnavailable,
			retryable: true,
		},
		{
			name:        "query rejected",
			status:      http.StatusBadRequest,
			body:        `{"error":{"type":"parsing_exception","reason":"bad query"}}`,
			code:        fetcher.ErrorCodeQueryRejected,
			wantMessage: []string{"parsing_exception", "bad query"},
		},
		{
			name:        "malformed success body",
			status:      http.StatusOK,
			body:        `not json`,
			code:        fetcher.ErrorCodeMalformedResponse,
			wantMessage: []string{"malformed"},
		},
		{
			name:   "malformed error body",
			status: http.StatusBadRequest,
			body:   `not json`,
			code:   fetcher.ErrorCodeMalformedResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			t.Cleanup(server.Close)

			fetcherClient := newTestFetcher(t, testInstance(server.URL), apiKeyEnvironment())
			status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
			requireFailure(t, status, err, test.code, test.retryable)
			for _, fragment := range test.wantMessage {
				if !strings.Contains(err.Error(), fragment) {
					t.Errorf("Fetch() error = %q, want it to contain %q", err, fragment)
				}
			}
			if strings.Contains(err.Error(), "api-key-value") {
				t.Errorf("Fetch() error %q contains the API key", err)
			}
		})
	}
}

func TestFetchDoesNotFollowRedirects(t *testing.T) {
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Location", target.URL)
		writer.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	fetcherClient := newTestFetcher(t, testInstance(redirect.URL), apiKeyEnvironment())
	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
	requireFailure(t, status, err, fetcher.ErrorCodeQueryRejected, false)

	if got := targetRequests.Load(); got != 0 {
		t.Errorf("redirect target received %d requests, want 0", got)
	}
	if strings.Contains(err.Error(), target.URL) || strings.Contains(err.Error(), "Location") {
		t.Errorf("Fetch() error %q exposes the redirect target", err)
	}
}

func TestFetchFailsOverAddresses(t *testing.T) {
	var liveRequests atomic.Int32
	live := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		liveRequests.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(live.Close)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddress := "http://" + listener.Addr().String()
	_ = listener.Close()

	instance := testInstance(live.URL)
	instance.Addresses = []string{closedAddress, live.URL}
	fetcherClient := newTestFetcher(t, instance, apiKeyEnvironment())

	status, fetchErr := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
	requireFailure(t, status, fetchErr, fetcher.ErrorCodeAuthFailed, false)
	if got := liveRequests.Load(); got != 1 {
		t.Errorf("second address received %d requests, want 1", got)
	}
}

func TestFetchDoesNotRetryAfterResponse(t *testing.T) {
	var secondRequests atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(first.Close)
	second := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		secondRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(second.Close)

	instance := testInstance(first.URL)
	instance.Addresses = []string{first.URL, second.URL}
	fetcherClient := newTestFetcher(t, instance, apiKeyEnvironment())

	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
	requireFailure(t, status, err, fetcher.ErrorCodeBackendUnavailable, true)
	if got := secondRequests.Load(); got != 0 {
		t.Errorf("second address received %d requests after a response, want 0", got)
	}
}

func TestFetchPreflightSendsNoRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	tests := []struct {
		name    string
		request func() fetcher.FetchRequest
		want    fetcher.ErrorCode
	}{
		{
			name: "index outside the allowlist",
			request: func() fetcher.FetchRequest {
				request := testFetchRequest()
				request.Index = "edr-2026.11.13"
				return request
			},
			want: fetcher.ErrorCodeIndexNotAllowed,
		},
		{
			name: "template outside the dialect",
			request: func() fetcher.FetchRequest {
				request := testFetchRequest()
				request.Template.RawQuery = map[string]any{"query": map[string]any{"script": map[string]any{"source": "1"}}}
				return request
			},
			want: fetcher.ErrorCodeInvalidTemplate,
		},
		{
			name: "value does not parse",
			request: func() fetcher.FetchRequest {
				request := testFetchRequest()
				request.Template.Parameters = map[string]config.TemplateParameter{"limit": {Type: "int", Required: true}}
				request.Template.RawQuery = map[string]any{"query": map[string]any{"term": map[string]any{"event.count": "${parameters.limit}"}}}
				request.Values = map[string]string{"limit": "1 OR 1"}
				return request
			},
			want: fetcher.ErrorCodeInvalidTemplate,
		},
		{
			name: "empty window",
			request: func() fetcher.FetchRequest {
				request := testFetchRequest()
				request.Window.End = request.Window.Start
				return request
			},
			want: fetcher.ErrorCodeQueryRejected,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fetcherClient := newTestFetcher(t, testInstance(server.URL), apiKeyEnvironment())
			status, err := fetcherClient.Fetch(context.Background(), test.request(), discardPage)
			requireFailure(t, status, err, test.want, false)
		})
	}

	if got := requests.Load(); got != 0 {
		t.Errorf("backend received %d requests for preflight failures, want 0", got)
	}
}

func testInstance(address string) config.FetcherInstance {
	return config.FetcherInstance{
		ID:             "integration",
		Type:           "elasticsearch",
		Addresses:      []string{address},
		Auth:           config.FetcherAuth{APIKey: &config.SecretRef{Name: "TEST_API_KEY"}},
		AllowedIndexes: []string{"logs-*"},
		Defaults: config.FetcherDefaults{
			Timeout:        config.Duration(time.Second),
			MaxResults:     1000,
			PageSize:       10,
			MaxBytes:       1 << 20,
			KeepAlive:      config.Duration(time.Minute),
			FetchTimeField: "event.ingested",
			TimeField:      "@timestamp",
		},
	}
}

func testFetchRequest() fetcher.FetchRequest {
	return fetcher.FetchRequest{
		PipelineRunID: "run-1",
		Index:         "logs-2026.11.13",
		Template: config.QueryTemplate{
			ID:          "auth-logins",
			FetcherType: "elasticsearch",
			Parameters:  map[string]config.TemplateParameter{},
			RawQuery:    map[string]any{"query": map[string]any{"term": map[string]any{"event.category": "authentication"}}},
		},
		Values: map[string]string{},
		Window: fetcher.Window{
			Start: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC),
			End:   time.Date(2026, 11, 13, 11, 0, 0, 0, time.UTC),
		},
	}
}

func apiKeyEnvironment() map[string]string {
	return map[string]string{"TEST_API_KEY": "api-key-value"}
}

func testEnvironment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func newTestFetcher(t *testing.T, instance config.FetcherInstance, environment map[string]string) *Fetcher {
	t.Helper()
	fetcherClient, err := New(instance, testEnvironment(environment))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return fetcherClient
}

func discardPage([]fetcher.SourceRecord) error {
	return nil
}

func requireFailure(t *testing.T, status fetcher.FetchStatus, err error, code fetcher.ErrorCode, retryable bool) {
	t.Helper()
	if err == nil {
		t.Fatalf("Fetch() error = nil, want FAILED with %s", code)
	}
	if status.Status != fetcher.StatusFailed {
		t.Errorf("Fetch() status = %q, want %q", status.Status, fetcher.StatusFailed)
	}
	if len(status.Errors) != 1 {
		t.Fatalf("Fetch() errors = %d, want 1", len(status.Errors))
	}
	if got := status.Errors[0].Code; got != code {
		t.Errorf("Fetch() error code = %q, want %q", got, code)
	}
	if got := status.Errors[0].Retryable; got != retryable {
		t.Errorf("Fetch() error retryable = %t, want %t", got, retryable)
	}
}

func TestFetchPages(t *testing.T) {
	pages := [][]map[string]any{
		{fakeHit("a", 1), fakeHit("b", 2)},
		{fakeHit("c", 3), fakeHit("d", 4)},
		{fakeHit("e", 5)},
	}
	backend := newFakeBackend(t, pages)
	fetcherClient := newBackendFetcher(t, backend, func(instance *config.FetcherInstance) {
		instance.Defaults.PageSize = 2
	})

	var emitted [][]fetcher.SourceRecord
	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), func(page []fetcher.SourceRecord) error {
		emitted = append(emitted, page)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if status.Status != fetcher.StatusOK {
		t.Errorf("status = %q, want %q", status.Status, fetcher.StatusOK)
	}
	if status.RecordCount != 5 || status.PageCount != 3 {
		t.Errorf("record/page count = %d/%d, want 5/3", status.RecordCount, status.PageCount)
	}
	if len(emitted) != 3 || len(emitted[0]) != 2 || len(emitted[1]) != 2 || len(emitted[2]) != 1 {
		t.Errorf("emitted page sizes = %v, want [2 2 1]", pageSizes(emitted))
	}
	if status.LastRecord == nil || status.LastRecord.Key.DocumentID != "e" {
		t.Errorf("LastRecord = %#v, want document e", status.LastRecord)
	}
	if status.Truncated || len(status.Errors) != 0 {
		t.Errorf("status = %#v, want an untruncated fetch without errors", status)
	}
	if len(status.RenderedQueryHash) != 64 {
		t.Errorf("RenderedQueryHash = %q, want 64 hex characters", status.RenderedQueryHash)
	}

	requests, closeBodies, openCount, closeCount := backend.requests()
	if openCount != 1 || closeCount != 1 {
		t.Errorf("PIT open/close = %d/%d, want 1/1", openCount, closeCount)
	}
	if len(requests) != 4 {
		t.Fatalf("search requests = %d, want 4 (the last one proves the window is exhausted)", len(requests))
	}
	for index, size := range []float64{2, 2, 2, 2} {
		if got := requests[index]["size"]; got != size {
			t.Errorf("search %d size = %#v, want %v", index, got, size)
		}
	}
	if _, exists := requests[0]["search_after"]; exists {
		t.Errorf("first search has search_after: %#v", requests[0]["search_after"])
	}
	for index, wantPIT := range []string{"pit-open", "pit-1", "pit-2", "pit-3"} {
		pit, _ := requests[index]["pit"].(map[string]any)
		if got := pit["id"]; got != wantPIT {
			t.Errorf("search %d pit id = %#v, want %q", index, got, wantPIT)
		}
	}
	secondAfter, _ := requests[1]["search_after"].([]any)
	if len(secondAfter) != 2 || secondAfter[0] != fakeSortTime(2) {
		t.Errorf("second search_after = %#v, want the first page's last sort", secondAfter)
	}
	fourthAfter, _ := requests[3]["search_after"].([]any)
	if len(fourthAfter) != 2 || fourthAfter[0] != fakeSortTime(5) {
		t.Errorf("fourth search_after = %#v, want the third page's last sort", fourthAfter)
	}
	if len(closeBodies) != 1 || closeBodies[0]["id"] != "pit-4" {
		t.Errorf("PIT close bodies = %#v, want the latest pit id", closeBodies)
	}
}

func TestFetchEmptyWindow(t *testing.T) {
	backend := newFakeBackend(t, [][]map[string]any{{}})
	fetcherClient := newBackendFetcher(t, backend, nil)

	emitted := 0
	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), func(page []fetcher.SourceRecord) error {
		emitted += len(page)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if status.Status != fetcher.StatusOK || status.RecordCount != 0 || status.PageCount != 0 {
		t.Errorf("status = %#v, want OK with no records", status)
	}
	if status.LastRecord != nil {
		t.Errorf("LastRecord = %#v, want nil", status.LastRecord)
	}
	if emitted != 0 {
		t.Errorf("emitted %d records, want 0", emitted)
	}
	if _, _, _, closeCount := backend.requests(); closeCount != 1 {
		t.Errorf("PIT close count = %d, want 1", closeCount)
	}
}

func TestFetchResultLimit(t *testing.T) {
	pages := [][]map[string]any{
		{fakeHit("a", 1), fakeHit("b", 2), fakeHit("c", 3), fakeHit("d", 4), fakeHit("e", 5)},
		{fakeHit("f", 6), fakeHit("g", 7), fakeHit("h", 8), fakeHit("i", 9), fakeHit("j", 10)},
		{fakeHit("k", 11), fakeHit("l", 12), fakeHit("m", 13), fakeHit("n", 14), fakeHit("o", 15)},
	}
	backend := newFakeBackend(t, pages)
	fetcherClient := newBackendFetcher(t, backend, func(instance *config.FetcherInstance) {
		instance.Defaults.PageSize = 5
		instance.Defaults.MaxResults = 12
	})

	var sizes []int
	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), func(page []fetcher.SourceRecord) error {
		sizes = append(sizes, len(page))
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v, want nil for PARTIAL", err)
	}
	if status.Status != fetcher.StatusPartial || !status.Truncated {
		t.Errorf("status = %q truncated = %t, want PARTIAL/true", status.Status, status.Truncated)
	}
	if status.RecordCount != 12 || status.PageCount != 3 {
		t.Errorf("record/page count = %d/%d, want 12/3", status.RecordCount, status.PageCount)
	}
	if len(sizes) != 3 || sizes[0] != 5 || sizes[1] != 5 || sizes[2] != 2 {
		t.Errorf("emitted page sizes = %v, want [5 5 2]", sizes)
	}
	if status.LastRecord == nil || status.LastRecord.Key.DocumentID != "l" {
		t.Errorf("LastRecord = %#v, want document l", status.LastRecord)
	}
	requirePartial(t, status, fetcher.ErrorCodeResultLimitReached, false)

	requests, _, _, closeCount := backend.requests()
	if len(requests) != 3 || closeCount != 1 {
		t.Errorf("searches/closes = %d/%d, want 3/1", len(requests), closeCount)
	}
	if got := requests[2]["size"]; got != float64(2) {
		t.Errorf("last search size = %#v, want 2", got)
	}
}

func TestFetchByteLimit(t *testing.T) {
	pages := [][]map[string]any{
		{fakeHit("a", 1)},
		{fakeHitWithPadding("b", 2, 500)},
	}
	firstResponse := fakeSearchResponse("pit-1", pages[0])
	backend := newFakeBackend(t, pages)
	fetcherClient := newBackendFetcher(t, backend, func(instance *config.FetcherInstance) {
		instance.Defaults.PageSize = 1
		instance.Defaults.MaxBytes = int64(len(firstResponse)) + 10
	})

	var pagesEmitted int
	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), func(page []fetcher.SourceRecord) error {
		pagesEmitted++
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v, want nil for PARTIAL", err)
	}
	if status.Status != fetcher.StatusPartial || !status.Truncated {
		t.Errorf("status = %q truncated = %t, want PARTIAL/true", status.Status, status.Truncated)
	}
	if status.RecordCount != 1 || status.PageCount != 1 || pagesEmitted != 1 {
		t.Errorf("record/page count = %d/%d emitted = %d, want 1/1/1", status.RecordCount, status.PageCount, pagesEmitted)
	}
	if status.LastRecord == nil || status.LastRecord.Key.DocumentID != "a" {
		t.Errorf("LastRecord = %#v, want document a", status.LastRecord)
	}
	requirePartial(t, status, fetcher.ErrorCodeByteLimitReached, false)
	if _, _, _, closeCount := backend.requests(); closeCount != 1 {
		t.Errorf("PIT close count = %d, want 1", closeCount)
	}
}

func TestFetchPITExpired(t *testing.T) {
	backend := newFakeBackend(t, [][]map[string]any{
		{fakeHit("a", 1), fakeHit("b", 2)},
	})
	backend.searchOverride = func(request *http.Request, index int) (int, []byte, bool) {
		if index != 1 {
			return 0, nil, false
		}
		return http.StatusNotFound, []byte(`{"error":{"type":"search_context_missing_exception","reason":"no search context"},"status":404}`), true
	}
	fetcherClient := newBackendFetcher(t, backend, nil)

	var pagesEmitted int
	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), func(page []fetcher.SourceRecord) error {
		pagesEmitted++
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v, want nil for PARTIAL", err)
	}
	if status.Status != fetcher.StatusPartial || !status.Truncated {
		t.Errorf("status = %q truncated = %t, want PARTIAL/true", status.Status, status.Truncated)
	}
	if status.RecordCount != 2 || status.PageCount != 1 || pagesEmitted != 1 {
		t.Errorf("record/page count = %d/%d emitted = %d, want 2/1/1", status.RecordCount, status.PageCount, pagesEmitted)
	}
	if status.LastRecord == nil || status.LastRecord.Key.DocumentID != "b" {
		t.Errorf("LastRecord = %#v, want document b", status.LastRecord)
	}
	requirePartial(t, status, fetcher.ErrorCodePITExpired, true)
	if _, _, _, closeCount := backend.requests(); closeCount != 1 {
		t.Errorf("PIT close count = %d, want 1", closeCount)
	}
}

func TestFetchEmitError(t *testing.T) {
	backend := newFakeBackend(t, [][]map[string]any{{fakeHit("a", 1)}})
	fetcherClient := newBackendFetcher(t, backend, nil)

	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), func([]fetcher.SourceRecord) error {
		return errors.New("listener stopped")
	})
	requireFailure(t, status, err, fetcher.ErrorCodeEmitFailed, false)
	if status.RecordCount != 0 || status.PageCount != 0 {
		t.Errorf("record/page count = %d/%d, want 0/0", status.RecordCount, status.PageCount)
	}
	requests, _, _, closeCount := backend.requests()
	if len(requests) != 1 || closeCount != 1 {
		t.Errorf("searches/closes = %d/%d, want 1/1", len(requests), closeCount)
	}
}

func TestFetchCancellationClosesPIT(t *testing.T) {
	backend := newFakeBackend(t, [][]map[string]any{{fakeHit("a", 1)}})
	started := make(chan struct{})
	backend.searchOverride = func(request *http.Request, index int) (int, []byte, bool) {
		close(started)
		<-request.Context().Done()
		return 0, nil, true
	}
	fetcherClient := newBackendFetcher(t, backend, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan fetcherResult, 1)
	go func() {
		status, err := fetcherClient.Fetch(ctx, testFetchRequest(), discardPage)
		result <- fetcherResult{status: status, err: err}
	}()

	select {
	case <-started:
		cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("the search request did not reach the backend")
	}

	select {
	case fetched := <-result:
		requireFailure(t, fetched.status, fetched.err, fetcher.ErrorCodeCanceled, false)
	case <-time.After(5 * time.Second):
		t.Fatal("Fetch() did not return after cancellation")
	}
	if _, _, _, closeCount := backend.requests(); closeCount != 1 {
		t.Errorf("PIT close count = %d, want 1", closeCount)
	}
}

func TestFetchMalformedHit(t *testing.T) {
	backend := newFakeBackend(t, [][]map[string]any{{
		{"_index": "logs-2026.11.13", "_id": "a", "_source": map[string]any{}},
	}})
	fetcherClient := newBackendFetcher(t, backend, nil)

	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
	requireFailure(t, status, err, fetcher.ErrorCodeMalformedResponse, false)
	if _, _, _, closeCount := backend.requests(); closeCount != 1 {
		t.Errorf("PIT close count = %d, want 1", closeCount)
	}
}

func TestFetchCloseFailureIsNotReturned(t *testing.T) {
	backend := newFakeBackend(t, [][]map[string]any{{}})
	backend.closeStatus = http.StatusInternalServerError
	fetcherClient := newBackendFetcher(t, backend, nil)

	status, err := fetcherClient.Fetch(context.Background(), testFetchRequest(), discardPage)
	if err != nil || status.Status != fetcher.StatusOK {
		t.Errorf("Fetch() = %q, %v; want OK and nil error", status.Status, err)
	}
	if _, _, _, closeCount := backend.requests(); closeCount != 1 {
		t.Errorf("PIT close count = %d, want 1", closeCount)
	}
}

type fetcherResult struct {
	status fetcher.FetchStatus
	err    error
}

type fakeBackend struct {
	t              *testing.T
	server         *httptest.Server
	pages          [][]map[string]any
	searchOverride func(request *http.Request, index int) (int, []byte, bool)
	closeStatus    int

	mu           sync.Mutex
	searchBodies []map[string]any
	openCount    int
	closeCount   int
	closeBodies  []map[string]any
}

func newFakeBackend(t *testing.T, pages [][]map[string]any) *fakeBackend {
	t.Helper()
	backend := &fakeBackend{t: t, pages: pages}
	backend.server = httptest.NewServer(backend)
	t.Cleanup(backend.server.Close)
	return backend
}

func (backend *fakeBackend) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/_pit"):
		backend.mu.Lock()
		backend.openCount++
		backend.mu.Unlock()
		writeJSON(writer, map[string]any{"id": "pit-open"})

	case request.Method == http.MethodDelete && request.URL.Path == "/_pit":
		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		backend.mu.Lock()
		backend.closeCount++
		backend.closeBodies = append(backend.closeBodies, body)
		backend.mu.Unlock()
		status := backend.closeStatus
		if status == 0 {
			status = http.StatusOK
		}
		writer.WriteHeader(status)

	case request.Method == http.MethodPost && request.URL.Path == "/_search":
		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		backend.mu.Lock()
		index := len(backend.searchBodies)
		backend.searchBodies = append(backend.searchBodies, body)
		backend.mu.Unlock()

		if backend.searchOverride != nil {
			if status, response, handled := backend.searchOverride(request, index); handled {
				if status != 0 {
					writer.WriteHeader(status)
				}
				if len(response) > 0 {
					_, _ = writer.Write(response)
				}
				return
			}
		}

		hits := []map[string]any{}
		if index < len(backend.pages) {
			hits = backend.pages[index]
		}
		if size, ok := body["size"].(float64); ok && len(hits) > int(size) {
			hits = hits[:int(size)]
		}
		writeJSON(writer, map[string]any{
			"pit_id": "pit-" + strconv.Itoa(index+1),
			"hits":   map[string]any{"hits": hits},
		})

	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (backend *fakeBackend) requests() (searches []map[string]any, closes []map[string]any, opens, closeCount int) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	searches = append(searches, backend.searchBodies...)
	closes = append(closes, backend.closeBodies...)
	return searches, closes, backend.openCount, backend.closeCount
}

func writeJSON(writer http.ResponseWriter, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(encoded)
}

func newBackendFetcher(t *testing.T, backend *fakeBackend, configure func(*config.FetcherInstance)) *Fetcher {
	t.Helper()
	instance := testInstance(backend.server.URL)
	if configure != nil {
		configure(&instance)
	}
	return newTestFetcher(t, instance, apiKeyEnvironment())
}

func fakeSearchResponse(pitID string, hits []map[string]any) []byte {
	encoded, err := json.Marshal(map[string]any{"pit_id": pitID, "hits": map[string]any{"hits": hits}})
	if err != nil {
		panic(err)
	}
	return encoded
}

func fakeHit(id string, shardDocument int) map[string]any {
	return fakeHitWithPadding(id, shardDocument, 0)
}

func fakeHitWithPadding(id string, shardDocument, padding int) map[string]any {
	source := map[string]any{"@timestamp": fakeSortTime(shardDocument)}
	if padding > 0 {
		source["padding"] = strings.Repeat("x", padding)
	}
	return map[string]any{
		"_index":  "logs-2026.11.13",
		"_id":     id,
		"_source": source,
		"sort":    []any{fakeSortTime(shardDocument), shardDocument},
	}
}

func fakeSortTime(shardDocument int) string {
	return time.Date(2026, 11, 13, 10, shardDocument, 0, 0, time.UTC).Format(time.RFC3339Nano)
}

func pageSizes(pages [][]fetcher.SourceRecord) []int {
	sizes := make([]int, len(pages))
	for index, page := range pages {
		sizes[index] = len(page)
	}
	return sizes
}

func requirePartial(t *testing.T, status fetcher.FetchStatus, code fetcher.ErrorCode, retryable bool) {
	t.Helper()
	if len(status.Errors) != 1 {
		t.Fatalf("Fetch() errors = %d, want 1", len(status.Errors))
	}
	if got := status.Errors[0].Code; got != code {
		t.Errorf("Fetch() error code = %q, want %q", got, code)
	}
	if got := status.Errors[0].Retryable; got != retryable {
		t.Errorf("Fetch() error retryable = %t, want %t", got, retryable)
	}
}
