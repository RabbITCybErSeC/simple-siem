package api_test

import (
	"errors"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
)

const (
	indexShellMarker = "test shell"
	testAssetScript  = "console.log('test asset')\n"

	baseContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
	cspNoncePlaceholder       = "SIMPLE_SIEM_CSP_NONCE"
)

func TestSecurityHeaders(t *testing.T) {
	wantHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
	}

	router, _ := newTestRouter(t, nil, nil, nil)
	router.GET("/panic", func(*gin.Context) {
		panic("boom")
	})

	for _, target := range []string{"/", "/api/v1/nope", "/panic"} {
		t.Run(target, func(t *testing.T) {
			response := get(router, target, "", nil)
			for name, want := range wantHeaders {
				if got := response.Header().Get(name); got != want {
					t.Errorf("GET %s %s = %q, want %q", target, name, got, want)
				}
			}
			policy := response.Header().Get("Content-Security-Policy")
			if target == "/" {
				pageNonceFromPolicy(t, policy)
				return
			}
			if policy != baseContentSecurityPolicy {
				t.Errorf("GET %s Content-Security-Policy = %q, want %q", target, policy, baseContentSecurityPolicy)
			}
		})
	}
}

func TestPageResponsesCarryNonceInPolicyAndBody(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, newNonceWebFiles())

	for _, target := range []string{"/", "/cases"} {
		t.Run(target, func(t *testing.T) {
			response := get(router, target, "", nil)
			nonce := pageNonceFromPolicy(t, response.Header().Get("Content-Security-Policy"))
			body := response.Body.String()
			if count := strings.Count(body, nonce); count != 3 {
				t.Errorf("GET %s body contains the nonce %d times, want 3: %s", target, count, body)
			}
			if strings.Contains(body, cspNoncePlaceholder) {
				t.Errorf("GET %s body still contains the nonce placeholder: %s", target, body)
			}
		})
	}
}

func TestPageNonceChangesPerResponse(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, newNonceWebFiles())

	first := pageNonceFromPolicy(t, get(router, "/", "", nil).Header().Get("Content-Security-Policy"))
	second := pageNonceFromPolicy(t, get(router, "/", "", nil).Header().Get("Content-Security-Policy"))
	if first == second {
		t.Errorf("two GET / responses share the nonce %q", first)
	}
}

func TestNonPageResponsesKeepBasePolicy(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, newNonceWebFiles())

	for _, target := range []string{"/healthz", "/assets/app.js", "/api/v1/nope"} {
		t.Run(target, func(t *testing.T) {
			response := get(router, target, "", nil)
			if got := response.Header().Get("Content-Security-Policy"); got != baseContentSecurityPolicy {
				t.Errorf("GET %s Content-Security-Policy = %q, want exactly the base policy", target, got)
			}
		})
	}
}

func TestUnknownPageRoutesReturnIndexHTML(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, newTestWebFiles())

	for _, target := range []string{"/", "/cases/42"} {
		t.Run(target, func(t *testing.T) {
			response := get(router, target, "", nil)
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200: %s", target, response.Code, response.Body)
			}
			if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
				t.Errorf("GET %s Content-Type = %q, want HTML", target, contentType)
			}
			if cacheControl := response.Header().Get("Cache-Control"); cacheControl != "no-cache" {
				t.Errorf("GET %s Cache-Control = %q, want no-cache", target, cacheControl)
			}
			if !strings.Contains(response.Body.String(), indexShellMarker) {
				t.Errorf("GET %s body is not index.html: %s", target, response.Body)
			}
		})
	}

	response := send(router, http.MethodPost, "/cases/42", "", nil)
	if response.Code != http.StatusNotFound {
		t.Errorf("POST /cases/42 = %d, want 404: %s", response.Code, response.Body)
	}
	if strings.Contains(response.Body.String(), indexShellMarker) {
		t.Errorf("POST /cases/42 returned index.html: %s", response.Body)
	}
}

func TestHealthRouteIsNotShadowedByWebUI(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, newTestWebFiles())

	response := get(router, "/healthz", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200: %s", response.Code, response.Body)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Errorf("GET /healthz Content-Type = %q, want JSON", contentType)
	}
	if strings.Contains(response.Body.String(), indexShellMarker) {
		t.Errorf("GET /healthz returned index.html: %s", response.Body)
	}
}

func TestHeadOnHealthRoutesReachesHandlers(t *testing.T) {
	router, _ := newTestRouter(t, fakeReadiness{err: errors.New("database is down")}, nil, newTestWebFiles())

	for target, wantStatus := range map[string]int{
		"/healthz": http.StatusOK,
		"/readyz":  http.StatusServiceUnavailable,
		"/version": http.StatusOK,
	} {
		response := send(router, http.MethodHead, target, "", nil)
		if response.Code != wantStatus {
			t.Errorf("HEAD %s with the database down = %d, want %d", target, response.Code, wantStatus)
		}
		if strings.Contains(response.Body.String(), indexShellMarker) {
			t.Errorf("HEAD %s returned index.html", target)
		}
	}
}

func TestUnknownAPIPathsReturnJSON(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, newTestWebFiles())
	tests := []struct {
		name   string
		method string
		target string
	}{
		{name: "api root", method: http.MethodGet, target: "/api"},
		{name: "unknown version", method: http.MethodGet, target: "/api/v2/alerts"},
		{name: "write under v1", method: http.MethodPost, target: "/api/v1/nope"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := send(router, test.method, test.target, "", nil)
			if response.Code != http.StatusNotFound {
				t.Fatalf("%s %s = %d, want 404: %s", test.method, test.target, response.Code, response.Body)
			}
			if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
				t.Errorf("%s %s Content-Type = %q, want JSON", test.method, test.target, contentType)
			}
			body := response.Body.String()
			if !strings.Contains(body, `"code":"NOT_FOUND"`) {
				t.Errorf("%s %s body = %s, want code NOT_FOUND", test.method, test.target, body)
			}
			if strings.Contains(body, indexShellMarker) {
				t.Errorf("%s %s returned index.html: %s", test.method, test.target, body)
			}
		})
	}
}

func TestAssets(t *testing.T) {
	router, _ := newTestRouter(t, nil, nil, newTestWebFiles())

	response := get(router, "/assets/index-abc123.js", "", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("GET /assets/index-abc123.js = %d, want 200: %s", response.Code, response.Body)
	}
	if cacheControl := response.Header().Get("Cache-Control"); cacheControl != "public, max-age=31536000, immutable" {
		t.Errorf("asset Cache-Control = %q, want immutable one year", cacheControl)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "javascript") {
		t.Errorf("asset Content-Type = %q, want a JavaScript type", contentType)
	}
	if response.Body.String() != testAssetScript {
		t.Errorf("asset body = %q, want %q", response.Body, testAssetScript)
	}

	for _, target := range []string{"/assets/missing.js", "/assets/"} {
		response := get(router, target, "", nil)
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404: %s", target, response.Code, response.Body)
		}
		if strings.Contains(response.Body.String(), indexShellMarker) {
			t.Errorf("GET %s returned index.html: %s", target, response.Body)
		}
	}

	for _, target := range []string{"/assets/../embed.go", "/assets/%2e%2e/embed.go"} {
		response := get(router, target, "", nil)
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404: %s", target, response.Code, response.Body)
		}
		if strings.Contains(response.Body.String(), "package web") {
			t.Errorf("GET %s served a file outside the asset directory: %s", target, response.Body)
		}
		if strings.Contains(response.Body.String(), indexShellMarker) {
			t.Errorf("GET %s returned index.html: %s", target, response.Body)
		}
	}
}

func TestFrontendNotBuilt(t *testing.T) {
	tests := []struct {
		name  string
		files fs.FS
	}{
		{name: "nil web"},
		{
			name:  "web without index",
			files: fstest.MapFS{"assets/index-abc123.js": {Data: []byte(testAssetScript)}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router, _ := newTestRouter(t, nil, nil, test.files)

			for _, target := range []string{"/", "/cases/42"} {
				response := get(router, target, "", nil)
				if response.Code != http.StatusOK {
					t.Errorf("GET %s = %d, want 200: %s", target, response.Code, response.Body)
				}
				if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
					t.Errorf("GET %s Content-Type = %q, want HTML", target, contentType)
				}
				body := response.Body.String()
				if !strings.Contains(body, "frontend is not built") || !strings.Contains(body, "make build") {
					t.Errorf("GET %s body = %s, want the frontend-not-built page naming make build", target, body)
				}
				if strings.Contains(body, indexShellMarker) {
					t.Errorf("GET %s returned index.html without a build", target)
				}
			}

			if response := get(router, "/healthz", "", nil); response.Code != http.StatusOK {
				t.Errorf("GET /healthz without a build = %d, want 200: %s", response.Code, response.Body)
			}
		})
	}
}

func TestRequestLogWebRouteLabels(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		wantRoute string
	}{
		{name: "page", target: "/", wantRoute: "web"},
		{name: "client route", target: "/cases/42", wantRoute: "web"},
		{name: "asset", target: "/assets/index-abc123.js", wantRoute: "/assets/*filepath"},
		{name: "missing asset", target: "/assets/missing.js", wantRoute: "/assets/*filepath"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router, logs := newTestRouter(t, nil, nil, newTestWebFiles())
			_ = get(router, test.target, "", nil)

			record := logRecord(t, logs, "route")
			if record["route"] != test.wantRoute {
				t.Errorf("GET %s log route = %v, want %q", test.target, record["route"], test.wantRoute)
			}
		})
	}
}

func newTestWebFiles() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {
			Data: []byte(`<!doctype html><html><body><div id="root">test shell</div></body></html>`),
		},
		"assets/index-abc123.js": {Data: []byte(testAssetScript)},
		"embed.go":               {Data: []byte("package web\n")},
	}
}

func newNonceWebFiles() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {
			Data: []byte(`<!doctype html><html><head><meta property="csp-nonce" nonce="SIMPLE_SIEM_CSP_NONCE"><script type="module" nonce="SIMPLE_SIEM_CSP_NONCE" src="/assets/app.js"></script><link rel="stylesheet" nonce="SIMPLE_SIEM_CSP_NONCE" href="/assets/app.css"></head><body></body></html>`),
		},
		"assets/app.js": {Data: []byte(testAssetScript)},
	}
}

// pageNonceFromPolicy returns the nonce from a page CSP and fails the test
// when the header is not exactly the base policy plus the nonce directive.
func pageNonceFromPolicy(t *testing.T, policy string) string {
	t.Helper()
	pattern := regexp.MustCompile("^" + regexp.QuoteMeta(baseContentSecurityPolicy) + `; style-src 'self' 'nonce-([A-Za-z0-9_-]{22})'$`)
	matches := pattern.FindStringSubmatch(policy)
	if matches == nil {
		t.Fatalf("Content-Security-Policy = %q, want the base policy plus style-src 'self' 'nonce-<22 base64url characters>'", policy)
	}
	return matches[1]
}
