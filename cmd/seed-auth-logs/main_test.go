package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const (
	testUsername = "elastic"
	testPassword = "test-password"
)

type seedServer struct {
	server           *httptest.Server
	bulkDocuments    int
	templateRequests int
}

func TestRunWritesDatasetAndPrintsSummary(t *testing.T) {
	seedServer := newSeedServer(t, false)

	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{
		"--url", seedServer.server.URL,
		"--seed", "1",
		"--end", "2026-11-13T12:00:00Z",
		"--index-prefix", "auth",
		"--background", "3",
	}, testGetenv, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("run = %d, want 0; stderr: %s", status, stderr.String())
	}
	if seedServer.templateRequests != 1 {
		t.Errorf("template requests = %d, want 1", seedServer.templateRequests)
	}
	if seedServer.bulkDocuments != 64 {
		t.Errorf("bulk documents = %d, want 64", seedServer.bulkDocuments)
	}

	output := stdout.String()
	for _, line := range []string{
		"scenario linux-burst-then-success: 13 documents",
		"scenario windows-burst-then-success: 13 documents",
		"scenario near-miss: 6 documents",
		"scenario failures-only: 15 documents",
		"scenario other-origin-success: 13 documents",
		"scenario malformed-no-user: 1 documents",
		"scenario background: 3 documents",
		"total: 64 documents",
		"index auth-linux-2026.11.13: ",
		"index auth-windows-2026.11.13: ",
	} {
		if !strings.Contains(output, line) {
			t.Errorf("stdout is missing %q:\n%s", line, output)
		}
	}
	if total := indexDocumentCount(t, output); total != 64 {
		t.Errorf("index counts sum to %d, want 64", total)
	}
	if strings.Contains(output, testPassword) || strings.Contains(stderr.String(), testPassword) {
		t.Error("output contains the password")
	}
}

func TestRunUsesDefaults(t *testing.T) {
	seedServer := newSeedServer(t, false)

	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"--url", seedServer.server.URL}, testGetenv, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("run = %d, want 0; stderr: %s", status, stderr.String())
	}
	if seedServer.bulkDocuments != 261 {
		t.Errorf("bulk documents = %d, want 261 (61 scenarios + 200 background)", seedServer.bulkDocuments)
	}
	output := stdout.String()
	if !strings.Contains(output, "scenario background: 200 documents") {
		t.Errorf("stdout is missing the default background summary:\n%s", output)
	}
	if !strings.Contains(output, "scenario linux-burst-then-success: 13 documents") {
		t.Errorf("stdout is missing the linux burst summary:\n%s", output)
	}
	if total := indexDocumentCount(t, output); total != 261 {
		t.Errorf("index counts sum to %d, want 261", total)
	}
}

func TestRunRejectsBadArguments(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		getenv  func(string) string
		message string
	}{
		{
			name:    "invalid end",
			args:    []string{"--url", "http://127.0.0.1:1", "--end", "13-11-2026"},
			getenv:  testGetenv,
			message: "--end",
		},
		{
			name:    "missing URL",
			args:    []string{"--end", "2026-11-13T12:00:00Z"},
			getenv:  func(string) string { return "" },
			message: "ELASTICSEARCH_URL",
		},
		{
			name:    "unknown flag",
			args:    []string{"--url", "http://127.0.0.1:1", "--bogus"},
			getenv:  testGetenv,
			message: "flag provided but not defined",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			status := run(context.Background(), test.args, test.getenv, &stdout, &stderr)
			if status != 2 {
				t.Errorf("run = %d, want 2", status)
			}
			if !strings.Contains(stderr.String(), test.message) {
				t.Errorf("stderr %q does not contain %q", stderr.String(), test.message)
			}
		})
	}
}

func TestRunRejectsInvalidIndexPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{"uppercase", "Auth"},
		{"empty", ""},
		{"leading dash", "-x"},
		{"underscore", "_x"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seedServer := newSeedServer(t, false)

			var stdout, stderr bytes.Buffer
			status := run(context.Background(), []string{
				"--url", seedServer.server.URL,
				"--end", "2026-11-13T12:00:00Z",
				"--index-prefix", test.prefix,
			}, testGetenv, &stdout, &stderr)
			if status != 2 {
				t.Errorf("run = %d, want 2", status)
			}
			if !strings.Contains(stderr.String(), "--index-prefix") {
				t.Errorf("stderr %q does not name --index-prefix", stderr.String())
			}
			if seedServer.templateRequests != 0 || seedServer.bulkDocuments != 0 {
				t.Errorf("requests = template %d, bulk %d documents, want none",
					seedServer.templateRequests, seedServer.bulkDocuments)
			}
		})
	}
}

func TestRunReturnsOneOnBulkError(t *testing.T) {
	seedServer := newSeedServer(t, true)

	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{
		"--url", seedServer.server.URL,
		"--end", "2026-11-13T12:00:00Z",
		"--background", "0",
	}, testGetenv, &stdout, &stderr)
	if status != 1 {
		t.Errorf("run = %d, want 1", status)
	}
	for _, want := range []string{"400", "mapper_parsing_exception", "bad document"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr %q does not contain %q", stderr.String(), want)
		}
	}
	if strings.Contains(stderr.String(), testPassword) {
		t.Error("stderr contains the password")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want no summary after a failed write", stdout.String())
	}
}

func TestRunReturnsOneOnHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":{"type":"security_exception"},"status":401}`)
	}))
	t.Cleanup(server.Close)

	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{
		"--url", server.URL,
		"--end", "2026-11-13T12:00:00Z",
		"--background", "0",
	}, testGetenv, &stdout, &stderr)
	if status != 1 {
		t.Errorf("run = %d, want 1", status)
	}
	if !strings.Contains(stderr.String(), "401") {
		t.Errorf("stderr %q does not name status 401", stderr.String())
	}
	if strings.Contains(stderr.String(), testPassword) {
		t.Error("stderr contains the password")
	}
}

func newSeedServer(t *testing.T, itemError bool) *seedServer {
	t.Helper()
	state := &seedServer{}
	state.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != testUsername || password != testPassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/_index_template/auth-dev-auth":
			state.templateRequests++
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"acknowledged":true}`)
		case r.Method == http.MethodPost && r.URL.Path == "/_bulk":
			body, _ := io.ReadAll(r.Body)
			count := bytes.Count(body, []byte("\n")) / 2
			state.bulkDocuments += count
			w.Header().Set("Content-Type", "application/json")
			if itemError {
				_, _ = fmt.Fprint(w, `{"errors":true,"items":[{"index":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"bad document"}}}]}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"errors":false,"items":[%s]}`, bulkItems(count))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(state.server.Close)
	return state
}

func bulkItems(count int) string {
	if count == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat(`{"index":{"status":201}},`, count), ",")
}

func testGetenv(key string) string {
	switch key {
	case "ELASTICSEARCH_USERNAME":
		return testUsername
	case "ELASTICSEARCH_PASSWORD":
		return testPassword
	default:
		return ""
	}
}

func indexDocumentCount(t *testing.T, output string) int {
	t.Helper()
	total := 0
	lines := 0
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "index ") {
			continue
		}
		lines++
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			t.Fatalf("index line %q has no count", line)
		}
		count, err := strconv.Atoi(strings.TrimSuffix(parts[1], " documents"))
		if err != nil {
			t.Fatalf("parse index line %q: %v", line, err)
		}
		total += count
	}
	if lines < 2 {
		t.Errorf("index lines = %d, want at least 2", lines)
	}
	return total
}
