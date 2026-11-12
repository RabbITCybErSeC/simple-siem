package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/version"
)

func TestRunVersion(t *testing.T) {
	previousVersion := version.Version
	previousCommit := version.Commit
	version.Version = "v1.2.3"
	version.Commit = "abc1234"
	t.Cleanup(func() {
		version.Version = previousVersion
		version.Commit = previousCommit
	})

	tests := []struct {
		name       string
		args       []string
		wantStatus int
		wantStdout string
	}{
		{
			name:       "version command",
			args:       []string{"version"},
			wantStatus: 0,
			wantStdout: "simple-siem v1.2.3 (abc1234)\n",
		},
		{
			name:       "no command",
			wantStatus: 0,
			wantStdout: "simple-siem v1.2.3 (abc1234)\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			status := run(context.Background(), test.args, mapGetenv(nil), &stdout, &stderr)

			if status != test.wantStatus {
				t.Errorf("run() status = %d, want %d", status, test.wantStatus)
			}
			if got := stdout.String(); got != test.wantStdout {
				t.Errorf("run() stdout = %q, want %q", got, test.wantStdout)
			}
			if got := stderr.String(); got != "" {
				t.Errorf("run() stderr = %q, want empty", got)
			}
		})
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	status := run(context.Background(), []string{"frobnicate"}, mapGetenv(nil), &stdout, &stderr)

	if status != 2 {
		t.Errorf("run() status = %d, want 2", status)
	}
	if stdout.Len() != 0 {
		t.Errorf("run() stdout = %q, want empty", stdout.String())
	}
	for _, command := range []string{"serve", "migrate", "version"} {
		if !strings.Contains(stderr.String(), command) {
			t.Errorf("run() stderr %q does not list command %q", stderr.String(), command)
		}
	}
}

func TestRunUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer

	status := run(context.Background(), []string{"serve", "--no-such-flag"}, mapGetenv(nil), &stdout, &stderr)

	if status != 2 {
		t.Errorf("run() status = %d, want 2", status)
	}
	if stdout.Len() != 0 {
		t.Errorf("run() stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "no-such-flag") {
		t.Errorf("run() stderr %q does not name the unknown flag", stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage: simple-siem serve") {
		t.Errorf("run() stderr %q does not print the serve usage", stderr.String())
	}
}

func TestRunInvalidConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer

	status := run(context.Background(), []string{"serve"}, mapGetenv(nil), &stdout, &stderr)

	if status != 1 {
		t.Errorf("run() status = %d, want 1", status)
	}
	if !strings.Contains(stderr.String(), "SIMPLE_SIEM_DATABASE_URL") {
		t.Errorf("run() stderr %q does not name SIMPLE_SIEM_DATABASE_URL", stderr.String())
	}
}

func TestRunServeRefusesPendingSchema(t *testing.T) {
	_, databaseURL := databasetest.NewUnmigrated(t)
	getenv := mapGetenv(map[string]string{
		"SIMPLE_SIEM_ENV":          "development",
		"SIMPLE_SIEM_DATABASE_URL": databaseURL,
	})

	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"serve", "--migrate=false"}, getenv, &stdout, &stderr)

	if status != 1 {
		t.Fatalf("run() status = %d, want 1; stderr: %s", status, stderr.String())
	}
	if !strings.Contains(stdout.String(), "behind") {
		t.Errorf("run() stdout %q does not report the schema as behind", stdout.String())
	}
}

func TestRunMigrateAppliesPendingMigrations(t *testing.T) {
	testDatabase, databaseURL := databasetest.NewUnmigrated(t)
	getenv := mapGetenv(map[string]string{
		"SIMPLE_SIEM_ENV":          "development",
		"SIMPLE_SIEM_DATABASE_URL": databaseURL,
	})

	var stdout, stderr bytes.Buffer
	status := run(context.Background(), []string{"migrate"}, getenv, &stdout, &stderr)

	if status != 0 {
		t.Fatalf("run() status = %d, want 0; stdout: %s; stderr: %s", status, stdout.String(), stderr.String())
	}
	if err := database.CheckSchema(context.Background(), testDatabase); err != nil {
		t.Errorf("schema after migrate: %v", err)
	}
}

func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	db := databasetest.New(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	server := newHTTPServer(config.Config{Listen: "127.0.0.1:0"}, db, logger)

	timeouts := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", server.ReadHeaderTimeout, 10 * time.Second},
		{"ReadTimeout", server.ReadTimeout, 30 * time.Second},
		{"WriteTimeout", server.WriteTimeout, 60 * time.Second},
		{"IdleTimeout", server.IdleTimeout, 120 * time.Second},
	}
	for _, timeout := range timeouts {
		if timeout.got != timeout.want {
			t.Errorf("server.%s = %s, want %s", timeout.name, timeout.got, timeout.want)
		}
	}
}

func TestServeHTTPCompletesInFlightRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		time.Sleep(time.Second)
		_, _ = writer.Write([]byte("done"))
	})
	server, address := newTestServer(t, handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitCode := make(chan int, 1)
	go func() { exitCode <- serveHTTP(ctx, server, 5*time.Second) }()
	waitForListener(t, address)

	type requestResult struct {
		statusCode int
		body       string
		err        error
	}
	results := make(chan requestResult, 1)
	go func() {
		response, err := http.Get("http://" + address + "/slow")
		if err != nil {
			results <- requestResult{err: err}
			return
		}
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		results <- requestResult{statusCode: response.StatusCode, body: string(body), err: err}
	}()

	waitForSignal(t, requestStarted, "request did not reach the handler")
	cancel()

	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("in-flight request failed: %v", result.err)
		}
		if result.statusCode != http.StatusOK {
			t.Errorf("in-flight request status = %d, want 200", result.statusCode)
		}
		if result.body != "done" {
			t.Errorf("in-flight request body = %q, want %q", result.body, "done")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not complete")
	}

	select {
	case code := <-exitCode:
		if code != 0 {
			t.Errorf("serveHTTP() status = %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTP did not return after the in-flight request completed")
	}
}

func TestServeHTTPTimeoutCutsOffRequest(t *testing.T) {
	requestStarted := make(chan struct{})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		time.Sleep(5 * time.Second)
	})
	server, address := newTestServer(t, handler)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitCode := make(chan int, 1)
	go func() { exitCode <- serveHTTP(ctx, server, time.Second) }()
	waitForListener(t, address)

	go func() {
		response, err := http.Get("http://" + address + "/slow")
		if err == nil {
			_ = response.Body.Close()
		}
	}()

	waitForSignal(t, requestStarted, "request did not reach the handler")
	cancelledAt := time.Now()
	cancel()

	select {
	case code := <-exitCode:
		if code != 1 {
			t.Errorf("serveHTTP() status = %d, want 1", code)
		}
		if elapsed := time.Since(cancelledAt); elapsed > 2*time.Second {
			t.Errorf("serveHTTP took %s to stop, want about 1s", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTP did not return after the shutdown timeout")
	}
}

func mapGetenv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func newTestServer(t *testing.T, handler http.Handler) (*http.Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 10 * time.Second}, address
}

func waitForListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.Dial("tcp", address)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server at %s did not start listening", address)
}

func waitForSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal(message)
	}
}
