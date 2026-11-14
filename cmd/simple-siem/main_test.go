package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/pipeline"
	"github.com/RabbITCybErSeC/simple-siem/internal/version"
	"gorm.io/gorm"
)

const cliTestPassword = "correct horse battery"

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

			status := run(context.Background(), test.args, mapGetenv(nil), strings.NewReader(""), &stdout, &stderr)

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

	status := run(context.Background(), []string{"frobnicate"}, mapGetenv(nil), strings.NewReader(""), &stdout, &stderr)

	if status != 2 {
		t.Errorf("run() status = %d, want 2", status)
	}
	if stdout.Len() != 0 {
		t.Errorf("run() stdout = %q, want empty", stdout.String())
	}
	for _, command := range []string{"serve", "migrate", "admin", "config", "version"} {
		if !strings.Contains(stderr.String(), command) {
			t.Errorf("run() stderr %q does not list command %q", stderr.String(), command)
		}
	}
}

func TestRunUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer

	status := run(context.Background(), []string{"serve", "--no-such-flag"}, mapGetenv(nil), strings.NewReader(""), &stdout, &stderr)

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

func TestRunConfigValidate(t *testing.T) {
	// SIMPLE_SIEM_DATABASE_URL is deliberately unset: config validate must not
	// need the database.
	directory := t.TempDir()
	if err := os.CopyFS(directory, os.DirFS("../../internal/config/testdata/valid")); err != nil {
		t.Fatalf("copy valid config fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "mappings", "ecs-ssh-login.yaml"), []byte(runTestMapping), 0o600); err != nil {
		t.Fatalf("write mapping: %v", err)
	}
	environment := map[string]string{
		"SIMPLE_SIEM_ENV":      "development",
		"ELASTIC_PROD_API_KEY": "test-api-key",
		"ELASTIC_PROD_CA":      "test-ca",
		"ELASTIC_EDR_USERNAME": "test-user",
		"ELASTIC_EDR_PASSWORD": "test-password",
	}

	status, stdout, stderr := runCLI(t,
		[]string{"config", "validate", "--config-dir", directory}, environment)

	if status != 0 {
		t.Fatalf("run() status = %d, want 0; stderr: %s", status, stderr)
	}
	if want := "config valid: 2 fetcher instances, 1 pipeline, 1 dataset\n"; stdout != want {
		t.Errorf("run() stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("run() stderr = %q, want empty", stderr)
	}
}

func TestRunConfigValidateRejectsDialectErrors(t *testing.T) {
	directory := writeConfigDirectory(t, map[string]string{
		"system.yaml": "version: \"0.1\"\n",
		"fetchers.yaml": `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
		"query_templates/auth-logins.yaml": `id: auth-logins
fetcherType: elasticsearch
version: 0.1.0
rawQuery:
  query:
    term: { event.category: authentication }
  sort:
    - "@timestamp": asc
`,
	})

	status, stdout, stderr := runCLI(t,
		[]string{"config", "validate", "--config-dir", directory},
		map[string]string{"SIMPLE_SIEM_ENV": "development", "ELASTIC_DEV_API_KEY": "test-key"})

	if status != 1 {
		t.Fatalf("run() status = %d, want 1; stdout: %s", status, stdout)
	}
	if stdout != "" {
		t.Errorf("run() stdout = %q, want empty", stdout)
	}
	for _, fragment := range []string{"query_templates/auth-logins.yaml", "sort"} {
		if !strings.Contains(stderr, fragment) {
			t.Errorf("run() stderr %q does not contain %q", stderr, fragment)
		}
	}
}

func TestRunConfigValidateSingularCounts(t *testing.T) {
	directory := writeConfigDirectory(t, map[string]string{
		"system.yaml": "version: \"0.1\"\n",
		"fetchers.yaml": `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
		"query_templates/auth-logins.yaml": `id: auth-logins
fetcherType: elasticsearch
version: 0.1.0
rawQuery:
  query:
    term: { event.category: authentication }
`,
		"pipelines/auth.yaml": `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
fetchers:
  - id: auth
    ref: elastic-dev
    inputs:
      index: auth-*
      query_template: auth-logins
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events:
    from: udm.auth_events
`,
		"mappings/auth.yaml": runTestMapping,
	})

	status, stdout, stderr := runCLI(t,
		[]string{"config", "validate", "--config-dir", directory},
		map[string]string{"SIMPLE_SIEM_ENV": "development", "ELASTIC_DEV_API_KEY": "test-key"})

	if status != 0 {
		t.Fatalf("run() status = %d, want 0; stderr: %s", status, stderr)
	}
	if want := "config valid: 1 fetcher instance, 1 pipeline, 1 dataset\n"; stdout != want {
		t.Errorf("run() stdout = %q, want %q", stdout, want)
	}
}

func TestRunConfigValidateReportsEveryProblem(t *testing.T) {
	directory := writeConfigDirectory(t, map[string]string{
		"system.yaml":   "version: \"0.1\"\nscheduler: {}\n",
		"fetchers.yaml": "fetchers:\n  elastic-dev:\n    type: elasticsearch\n    adresses: []\n",
	})

	status, stdout, stderr := runCLI(t,
		[]string{"config", "validate", "--config-dir", directory},
		map[string]string{"SIMPLE_SIEM_ENV": "development"})

	if status != 1 {
		t.Fatalf("run() status = %d, want 1; stderr: %s", status, stderr)
	}
	if stdout != "" {
		t.Errorf("run() stdout = %q, want empty", stdout)
	}
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("run() stderr has %d lines, want 2:\n%s", len(lines), stderr)
	}
	for _, fragment := range []string{"system.yaml", "scheduler", "fetchers.yaml", "adresses"} {
		if !strings.Contains(stderr, fragment) {
			t.Errorf("run() stderr %q does not contain %q", stderr, fragment)
		}
	}
	if strings.Contains(stderr, "SIMPLE_SIEM_DATABASE_URL") {
		t.Errorf("run() stderr %q mentions the database", stderr)
	}
}

func TestRunConfigUsage(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantFragments []string
	}{
		{
			name:          "no action",
			args:          []string{"config"},
			wantFragments: []string{"usage: simple-siem config validate"},
		},
		{
			name:          "unknown action",
			args:          []string{"config", "frobnicate"},
			wantFragments: []string{"usage: simple-siem config validate"},
		},
		{
			name:          "unknown flag",
			args:          []string{"config", "validate", "--no-such-flag"},
			wantFragments: []string{"no-such-flag", "usage: simple-siem config validate"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, stdout, stderr := runCLI(t, test.args, nil)

			if status != 2 {
				t.Fatalf("run() status = %d, want 2; stderr: %s", status, stderr)
			}
			if stdout != "" {
				t.Errorf("run() stdout = %q, want empty", stdout)
			}
			for _, fragment := range test.wantFragments {
				if !strings.Contains(stderr, fragment) {
					t.Errorf("run() stderr %q does not contain %q", stderr, fragment)
				}
			}
		})
	}
}

func TestRunConfigInvalidEnvironment(t *testing.T) {
	status, stdout, stderr := runCLI(t,
		[]string{"config", "validate", "--config-dir", filepath.Join(t.TempDir(), "missing")},
		map[string]string{"SIMPLE_SIEM_ENV": "staging"})

	if status != 2 {
		t.Fatalf("run() status = %d, want 2; stderr: %s", status, stderr)
	}
	if stdout != "" {
		t.Errorf("run() stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, `SIMPLE_SIEM_ENV must be "development" or "production"`) {
		t.Errorf("run() stderr = %q, want the environment error", stderr)
	}
	if strings.Contains(stderr, "system.yaml") {
		t.Errorf("run() stderr = %q, must not load the configuration before the environment check", stderr)
	}
}

func TestRunCommandUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no pipeline", args: []string{"run"}},
		{name: "two pipelines", args: []string{"run", "one", "two"}},
		{name: "unknown flag", args: []string{"run", "--no-such-flag", "auth-events"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, stdout, stderr := runCLI(t, test.args, nil)

			if status != 2 {
				t.Fatalf("run() status = %d, want 2; stderr: %s", status, stderr)
			}
			if stdout != "" {
				t.Errorf("run() stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, "usage: simple-siem run <pipeline-id> [--config-dir DIR]") {
				t.Errorf("run() stderr %q does not print the run usage", stderr)
			}
		})
	}
}

func TestRunCommandUnknownPipeline(t *testing.T) {
	testDatabase, environment := runCommandEnvironment(t)
	directory := runCommandConfig(t, "http://127.0.0.1:1")

	status, stdout, stderr := runCLI(t,
		[]string{"run", "missing", "--config-dir", directory}, environment)

	if status != 1 {
		t.Fatalf("run() status = %d, want 1; stderr: %s", status, stderr)
	}
	if stdout != "" {
		t.Errorf("run() stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, `unknown pipeline "missing"`) {
		t.Errorf("run() stderr %q does not name the unknown pipeline", stderr)
	}
	var runs int
	if err := testDatabase.Raw("SELECT count(*) FROM pipeline_runs").Scan(&runs).Error; err != nil {
		t.Fatalf("count run rows: %v", err)
	}
	if runs != 0 {
		t.Errorf("run rows = %d, want 0", runs)
	}
}

func TestRunCommandSkipped(t *testing.T) {
	testDatabase, environment := runCommandEnvironment(t)
	ctx := context.Background()
	sqlDatabase, err := testDatabase.DB()
	if err != nil {
		t.Fatalf("connection pool: %v", err)
	}
	connection, err := sqlDatabase.Conn(ctx)
	if err != nil {
		t.Fatalf("reserve connection: %v", err)
	}
	defer func() {
		_, _ = connection.ExecContext(ctx, "SELECT pg_advisory_unlock(hashtextextended('pipeline:' || $1, 0))", "auth-events")
		_ = connection.Close()
	}()
	var acquired bool
	err = connection.QueryRowContext(ctx,
		"SELECT pg_try_advisory_lock(hashtextextended('pipeline:' || $1, 0))", "auth-events").Scan(&acquired)
	if err != nil || !acquired {
		t.Fatalf("take the pipeline lock: acquired = %t, error = %v", acquired, err)
	}

	directory := runCommandConfig(t, "http://127.0.0.1:1")
	status, stdout, stderr := runCLI(t,
		[]string{"run", "auth-events", "--config-dir", directory}, environment)

	if status != 0 {
		t.Fatalf("run() status = %d, want 0; stderr: %s", status, stderr)
	}
	result := decodeRunResult(t, stdout)
	if result.Status != pipeline.StatusSkipped {
		t.Errorf("result status = %q, want SKIPPED", result.Status)
	}
	if result.RunID == "" {
		t.Error("result run id is empty")
	}
}

func TestRunCommandFailedBackend(t *testing.T) {
	testDatabase, environment := runCommandEnvironment(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := "http://" + listener.Addr().String()
	_ = listener.Close()

	directory := runCommandConfig(t, address)
	status, stdout, stderr := runCLI(t,
		[]string{"run", "auth-events", "--config-dir", directory}, environment)

	if status != 1 {
		t.Fatalf("run() status = %d, want 1; stderr: %s", status, stderr)
	}
	result := decodeRunResult(t, stdout)
	if result.Status != pipeline.StatusFailed {
		t.Errorf("result status = %q, want FAILED", result.Status)
	}
	if !strings.Contains(result.Error, "BACKEND_UNAVAILABLE") {
		t.Errorf("result error = %q, want the backend failure", result.Error)
	}
	rowStatus := runRowStatus(t, testDatabase, result.RunID)
	if rowStatus != string(pipeline.StatusFailed) {
		t.Errorf("run row status = %q, want FAILED", rowStatus)
	}
}

func TestRunCommandSucceeds(t *testing.T) {
	testDatabase, environment := runCommandEnvironment(t)
	now := time.Now().UTC()
	fetchTime := now.Add(-2 * time.Minute)
	server := newStubElasticsearch(t, map[string]any{
		"@timestamp": now.Add(-5 * time.Minute).Format(time.RFC3339Nano),
		"event":      map[string]any{"category": "authentication"},
	}, fetchTime)

	directory := runCommandConfig(t, server.URL)
	status, stdout, stderr := runCLI(t,
		[]string{"run", "auth-events", "--config-dir", directory}, environment)

	if status != 0 {
		t.Fatalf("run() status = %d, want 0; stderr: %s", status, stderr)
	}
	result := decodeRunResult(t, stdout)
	if result.Status != pipeline.StatusOK {
		t.Errorf("result status = %q, want OK; error: %s", result.Status, result.Error)
	}
	if result.RecordsRead != 1 || result.RecordsWritten != 1 {
		t.Errorf("records read/written = %d/%d, want 1/1", result.RecordsRead, result.RecordsWritten)
	}
	if !result.WindowStart.Before(result.WindowEnd) {
		t.Errorf("window = %s..%s, want start before end", result.WindowStart, result.WindowEnd)
	}
	var events int
	if err := testDatabase.Raw("SELECT count(*) FROM dataset_events").Scan(&events).Error; err != nil {
		t.Fatalf("count dataset events: %v", err)
	}
	if events != 1 {
		t.Errorf("dataset events = %d, want 1", events)
	}
	if got := runRowStatus(t, testDatabase, result.RunID); got != string(pipeline.StatusOK) {
		t.Errorf("run row status = %q, want OK", got)
	}
}

func TestRunConfigValidateRejectsPhaseOneShape(t *testing.T) {
	directory := writeConfigDirectory(t, map[string]string{
		"system.yaml": "version: \"0.1\"\n",
		"fetchers.yaml": `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [http://es.example.internal:9200]
    auth:
      username: ${secret:ELASTICSEARCH_USERNAME}
      password: ${secret:ELASTICSEARCH_PASSWORD}
    allowed_indexes: [auth-*]
`,
		"query_templates/auth-events.yaml": `id: auth-events
fetcherType: elasticsearch
version: 0.1.0
rawQuery:
  query:
    term: { event.category: authentication }
`,
		"mappings/auth.yaml": runTestMapping,
		"pipelines/auth.yaml": `id: auth-events
version: 0.1.0
schedule: {timeout: 2m}
fetchers:
  - id: auth
    ref: elastic-dev
    inputs: {index: auth-*, query_template: auth-events}
  - id: edr
    ref: elastic-dev
    inputs: {index: auth-*, query_template: auth-events}
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events: {from: udm.auth_events}
`,
	})

	status, stdout, stderr := runCLI(t,
		[]string{"config", "validate", "--config-dir", directory},
		map[string]string{
			"SIMPLE_SIEM_ENV":        "development",
			"ELASTICSEARCH_USERNAME": "elastic",
			"ELASTICSEARCH_PASSWORD": "test-password",
		})

	if status != 1 {
		t.Fatalf("run() status = %d, want 1; stdout: %s", status, stdout)
	}
	for _, fragment := range []string{"auth-events", "Phase 1 runs one fetcher step, one converter, one output"} {
		if !strings.Contains(stderr, fragment) {
			t.Errorf("run() stderr %q does not contain %q", stderr, fragment)
		}
	}
}

func TestExampleConfigLoads(t *testing.T) {
	files, err := loadFileConfig("../../config", config.EnvironmentDevelopment, func(name string) string {
		switch name {
		case "ELASTICSEARCH_USERNAME":
			return "elastic"
		case "ELASTICSEARCH_PASSWORD":
			return "test-password"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("loadFileConfig() error = %v", err)
	}
	if len(files.Pipelines) != 1 || files.Pipelines[0].ID != "auth-events" {
		t.Fatalf("pipelines = %#v, want the one auth-events pipeline", files.Pipelines)
	}
	if _, ok := files.Fetchers["elastic-dev"]; !ok {
		t.Fatalf("fetchers = %#v, want elastic-dev", files.Fetchers)
	}
	pipeline := files.Pipelines[0]
	if len(pipeline.Fetchers) != 1 || pipeline.Fetchers[0].Ref != "elastic-dev" {
		t.Errorf("fetcher steps = %#v, want one on elastic-dev", pipeline.Fetchers)
	}
	if len(pipeline.Processors) != 1 || len(pipeline.Processors[0].Mappings) != 2 {
		t.Fatalf("processors = %#v, want one converter with both shipped mappings", pipeline.Processors)
	}
	if _, ok := pipeline.Outputs["auth_events"]; !ok {
		t.Errorf("outputs = %#v, want auth_events", pipeline.Outputs)
	}
}

func runCommandEnvironment(t *testing.T) (*gorm.DB, map[string]string) {
	t.Helper()
	testDatabase, databaseURL := databasetest.NewUnmigrated(t)
	return testDatabase, map[string]string{
		"SIMPLE_SIEM_ENV":          "development",
		"SIMPLE_SIEM_DATABASE_URL": databaseURL,
		"ELASTICSEARCH_USERNAME":   "elastic",
		"ELASTICSEARCH_PASSWORD":   "test-password",
	}
}

// runTestMapping is the smallest mapping the pipeline tests convert with.
const runTestMapping = `id: auth
version: 1
match: [{field: event.category, equals: authentication}]
constants: {metadata.event_type: GENERIC_EVENT}
fields: [{to: metadata.event_timestamp, from: "@timestamp"}]
`

func runCommandConfig(t *testing.T, address string) string {
	t.Helper()
	return writeConfigDirectory(t, map[string]string{
		"system.yaml": "version: \"0.1\"\n",
		"fetchers.yaml": fmt.Sprintf(`fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [%s]
    auth:
      username: ${secret:ELASTICSEARCH_USERNAME}
      password: ${secret:ELASTICSEARCH_PASSWORD}
    allowed_indexes: [auth-*]
`, address),
		"query_templates/auth-events.yaml": `id: auth-events
fetcherType: elasticsearch
version: 0.1.0
rawQuery:
  query:
    term: { event.category: authentication }
`,
		"mappings/auth.yaml": runTestMapping,
		"pipelines/auth-events.yaml": `id: auth-events
version: 0.1.0
schedule: {timeout: 2m}
fetchers:
  - id: auth
    ref: elastic-dev
    inputs: {index: auth-*, query_template: auth-events}
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events: {from: udm.auth_events}
`,
	})
}

// newStubElasticsearch serves one hit and then an empty page, enough for the
// Elasticsearch fetcher to complete one window.
func newStubElasticsearch(t *testing.T, source map[string]any, fetchTime time.Time) *httptest.Server {
	t.Helper()
	var searches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/_pit"):
			writeStubJSON(t, writer, map[string]any{"id": "pit-stub"})
		case request.Method == http.MethodPost && request.URL.Path == "/_search":
			hits := []any{}
			if searches.Add(1) == 1 {
				hits = append(hits, map[string]any{
					"_index":  "auth-linux-2026.11.14",
					"_id":     "doc-1",
					"_source": source,
					"sort":    []any{fetchTime.UTC().Format(time.RFC3339Nano), 1},
				})
			}
			writeStubJSON(t, writer, map[string]any{
				"pit_id": "pit-stub",
				"hits":   map[string]any{"hits": hits},
			})
		case request.Method == http.MethodDelete && request.URL.Path == "/_pit":
			writer.WriteHeader(http.StatusOK)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func writeStubJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode stub response: %v", err)
	}
}

func decodeRunResult(t *testing.T, stdout string) pipeline.RunResult {
	t.Helper()
	if strings.Count(stdout, "\n") != 1 || !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("run() stdout = %q, want exactly one JSON line", stdout)
	}
	var result pipeline.RunResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode run result %q: %v", stdout, err)
	}
	return result
}

func runRowStatus(t *testing.T, testDatabase *gorm.DB, runID string) string {
	t.Helper()
	var status string
	if err := testDatabase.Raw("SELECT status FROM pipeline_runs WHERE id = ?", runID).Scan(&status).Error; err != nil {
		t.Fatalf("read run row status: %v", err)
	}
	return status
}

func runCLI(t *testing.T, args []string, environment map[string]string) (status int, stdout, stderr string) {
	t.Helper()
	var stdoutBuffer, stderrBuffer bytes.Buffer
	status = run(context.Background(), args, mapGetenv(environment), strings.NewReader(""), &stdoutBuffer, &stderrBuffer)
	return status, stdoutBuffer.String(), stderrBuffer.String()
}

func writeConfigDirectory(t *testing.T, files map[string]string) string {
	t.Helper()
	directory := t.TempDir()
	for name, content := range files {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create config directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write config file %s: %v", name, err)
		}
	}
	return directory
}

func TestRunInvalidConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer

	status := run(context.Background(), []string{"serve"}, mapGetenv(nil), strings.NewReader(""), &stdout, &stderr)

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
	status := run(context.Background(), []string{"serve", "--migrate=false"}, getenv, strings.NewReader(""), &stdout, &stderr)

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
	status := run(context.Background(), []string{"migrate"}, getenv, strings.NewReader(""), &stdout, &stderr)

	if status != 0 {
		t.Fatalf("run() status = %d, want 0; stdout: %s; stderr: %s", status, stdout.String(), stderr.String())
	}
	if err := database.CheckSchema(context.Background(), testDatabase); err != nil {
		t.Errorf("schema after migrate: %v", err)
	}
}

func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	server := newHTTPServer(config.Config{Listen: "127.0.0.1:0"}, nil, nil, nil, logger)

	timeouts := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", server.ReadHeaderTimeout, readHeaderTimeout},
		{"ReadTimeout", server.ReadTimeout, readTimeout},
		{"WriteTimeout", server.WriteTimeout, writeTimeout},
		{"IdleTimeout", server.IdleTimeout, idleTimeout},
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

func TestAdminCreateFromStdin(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, stdout, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", " Admin@Example.com ")
	if status != 0 {
		t.Fatalf("admin create status = %d, want 0; stderr: %s", status, stderr)
	}
	if !strings.Contains(stdout, "created admin ") {
		t.Errorf("stdout = %q, want a created admin line", stdout)
	}
	if strings.Contains(stdout, cliTestPassword) || strings.Contains(stderr, cliTestPassword) {
		t.Errorf("output contains the password: stdout %q, stderr %q", stdout, stderr)
	}
	assertNoUserPassword(t, database, cliTestPassword)

	var user struct {
		ID          string
		Status      string
		DisplayName string
	}
	mustScan(t, database, &user,
		"SELECT id::text AS id, status, display_name FROM users WHERE email = ?", "admin@example.com")
	if user.ID == "" {
		t.Fatal("admin create wrote no user")
	}
	if user.Status != auth.StatusActive {
		t.Errorf("user status = %q, want %q", user.Status, auth.StatusActive)
	}
	if user.DisplayName != "admin" {
		t.Errorf("user display name = %q, want the email local part", user.DisplayName)
	}

	var roles int64
	mustScan(t, database, &roles,
		"SELECT count(*) FROM user_roles WHERE user_id = ? AND role_name = ?", user.ID, auth.RoleAdmin)
	if roles != 1 {
		t.Errorf("user has %d ADMIN roles, want 1", roles)
	}

	var events int64
	mustScan(t, database, &events,
		"SELECT count(*) FROM audit_events WHERE event_name = 'simple_siem.user.created'")
	if events != 1 {
		t.Errorf("admin create wrote %d user.created audit events, want 1", events)
	}
}

func TestAdminCreateFromPasswordFile(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)
	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte(cliTestPassword+"\r\n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	status, stdout, stderr := runAdminCommand(t, getenv, "",
		"create", "--email", "admin@example.com", "--password-file", passwordFile)
	if status != 0 {
		t.Fatalf("admin create status = %d, want 0; stderr: %s", status, stderr)
	}
	if strings.Contains(stdout, cliTestPassword) || strings.Contains(stderr, cliTestPassword) {
		t.Errorf("output contains the password: stdout %q, stderr %q", stdout, stderr)
	}

	service := newAdminTestService(t, database)
	result, err := service.Login(
		context.Background(),
		auth.LoginRequest{Email: "admin@example.com", Password: cliTestPassword},
		auth.ClientInfo{IP: net.ParseIP("192.0.2.7")},
	)
	if err != nil {
		t.Fatalf("login with the password file's first line: %v", err)
	}
	if result.User.Email != "admin@example.com" {
		t.Errorf("login user email = %q, want admin@example.com", result.User.Email)
	}
}

func TestAdminCreateRejectsShortPassword(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, "short pass1", "create", "--email", "admin@example.com")
	if status != 1 {
		t.Fatalf("admin create status = %d, want 1", status)
	}
	if !strings.Contains(stderr, "12 to 128") {
		t.Errorf("stderr = %q, want the password length rule", stderr)
	}

	var users int64
	mustScan(t, database, &users, "SELECT count(*) FROM users")
	if users != 0 {
		t.Errorf("admin create wrote %d users, want 0", users)
	}
}

func TestAdminCreateRejectsDuplicateEmail(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", "admin@example.com")
	if status != 0 {
		t.Fatalf("first admin create status = %d, want 0; stderr: %s", status, stderr)
	}
	var eventsBefore int64
	mustScan(t, database, &eventsBefore, "SELECT count(*) FROM audit_events")

	status, _, stderr = runAdminCommand(t, getenv, "another correct horse", "create", "--email", " Admin@Example.com ")
	if status != 1 {
		t.Fatalf("duplicate admin create status = %d, want 1", status)
	}
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("stderr = %q, want the duplicate email message", stderr)
	}

	var eventsAfter int64
	mustScan(t, database, &eventsAfter, "SELECT count(*) FROM audit_events")
	if eventsAfter != eventsBefore {
		t.Errorf("duplicate admin create wrote %d audit events, want 0", eventsAfter-eventsBefore)
	}
}

func TestAdminCreateRejectsLongDisplayName(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword,
		"create", "--email", "admin@example.com", "--display-name", strings.Repeat("a", 201))
	if status != 1 {
		t.Fatalf("admin create with a long display name status = %d, want 1", status)
	}
	if !strings.Contains(stderr, "display name must be 1 to 200") {
		t.Errorf("stderr = %q, want the display name rule", stderr)
	}

	var users int64
	mustScan(t, database, &users, "SELECT count(*) FROM users")
	if users != 0 {
		t.Errorf("admin create wrote %d users, want 0", users)
	}
}

func TestAdminCreateCutsDefaultDisplayName(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)
	localPart := strings.Repeat("a", 210)
	email := localPart + "@example.com"

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", email)
	if status != 0 {
		t.Fatalf("admin create status = %d, want 0; stderr: %s", status, stderr)
	}

	var displayName string
	mustScan(t, database, &displayName, "SELECT display_name FROM users WHERE email = ?", email)
	if displayName != strings.Repeat("a", 200) {
		t.Errorf("display name = %q (%d runes), want 200 a's", displayName, len([]rune(displayName)))
	}
}

func TestAdminCreateRejectsNonASCIIEmail(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", "ÄDMIN@example.com")
	if status != 1 {
		t.Fatalf("admin create status = %d, want 1", status)
	}
	if stderr == "" {
		t.Error("admin create printed no error for a non-ASCII email")
	}

	var users int64
	mustScan(t, database, &users, "SELECT count(*) FROM users")
	if users != 0 {
		t.Errorf("admin create wrote %d users, want 0", users)
	}
}

func TestAdminCreateRejectsPasswordFlag(t *testing.T) {
	status, stdout, stderr := runAdminCommand(t, mapGetenv(nil), "",
		"create", "--email", "admin@example.com", "--password", "x")

	if status != 2 {
		t.Fatalf("admin create --password status = %d, want 2", status)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "usage: simple-siem admin create") {
		t.Errorf("stderr = %q, want the admin usage", stderr)
	}
}

func TestAdminCreateRequiresEmail(t *testing.T) {
	status, _, stderr := runAdminCommand(t, mapGetenv(nil), "", "create")

	if status != 2 {
		t.Fatalf("admin create without --email status = %d, want 2", status)
	}
	if !strings.Contains(stderr, "usage: simple-siem admin create") {
		t.Errorf("stderr = %q, want the admin usage", stderr)
	}
}

func TestAdminResetPasswordRevokesSessions(t *testing.T) {
	database, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, cliTestPassword, "create", "--email", "admin@example.com")
	if status != 0 {
		t.Fatalf("admin create status = %d, want 0; stderr: %s", status, stderr)
	}

	service := newAdminTestService(t, database)
	client := auth.ClientInfo{IP: net.ParseIP("192.0.2.7")}
	var tokens []string
	for attempt := 1; attempt <= 2; attempt++ {
		result, err := service.Login(
			context.Background(),
			auth.LoginRequest{Email: "admin@example.com", Password: cliTestPassword},
			client,
		)
		if err != nil {
			t.Fatalf("login %d: %v", attempt, err)
		}
		tokens = append(tokens, result.Token)
	}

	const newPassword = "fresh correct horse"
	status, stdout, stderr := runAdminCommand(t, getenv, newPassword,
		"reset-password", "--email", "admin@example.com")
	if status != 0 {
		t.Fatalf("admin reset-password status = %d, want 0; stderr: %s", status, stderr)
	}
	if !strings.Contains(stdout, "revoked 2 sessions") {
		t.Errorf("stdout = %q, want two revoked sessions", stdout)
	}
	if strings.Contains(stdout, newPassword) || strings.Contains(stderr, newPassword) {
		t.Errorf("output contains the new password: stdout %q, stderr %q", stdout, stderr)
	}

	for index, token := range tokens {
		if _, err := service.Authenticate(context.Background(), token); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("session %d after reset: error = %v, want ErrUnauthenticated", index+1, err)
		}
	}

	if _, err := service.Login(
		context.Background(),
		auth.LoginRequest{Email: "admin@example.com", Password: newPassword},
		client,
	); err != nil {
		t.Errorf("login with the new password: %v", err)
	}
}

func TestAdminResetPasswordRejectsUnknownEmail(t *testing.T) {
	_, getenv := newAdminTestDatabase(t)

	status, _, stderr := runAdminCommand(t, getenv, "fresh correct horse",
		"reset-password", "--email", "nobody@example.com")
	if status != 1 {
		t.Fatalf("admin reset-password status = %d, want 1", status)
	}
	if !strings.Contains(stderr, "no user with this email") {
		t.Errorf("stderr = %q, want the unknown email message", stderr)
	}
}

func TestRunServeWarnsWithoutUsers(t *testing.T) {
	_, baseGetenv := newAdminTestDatabase(t)
	address := reserveAddress(t)
	getenv := func(name string) string {
		if name == "SIMPLE_SIEM_LISTEN" {
			return address
		}
		return baseGetenv(name)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	exitCode := make(chan int, 1)
	go func() {
		exitCode <- run(ctx, []string{"serve"}, getenv, strings.NewReader(""), &stdout, &stderr)
	}()

	waitForListener(t, address)
	cancel()

	select {
	case status := <-exitCode:
		if status != 0 {
			t.Fatalf("serve status = %d, want 0; stderr: %s", status, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop after the context was cancelled")
	}

	for _, fragment := range []string{"no users exist", "simple-siem admin create --email <email>"} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Errorf("stdout %q does not contain %q", stdout.String(), fragment)
		}
	}
}

func TestRunAdminUnknownSubcommand(t *testing.T) {
	status, stdout, stderr := runAdminCommand(t, mapGetenv(nil), "", "frobnicate")

	if status != 2 {
		t.Errorf("admin frobnicate status = %d, want 2", status)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	for _, usage := range []string{
		"usage: simple-siem admin create",
		"usage: simple-siem admin reset-password",
	} {
		if !strings.Contains(stderr, usage) {
			t.Errorf("stderr %q does not contain %q", stderr, usage)
		}
	}
}

func TestNewHTTPServerWiresAuthService(t *testing.T) {
	database, _ := newAdminTestDatabase(t)
	service := newAdminTestService(t, database)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	server := newHTTPServer(config.Config{Listen: "127.0.0.1:0"}, nil, database, service, logger)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/auth/providers = %d, want 200: %s", response.Code, response.Body)
	}
	if got, want := response.Body.String(), `{"data":[{"id":"local"}]}`; got != want {
		t.Errorf("providers body = %s, want %s", got, want)
	}
}

func TestNewHTTPServerSetsSecureBrowserCookie(t *testing.T) {
	database, _ := newAdminTestDatabase(t)
	service := newAdminTestService(t, database)
	if _, err := service.CreateAdmin(context.Background(), "admin@example.com", "Admin User", cliTestPassword); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	server := newHTTPServer(config.Config{
		Listen:      "127.0.0.1:0",
		Environment: config.EnvironmentProduction,
		PublicURL:   "https://siem.example.com",
	}, nil, database, service, logger)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(
		fmt.Sprintf(`{"email":%q,"password":%q}`, "admin@example.com", cliTestPassword),
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Requested-With", "simple-siem")
	request.Header.Set("Origin", "https://siem.example.com")
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("browser login = %d, want 200: %s", response.Code, response.Body)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("browser login set %d cookies, want 1: %v", len(cookies), cookies)
	}
	if !cookies[0].Secure {
		t.Error("browser login over an https public URL set no Secure cookie")
	}
}

func newAdminTestDatabase(t *testing.T) (*gorm.DB, func(string) string) {
	t.Helper()
	testDatabase, databaseURL := databasetest.NewUnmigrated(t)
	if _, err := database.Migrate(context.Background(), testDatabase); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return testDatabase, mapGetenv(map[string]string{
		"SIMPLE_SIEM_ENV":          "development",
		"SIMPLE_SIEM_DATABASE_URL": databaseURL,
	})
}

func newAdminTestService(t *testing.T, database *gorm.DB) *auth.Service {
	t.Helper()
	service, err := auth.NewService(
		context.Background(),
		database,
		auth.Settings{IdleTimeout: 30 * time.Minute, AbsoluteLifetime: 12 * time.Hour},
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service
}

func runAdminCommand(t *testing.T, getenv func(string) string, stdin string, args ...string) (status int, stdout, stderr string) {
	t.Helper()
	var stdoutBuffer, stderrBuffer bytes.Buffer
	status = run(context.Background(), append([]string{"admin"}, args...), getenv, strings.NewReader(stdin), &stdoutBuffer, &stderrBuffer)
	return status, stdoutBuffer.String(), stderrBuffer.String()
}

func mustScan(t *testing.T, database *gorm.DB, value any, query string, args ...any) {
	t.Helper()
	if err := database.Raw(query, args...).Scan(value).Error; err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
}

// assertNoUserPassword checks that no identity or audit row stores the password.
func assertNoUserPassword(t *testing.T, database *gorm.DB, password string) {
	t.Helper()
	var identityRows, auditRows string
	mustScan(t, database, &identityRows,
		"SELECT COALESCE(jsonb_agg(user_identities)::text, '') FROM user_identities")
	mustScan(t, database, &auditRows,
		"SELECT COALESCE(jsonb_agg(changes)::text, '') FROM audit_events")
	if strings.Contains(identityRows, password) {
		t.Errorf("user identities contain the password: %s", identityRows)
	}
	if strings.Contains(auditRows, password) {
		t.Errorf("audit changes contain the password: %s", auditRows)
	}
}

func reserveAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return address
}

func mapGetenv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func newTestServer(t *testing.T, handler http.Handler) (*http.Server, string) {
	t.Helper()
	address := reserveAddress(t)
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
