//go:build elasticsearch

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/detection"
	"github.com/RabbITCybErSeC/simple-siem/internal/devdata"
	"github.com/RabbITCybErSeC/simple-siem/internal/pipeline"
	"gorm.io/gorm"
)

const (
	m1DataSeedA      = 11
	m1DataSeedB      = 12
	m1Background     = 50
	m1RequestTimeout = time.Minute
	m1WindowStep     = 5 * time.Minute
	m1DetectionID    = "brute-force-then-success"
)

// m1Alert is the read side of one alerts row.
type m1Alert struct {
	ID              string             `gorm:"column:id"`
	Identity        map[string]*string `gorm:"column:identity;serializer:json"`
	EvidenceCount   int                `gorm:"column:evidence_count"`
	OccurrenceCount int                `gorm:"column:occurrence_count"`
	Coalescing      bool               `gorm:"column:coalescing"`
	Status          string             `gorm:"column:status"`
	Version         int                `gorm:"column:version"`
}

func (m1Alert) TableName() string {
	return "alerts"
}

// m1Snapshot is the state phase 3 must leave unchanged.
type m1Snapshot struct {
	evidenceCount   int
	occurrenceCount int
	version         int
}

// m1Environment is the Elasticsearch connection from the test environment.
type m1Environment struct {
	url      string
	username string
	password string
}

// TestM1AlertCoalescingEndToEnd is milestone M1: two synthetic bursts produce
// exactly two alerts, a later burst merges into each, and re-running every
// window changes nothing.
func TestM1AlertCoalescingEndToEnd(t *testing.T) {
	environment := m1Elasticsearch(t)
	prefix := m1Prefix(t)
	endB := time.Now().UTC().Truncate(time.Minute).Add(-30 * time.Minute)
	endA := endB.Add(-30 * time.Minute)
	m1Seed(t, environment, prefix, endA, endB)
	directory := m1Config(t, environment, prefix)

	testDatabase, cliEnvironment := runCommandEnvironment(t)
	cliEnvironment["ELASTICSEARCH_USERNAME"] = environment.username
	cliEnvironment["ELASTICSEARCH_PASSWORD"] = environment.password

	status, stdout, stderr := runCLI(t, []string{"run", "auth-events", "--config-dir", directory}, cliEnvironment)
	if status != 0 {
		t.Fatalf("run auth-events: status %d, stderr: %s", status, stderr)
	}
	if result := decodeRunResult(t, stdout); result.Status != pipeline.StatusOK {
		t.Fatalf("run auth-events status = %q, want OK; error: %s", result.Status, result.Error)
	}

	phase1 := m1WindowEnds(endA.Add(-100*time.Minute), endA.Add(-15*time.Minute))
	m1RunWindows(t, cliEnvironment, directory, phase1)

	alerts := m1LoadAlerts(t, testDatabase)
	byUser := m1AssertAlerts(t, alerts)
	for user, alert := range byUser {
		if alert.EvidenceCount != 13 {
			t.Errorf("%s evidence_count = %d, want 13", user, alert.EvidenceCount)
		}
		var evidenceRows int64
		mustScan(t, testDatabase, &evidenceRows, "SELECT count(*) FROM alert_evidence WHERE alert_id = ?", alert.ID)
		if evidenceRows != 13 {
			t.Errorf("%s evidence rows = %d, want 13", user, evidenceRows)
		}
		if !alert.Coalescing {
			t.Errorf("%s coalescing = false, want true", user)
		}
		if alert.Status != "OPEN" {
			t.Errorf("%s status = %q, want OPEN", user, alert.Status)
		}
	}
	var auditCount int64
	mustScan(t, testDatabase, &auditCount,
		"SELECT count(*) FROM audit_events WHERE event_name = ?", "simple_siem.alert.created")
	if auditCount != 2 {
		t.Errorf("alert.created audit events = %d, want 2", auditCount)
	}
	var runtimeStatus string
	mustScan(t, testDatabase, &runtimeStatus,
		"SELECT status FROM detection_runtime WHERE detection_id = ?", m1DetectionID)
	if runtimeStatus != "ENABLED" {
		t.Errorf("detection runtime = %q, want ENABLED", runtimeStatus)
	}

	phase2 := m1WindowEnds(endA.Add(-10*time.Minute), endB.Add(5*time.Minute))
	m1RunWindows(t, cliEnvironment, directory, phase2)

	alerts = m1LoadAlerts(t, testDatabase)
	byUser = m1AssertAlerts(t, alerts)
	for user, alert := range byUser {
		if alert.EvidenceCount != 26 {
			t.Errorf("%s evidence_count = %d, want 26", user, alert.EvidenceCount)
		}
		var evidenceRows int64
		mustScan(t, testDatabase, &evidenceRows, "SELECT count(*) FROM alert_evidence WHERE alert_id = ?", alert.ID)
		if evidenceRows != 26 {
			t.Errorf("%s evidence rows = %d, want 26", user, evidenceRows)
		}
		if alert.OccurrenceCount < 2 {
			t.Errorf("%s occurrence_count = %d, want at least 2", user, alert.OccurrenceCount)
		}
	}
	var auditCountAfter int64
	mustScan(t, testDatabase, &auditCountAfter,
		"SELECT count(*) FROM audit_events WHERE event_name = ?", "simple_siem.alert.created")
	if auditCountAfter != 2 {
		t.Errorf("alert.created audit events after phase 2 = %d, want 2", auditCountAfter)
	}

	snapshots := map[string]m1Snapshot{}
	for user, alert := range byUser {
		snapshots[user] = m1Snapshot{
			evidenceCount:   alert.EvidenceCount,
			occurrenceCount: alert.OccurrenceCount,
			version:         alert.Version,
		}
	}
	allWindows := make([]time.Time, 0, len(phase1)+len(phase2))
	allWindows = append(allWindows, phase1...)
	allWindows = append(allWindows, phase2...)
	for _, windowEnd := range allWindows {
		result := m1Detect(t, cliEnvironment, directory, windowEnd)
		if result.AlertsCreated != 0 || result.AlertsMerged != 0 {
			t.Errorf("re-run window ending %s created %d and merged %d, want 0 and 0",
				windowEnd.Format(time.RFC3339), result.AlertsCreated, result.AlertsMerged)
		}
	}

	alerts = m1LoadAlerts(t, testDatabase)
	byUser = m1AssertAlerts(t, alerts)
	for user, alert := range byUser {
		snapshot := snapshots[user]
		if alert.EvidenceCount != snapshot.evidenceCount ||
			alert.OccurrenceCount != snapshot.occurrenceCount ||
			alert.Version != snapshot.version {
			t.Errorf("%s after re-runs = evidence %d, occurrences %d, version %d; want %d, %d, %d",
				user, alert.EvidenceCount, alert.OccurrenceCount, alert.Version,
				snapshot.evidenceCount, snapshot.occurrenceCount, snapshot.version)
		}
	}
}

// m1WindowEnds lists every window end from start to end inclusive, step 5m.
func m1WindowEnds(start, end time.Time) []time.Time {
	var windows []time.Time
	for windowEnd := start; !windowEnd.After(end); windowEnd = windowEnd.Add(m1WindowStep) {
		windows = append(windows, windowEnd)
	}
	return windows
}

func m1RunWindows(t *testing.T, environment map[string]string, directory string, windows []time.Time) {
	t.Helper()
	for _, windowEnd := range windows {
		m1Detect(t, environment, directory, windowEnd)
	}
}

func m1Detect(t *testing.T, environment map[string]string, directory string, windowEnd time.Time) detection.RunResult {
	t.Helper()
	status, stdout, stderr := runCLI(t, []string{
		"detect", m1DetectionID, "--window-end", windowEnd.UTC().Format(time.RFC3339), "--config-dir", directory,
	}, environment)
	if status != 0 {
		t.Fatalf("detect window ending %s: status %d, stderr: %s", windowEnd.Format(time.RFC3339), status, stderr)
	}
	result := decodeJSONLine[detection.RunResult](t, stdout)
	if result.Status != detection.RunStatusOK {
		t.Fatalf("detect window ending %s status = %q, want OK; error: %s",
			windowEnd.Format(time.RFC3339), result.Status, result.Error)
	}
	return result
}

func m1LoadAlerts(t *testing.T, db *gorm.DB) []m1Alert {
	t.Helper()
	var alerts []m1Alert
	if err := db.Order("id").Find(&alerts).Error; err != nil {
		t.Fatalf("load alerts: %v", err)
	}
	return alerts
}

// m1AssertAlerts checks the exact two identities and returns them by user.
func m1AssertAlerts(t *testing.T, alerts []m1Alert) map[string]m1Alert {
	t.Helper()
	if len(alerts) != 2 {
		t.Fatalf("alerts = %d, want exactly 2", len(alerts))
	}
	wantHosts := map[string]string{"alice": "web01", "bob": "dc01"}
	byUser := map[string]m1Alert{}
	for _, alert := range alerts {
		user := m1IdentityValue(alert, "target.user.userid")
		host := m1IdentityValue(alert, "target.hostname")
		wantHost, known := wantHosts[user]
		if !known {
			t.Errorf("unexpected alert for user %q on host %q", user, host)
			continue
		}
		if host != wantHost {
			t.Errorf("%s host = %q, want %q", user, host, wantHost)
		}
		byUser[user] = alert
	}
	for _, user := range []string{"alice", "bob"} {
		if _, present := byUser[user]; !present {
			t.Errorf("missing alert for %s", user)
		}
	}
	return byUser
}

func m1IdentityValue(alert m1Alert, path string) string {
	value := alert.Identity[path]
	if value == nil {
		return ""
	}
	return *value
}

func m1Elasticsearch(t *testing.T) m1Environment {
	t.Helper()
	environment := m1Environment{
		url:      os.Getenv("ELASTICSEARCH_URL"),
		username: os.Getenv("ELASTICSEARCH_USERNAME"),
		password: os.Getenv("ELASTICSEARCH_PASSWORD"),
	}
	var missing []string
	if environment.url == "" {
		missing = append(missing, "ELASTICSEARCH_URL")
	}
	if environment.username == "" {
		missing = append(missing, "ELASTICSEARCH_USERNAME")
	}
	if environment.password == "" {
		missing = append(missing, "ELASTICSEARCH_PASSWORD")
	}
	if len(missing) > 0 {
		t.Fatalf("%s must be set; the integration suite fails rather than skips", strings.Join(missing, ", "))
	}
	response, err := environment.request(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("Elasticsearch at %s is unreachable: %v", environment.url, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Elasticsearch health check returned %d, want 200", response.StatusCode)
	}
	return environment
}

func (environment m1Environment) request(method, path string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequest(method, strings.TrimSuffix(environment.url, "/")+path, body)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(environment.username, environment.password)
	return (&http.Client{Timeout: 10 * time.Second}).Do(request)
}

func m1Prefix(t *testing.T) string {
	t.Helper()
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatalf("random prefix: %v", err)
	}
	return "t-" + hex.EncodeToString(random[:])
}

func m1Seed(t *testing.T, environment m1Environment, prefix string, endA, endB time.Time) {
	t.Helper()
	datasetA := devdata.GenerateAuthLogs(devdata.Options{
		Seed: m1DataSeedA, End: endA, IndexPrefix: prefix, Background: m1Background,
	})
	datasetB := devdata.GenerateAuthLogs(devdata.Options{
		Seed: m1DataSeedB, End: endB, IndexPrefix: prefix, Background: m1Background,
	})
	documents := append(datasetA, datasetB...)
	writer := &devdata.Writer{
		URL:      environment.url,
		Username: environment.username,
		Password: environment.password,
		Client:   &http.Client{Timeout: m1RequestTimeout},
	}
	ctx := context.Background()
	if err := writer.PutIndexTemplate(ctx, prefix); err != nil {
		t.Fatalf("put index template: %v", err)
	}
	t.Cleanup(func() { m1Cleanup(t, environment, prefix, documents) })
	if _, err := writer.Write(ctx, documents); err != nil {
		t.Fatalf("seed documents: %v", err)
	}
}

func m1Cleanup(t *testing.T, environment m1Environment, prefix string, documents []devdata.Document) {
	t.Helper()
	names := map[string]bool{}
	for _, document := range documents {
		names[document.Index] = true
	}
	indexes := make([]string, 0, len(names))
	for name := range names {
		indexes = append(indexes, name)
	}
	sort.Strings(indexes)
	if len(indexes) > 0 {
		response, err := environment.request(http.MethodDelete, "/"+strings.Join(indexes, ","), nil)
		if err != nil {
			t.Logf("cleanup indexes: %v", err)
		} else {
			_ = response.Body.Close()
		}
	}
	response, err := environment.request(http.MethodDelete, "/_index_template/"+prefix+"-dev-auth", nil)
	if err != nil {
		t.Logf("cleanup index template: %v", err)
	} else {
		_ = response.Body.Close()
	}
}

// m1Config writes the shipped config shape with the test Elasticsearch and
// index prefix, no ingest delay, and the shipped allowed lateness.
func m1Config(t *testing.T, environment m1Environment, prefix string) string {
	t.Helper()
	return writeConfigDirectory(t, map[string]string{
		"system.yaml":                      m1ReadConfig(t, "system.yaml"),
		"query_templates/auth-events.yaml": m1ReadConfig(t, filepath.Join("query_templates", "auth-events.yaml")),
		"mappings/ecs-ssh-login.yaml":      m1ReadConfig(t, filepath.Join("mappings", "ecs-ssh-login.yaml")),
		"mappings/ecs-windows-logon.yaml":  m1ReadConfig(t, filepath.Join("mappings", "ecs-windows-logon.yaml")),
		"fetchers.yaml": fmt.Sprintf(`fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [%s]
    auth:
      username: ${secret:ELASTICSEARCH_USERNAME}
      password: ${secret:ELASTICSEARCH_PASSWORD}
    allowed_indexes: [%s-*]
`, environment.url, prefix),
		"pipelines/auth-events.yaml": fmt.Sprintf(`id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
  ingest_delay: 0s
fetchers:
  - id: auth
    ref: elastic-dev
    inputs:
      index: %s-*
      query_template: auth-events
processors:
  - id: auth-to-udm
    type: converter
    from: auth.records
    mappings:
      - mappings/ecs-ssh-login.yaml
      - mappings/ecs-windows-logon.yaml
    output: udm.auth_events
outputs:
  auth_events:
    from: udm.auth_events
    allowed_lateness: 10m
`, prefix),
	})
}

func m1ReadConfig(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "config", name))
	if err != nil {
		t.Fatalf("read shipped config %s: %v", name, err)
	}
	return string(data)
}
