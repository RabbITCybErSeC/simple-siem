//go:build elasticsearch

package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/devdata"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher/elasticsearch"
)

const (
	integrationDataSeed     = 7
	integrationBackground   = 200
	integrationRequestLimit = time.Minute
)

type integrationEnvironment struct {
	url      string
	username string
	password string
}

// TestRunIntegrationElasticsearch runs the shipped pipeline twice over
// overlapping windows against a real Elasticsearch.
func TestRunIntegrationElasticsearch(t *testing.T) {
	environment := integrationElasticsearch(t)
	prefix := integrationPrefix(t)
	documents := integrationSeed(t, environment, prefix)
	files := integrationFiles(t, environment, prefix)

	testDatabase := databasetest.New(t)
	runner := &Runner{
		Files:    files,
		Database: testDatabase,
		Store:    dataset.NewPostgresStore(testDatabase),
		NewFetcher: func(instance config.FetcherInstance) (fetcher.Fetcher, error) {
			return elasticsearch.New(instance, environment.getenv)
		},
		Logger: slog.New(slog.DiscardHandler),
	}

	first, err := runner.Run(context.Background(), testPipelineID)
	if err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	if first.Status != StatusOK {
		t.Fatalf("first run status = %q, want OK; error: %s", first.Status, first.Error)
	}

	if err := testDatabase.Exec(
		"UPDATE datasets SET fetch_watermark = fetch_watermark - interval '10 minutes' WHERE name = ?",
		testDataset,
	).Error; err != nil {
		t.Fatalf("move the watermark back: %v", err)
	}
	second, err := runner.Run(context.Background(), testPipelineID)
	if err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if second.Status != StatusOK {
		t.Fatalf("second run status = %q, want OK; error: %s", second.Status, second.Error)
	}

	// The overlapping second run must update records in place, not duplicate
	// them.
	var stored, distinct int
	if err := testDatabase.Raw(
		"SELECT count(*) FROM dataset_events WHERE dataset = ?", testDataset,
	).Scan(&stored).Error; err != nil {
		t.Fatalf("count stored events: %v", err)
	}
	if err := testDatabase.Raw(
		`SELECT count(DISTINCT (fetcher_instance_id, source_index, document_id))
		 FROM dataset_events WHERE dataset = ?`, testDataset,
	).Scan(&distinct).Error; err != nil {
		t.Fatalf("count distinct source keys: %v", err)
	}
	if stored != distinct {
		t.Errorf("stored events = %d, distinct source keys = %d; the runs duplicated rows", stored, distinct)
	}
	if want := len(documents) - 1; stored != want {
		t.Errorf("stored events = %d, want %d (all but the malformed document)", stored, want)
	}

	malformed := integrationDocumentsWithScenario(documents, "malformed-no-user")
	if len(malformed) != 1 {
		t.Fatalf("malformed documents = %d, want 1", len(malformed))
	}
	var quarantined int
	if err := testDatabase.Raw(
		"SELECT count(*) FROM dataset_quarantine WHERE dataset = ? AND document_id = ?",
		testDataset, malformed[0].ID,
	).Scan(&quarantined).Error; err != nil {
		t.Fatalf("count quarantine: %v", err)
	}
	if quarantined != 1 {
		t.Errorf("quarantined malformed document = %d, want 1", quarantined)
	}

	expectedUsers := map[string]int{}
	for _, document := range documents {
		if user := integrationDocumentUser(t, document); user != "" {
			expectedUsers[user]++
		}
	}
	actualUsers := map[string]int{}
	var userRows []struct {
		TargetUser string
		Count      int
	}
	if err := testDatabase.Raw(
		"SELECT target_user, count(*) AS count FROM dataset_events WHERE dataset = ? GROUP BY target_user",
		testDataset,
	).Scan(&userRows).Error; err != nil {
		t.Fatalf("count events per user: %v", err)
	}
	for _, row := range userRows {
		actualUsers[row.TargetUser] = row.Count
	}
	if !maps.Equal(actualUsers, expectedUsers) {
		t.Errorf("events per user = %v, want %v", actualUsers, expectedUsers)
	}
}

func integrationElasticsearch(t *testing.T) integrationEnvironment {
	t.Helper()
	environment := integrationEnvironment{
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

func (environment integrationEnvironment) getenv(name string) string {
	switch name {
	case "ELASTICSEARCH_USERNAME":
		return environment.username
	case "ELASTICSEARCH_PASSWORD":
		return environment.password
	}
	return ""
}

func (environment integrationEnvironment) request(method, path string, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequest(method, strings.TrimSuffix(environment.url, "/")+path, body)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(environment.username, environment.password)
	return (&http.Client{Timeout: 10 * time.Second}).Do(request)
}

func integrationPrefix(t *testing.T) string {
	t.Helper()
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatalf("random prefix: %v", err)
	}
	return "t-" + hex.EncodeToString(random[:])
}

func integrationSeed(t *testing.T, environment integrationEnvironment, prefix string) []devdata.Document {
	t.Helper()
	options := devdata.Options{
		Seed:        integrationDataSeed,
		End:         time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second),
		IndexPrefix: prefix,
		Background:  integrationBackground,
	}
	writer := &devdata.Writer{
		URL:      environment.url,
		Username: environment.username,
		Password: environment.password,
		Client:   &http.Client{Timeout: integrationRequestLimit},
	}
	ctx := context.Background()
	if err := writer.PutIndexTemplate(ctx, prefix); err != nil {
		t.Fatalf("put index template: %v", err)
	}
	documents := devdata.GenerateAuthLogs(options)
	t.Cleanup(func() { integrationCleanup(t, environment, prefix, documents) })
	if _, err := writer.Write(ctx, documents); err != nil {
		t.Fatalf("seed documents: %v", err)
	}
	return documents
}

func integrationCleanup(t *testing.T, environment integrationEnvironment, prefix string, documents []devdata.Document) {
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
		if response, err := environment.request(http.MethodDelete, "/"+strings.Join(indexes, ","), nil); err != nil {
			t.Logf("cleanup indexes: %v", err)
		} else {
			_ = response.Body.Close()
		}
	}
	if response, err := environment.request(http.MethodDelete, "/_index_template/"+prefix+"-dev-auth", nil); err != nil {
		t.Logf("cleanup index template: %v", err)
	} else {
		_ = response.Body.Close()
	}
}

// integrationFiles writes the shipped pipeline shape into a temp config
// directory pointed at the test Elasticsearch.
func integrationFiles(t *testing.T, environment integrationEnvironment, prefix string) config.Files {
	t.Helper()
	directory := t.TempDir()
	writeTestFile(t, filepath.Join(directory, "system.yaml"), "version: \"0.1\"\n")
	writeTestFile(t, filepath.Join(directory, "fetchers.yaml"), fmt.Sprintf(`fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [%s]
    auth:
      username: ${secret:ELASTICSEARCH_USERNAME}
      password: ${secret:ELASTICSEARCH_PASSWORD}
    allowed_indexes: [%s-*]
`, environment.url, prefix))
	writeTestFile(t, filepath.Join(directory, "query_templates", "auth-events.yaml"), `id: auth-events
fetcherType: elasticsearch
version: 0.1.0
rawQuery:
  query:
    term:
      event.category: authentication
`)
	writeTestFile(t, filepath.Join(directory, "pipelines", "auth-events.yaml"), fmt.Sprintf(`id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
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
`, prefix))
	for _, name := range []string{"ecs-ssh-login.yaml", "ecs-windows-logon.yaml"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "config", "mappings", name))
		if err != nil {
			t.Fatalf("read shipped mapping %s: %v", name, err)
		}
		writeTestFile(t, filepath.Join(directory, "mappings", name), string(data))
	}

	files, err := config.LoadFiles(directory, config.EnvironmentDevelopment, environment.getenv)
	if err != nil {
		t.Fatalf("load integration config: %v", err)
	}
	if err := ValidateFiles(files); err != nil {
		t.Fatalf("validate integration config: %v", err)
	}
	return files
}

func integrationDocumentsWithScenario(documents []devdata.Document, scenario string) []devdata.Document {
	var selected []devdata.Document
	for _, document := range documents {
		if document.Scenario == scenario {
			selected = append(selected, document)
		}
	}
	return selected
}

// integrationDocumentUser is the user the shipped mappings store for a
// document, or "" when it has none.
func integrationDocumentUser(t *testing.T, document devdata.Document) string {
	t.Helper()
	if winlog, ok := document.Source["winlog"].(map[string]any); ok {
		eventData, ok := winlog["event_data"].(map[string]any)
		if !ok {
			t.Fatalf("document %s has no winlog.event_data", document.ID)
		}
		user, _ := eventData["TargetUserName"].(string)
		return user
	}
	if user, ok := document.Source["user"].(map[string]any); ok {
		name, _ := user["name"].(string)
		return name
	}
	return ""
}
