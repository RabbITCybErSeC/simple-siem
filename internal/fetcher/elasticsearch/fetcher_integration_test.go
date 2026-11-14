//go:build elasticsearch

package elasticsearch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/devdata"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher"
)

func TestIntegrationSuccessfulWindow(t *testing.T) {
	environment := integrationEnvironment(t)
	options := integrationOptions(t, 20)
	_, documents := integrationSeed(t, environment, options)
	window := integrationFullWindow(options)

	baseline := integrationOpenContexts(t, environment)
	fetcherClient := integrationFetcher(t, integrationInstance(environment, options.IndexPrefix+"-*"), os.Getenv)
	records, status := integrationFetch(t, fetcherClient, integrationFetchRequest(integrationTemplate(), options.IndexPrefix+"-*", window))

	if status.Status != fetcher.StatusOK {
		t.Fatalf("status = %q, want OK; errors: %#v", status.Status, status.Errors)
	}
	expected := integrationExpectedKeys(t, documents, window)
	integrationAssertKeys(t, records, expected)
	if status.RecordCount != len(records) || status.PageCount == 0 {
		t.Errorf("record/page count = %d/%d, want %d and at least 1", status.RecordCount, status.PageCount, len(records))
	}
	if status.LastRecord == nil {
		t.Fatal("LastRecord = nil, want the last emitted record")
	}
	last := records[len(records)-1]
	if status.LastRecord.FetchTime != last.FetchTime || status.LastRecord.Key != last.Key {
		t.Errorf("LastRecord = %#v, want the last emitted record %#v", status.LastRecord, last)
	}
	integrationAssertPayloads(t, records, documents)
	integrationWaitOpenContexts(t, environment, baseline)
}

func TestIntegrationEmptyWindow(t *testing.T) {
	environment := integrationEnvironment(t)
	options := integrationOptions(t, 5)
	integrationSeed(t, environment, options)
	window := fetcher.Window{Start: options.End.Add(time.Hour), End: options.End.Add(2 * time.Hour)}

	fetcherClient := integrationFetcher(t, integrationInstance(environment, options.IndexPrefix+"-*"), os.Getenv)
	records, status := integrationFetch(t, fetcherClient, integrationFetchRequest(integrationTemplate(), options.IndexPrefix+"-*", window))

	if status.Status != fetcher.StatusOK || status.RecordCount != 0 || len(records) != 0 {
		t.Errorf("status = %q records = %d, want OK with 0 records", status.Status, len(records))
	}
	if status.LastRecord != nil {
		t.Errorf("LastRecord = %#v, want nil", status.LastRecord)
	}
}

func TestIntegrationPagingMatchesOnePage(t *testing.T) {
	environment := integrationEnvironment(t)
	options := integrationOptions(t, 20)
	_, documents := integrationSeed(t, environment, options)
	window := integrationFullWindow(options)
	instance := integrationInstance(environment, options.IndexPrefix+"-*")

	small := instance
	small.Defaults.PageSize = 7
	smallFetcher := integrationFetcher(t, small, os.Getenv)
	smallRecords, smallStatus := integrationFetch(t, smallFetcher, integrationFetchRequest(integrationTemplate(), options.IndexPrefix+"-*", window))

	large := instance
	large.Defaults.PageSize = 1000
	largeFetcher := integrationFetcher(t, large, os.Getenv)
	largeRecords, largeStatus := integrationFetch(t, largeFetcher, integrationFetchRequest(integrationTemplate(), options.IndexPrefix+"-*", window))

	if smallStatus.Status != fetcher.StatusOK || largeStatus.Status != fetcher.StatusOK {
		t.Fatalf("statuses = %q/%q, want OK/OK", smallStatus.Status, largeStatus.Status)
	}
	integrationAssertKeys(t, smallRecords, integrationExpectedKeys(t, documents, window))
	integrationAssertKeys(t, largeRecords, integrationExpectedKeys(t, documents, window))
	if smallStatus.RecordCount != largeStatus.RecordCount {
		t.Errorf("record counts = %d/%d, want equal", smallStatus.RecordCount, largeStatus.RecordCount)
	}
	if smallStatus.PageCount < 2 {
		t.Errorf("small pages = %d, want at least 2", smallStatus.PageCount)
	}
	if smallStatus.RenderedQueryHash != largeStatus.RenderedQueryHash {
		t.Errorf("rendered hashes differ by page size: %q != %q", smallStatus.RenderedQueryHash, largeStatus.RenderedQueryHash)
	}
}

func TestIntegrationResultLimitContinues(t *testing.T) {
	environment := integrationEnvironment(t)
	options := integrationOptions(t, 20)
	_, documents := integrationSeed(t, environment, options)
	window := integrationFullWindow(options)
	index := options.IndexPrefix + "-*"

	instance := integrationInstance(environment, index)
	instance.Defaults.MaxResults = 12
	instance.Defaults.PageSize = 7
	fetcherClient := integrationFetcher(t, instance, os.Getenv)
	firstRecords, firstStatus := integrationFetch(t, fetcherClient, integrationFetchRequest(integrationTemplate(), index, window))

	if firstStatus.Status != fetcher.StatusPartial || !firstStatus.Truncated {
		t.Fatalf("status = %q truncated = %t, want PARTIAL/true", firstStatus.Status, firstStatus.Truncated)
	}
	if len(firstRecords) != 12 || firstStatus.LastRecord == nil {
		t.Fatalf("records = %d, LastRecord = %#v; want 12 and a last record", len(firstRecords), firstStatus.LastRecord)
	}
	requirePartial(t, firstStatus, fetcher.ErrorCodeResultLimitReached, false)

	continuation := fetcher.Window{Start: firstStatus.LastRecord.FetchTime, End: window.End}
	continuationInstance := instance
	continuationInstance.Defaults.MaxResults = 100000
	continuationFetcher := integrationFetcher(t, continuationInstance, os.Getenv)
	secondRecords, secondStatus := integrationFetch(t, continuationFetcher, integrationFetchRequest(integrationTemplate(), index, continuation))
	if secondStatus.Status != fetcher.StatusOK {
		t.Fatalf("continuation status = %q, want OK; errors: %#v", secondStatus.Status, secondStatus.Errors)
	}

	union := map[dataset.SourceKey]bool{}
	for _, record := range append(firstRecords, secondRecords...) {
		union[record.Key] = true
	}
	expected := integrationExpectedKeys(t, documents, window)
	for _, record := range firstRecords {
		if !expected[record.Key] {
			t.Errorf("first fetch returned unexpected key %#v", record.Key)
		}
	}
	if !reflect.DeepEqual(union, expected) {
		t.Errorf("union of both fetches = %d keys, want %d", len(union), len(expected))
	}
}

func TestIntegrationByteLimit(t *testing.T) {
	environment := integrationEnvironment(t)
	options := integrationOptions(t, 2500)
	_, documents := integrationSeed(t, environment, options)
	window := integrationFullWindow(options)
	index := options.IndexPrefix + "-*"

	instance := integrationInstance(environment, index)
	instance.Defaults.PageSize = 200
	instance.Defaults.MaxBytes = 1 << 20
	fetcherClient := integrationFetcher(t, instance, os.Getenv)
	records, status := integrationFetch(t, fetcherClient, integrationFetchRequest(integrationTemplate(), index, window))

	expected := integrationExpectedKeys(t, documents, window)
	if status.Status != fetcher.StatusPartial || !status.Truncated {
		t.Fatalf("status = %q truncated = %t, want PARTIAL/true", status.Status, status.Truncated)
	}
	if len(records) == 0 || len(records) >= len(expected) {
		t.Fatalf("records = %d of %d, want a non-empty strict subset", len(records), len(expected))
	}
	if status.LastRecord == nil {
		t.Error("LastRecord = nil, want the last emitted record")
	}
	requirePartial(t, status, fetcher.ErrorCodeByteLimitReached, false)
}

func TestIntegrationAuthFailure(t *testing.T) {
	environment := integrationEnvironment(t)
	instance := integrationInstance(environment, "auth-*")
	getter := func(name string) string {
		if name == "ELASTICSEARCH_USERNAME" {
			return environment.username
		}
		return environment.password + "-wrong"
	}
	fetcherClient := integrationFetcher(t, instance, getter)

	request := integrationFetchRequest(integrationTemplate(), "auth-*", fetcher.Window{Start: time.Now().Add(-time.Hour), End: time.Now()})
	status, err := fetcherClient.Fetch(context.Background(), request, discardPage)
	requireFailure(t, status, err, fetcher.ErrorCodeAuthFailed, false)
	if strings.Contains(err.Error(), environment.password) {
		t.Errorf("Fetch() error contains the password: %q", err)
	}
}

func TestIntegrationUnreachableAddress(t *testing.T) {
	environment := integrationEnvironment(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := "http://" + listener.Addr().String()
	_ = listener.Close()

	instance := integrationInstance(environment, "auth-*")
	instance.Addresses = []string{address}
	fetcherClient := integrationFetcher(t, instance, os.Getenv)

	request := integrationFetchRequest(integrationTemplate(), "auth-*", fetcher.Window{Start: time.Now().Add(-time.Hour), End: time.Now()})
	status, fetchErr := fetcherClient.Fetch(context.Background(), request, discardPage)
	requireFailure(t, status, fetchErr, fetcher.ErrorCodeBackendUnavailable, true)
}

func TestIntegrationIndexNotAllowedSendsNoRequest(t *testing.T) {
	environment := integrationEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	instance := integrationInstance(environment, "auth-*")
	instance.Addresses = []string{server.URL}
	fetcherClient := integrationFetcher(t, instance, os.Getenv)

	request := integrationFetchRequest(integrationTemplate(), "edr-*", fetcher.Window{Start: time.Now().Add(-time.Hour), End: time.Now()})
	status, err := fetcherClient.Fetch(context.Background(), request, discardPage)
	requireFailure(t, status, err, fetcher.ErrorCodeIndexNotAllowed, false)
	if got := requests.Load(); got != 0 {
		t.Errorf("backend received %d requests for a denied index, want 0", got)
	}
}

func TestIntegrationHostileValues(t *testing.T) {
	environment := integrationEnvironment(t)
	options := integrationOptions(t, 5)
	integrationSeed(t, environment, options)
	window := integrationFullWindow(options)
	index := options.IndexPrefix + "-*"
	template := integrationUserTemplate()
	instance := integrationInstance(environment, index)
	instance.Defaults.MaxResults = 10000

	hostile := []string{
		"*",
		"}}",
		`"}}, {"script": {"source": "1"}}`,
		`{"script": {"source": "1"}}`,
		strings.Repeat("x", 10*1024),
		"${parameters.other}",
	}
	hashes := map[string]bool{}
	for _, value := range hostile {
		fetcherClient := integrationFetcher(t, instance, os.Getenv)
		request := integrationFetchRequest(template, index, window)
		request.Values = map[string]string{"user": value}
		records, status := integrationFetch(t, fetcherClient, request)
		if status.Status != fetcher.StatusOK || len(records) != 0 {
			t.Errorf("hostile value %q returned %d records with status %q, want none", value, len(records), status.Status)
		}
		bound, err := fetcher.Bind(template.RawQuery, template.Parameters, request.Values)
		if err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		wantHash := fetcher.RenderedHash(searchBase(bound, instance.Defaults.FetchTimeField, window))
		if status.RenderedQueryHash != wantHash {
			t.Errorf("hostile value %q hash = %q, want the template-shaped body hash %q", value, status.RenderedQueryHash, wantHash)
		}
		if hashes[status.RenderedQueryHash] {
			t.Errorf("hostile value %q produced a duplicate rendered hash", value)
		}
		hashes[status.RenderedQueryHash] = true
	}
}

func TestIntegrationOptionalParameterUnset(t *testing.T) {
	environment := integrationEnvironment(t)
	options := integrationOptions(t, 20)
	_, documents := integrationSeed(t, environment, options)
	window := integrationFullWindow(options)
	index := options.IndexPrefix + "-*"
	template := integrationUserTemplate()

	unsetFetcher := integrationFetcher(t, integrationInstance(environment, index), os.Getenv)
	unsetRecords, unsetStatus := integrationFetch(t, unsetFetcher, integrationFetchRequest(template, index, window))
	if unsetStatus.Status != fetcher.StatusOK {
		t.Fatalf("unset status = %q, want OK", unsetStatus.Status)
	}
	integrationAssertKeys(t, unsetRecords, integrationExpectedKeys(t, documents, window))

	setFetcher := integrationFetcher(t, integrationInstance(environment, index), os.Getenv)
	setRequest := integrationFetchRequest(template, index, window)
	setRequest.Values = map[string]string{"user": "alice"}
	setRecords, setStatus := integrationFetch(t, setFetcher, setRequest)
	if setStatus.Status != fetcher.StatusOK {
		t.Fatalf("set status = %q, want OK", setStatus.Status)
	}
	expected := map[dataset.SourceKey]bool{}
	for key := range integrationExpectedKeys(t, documents, window) {
		expected[key] = true
	}
	alice := map[dataset.SourceKey]bool{}
	for _, document := range documents {
		user, _ := document.Source["user"].(map[string]any)
		if user["name"] == "alice" && integrationInWindow(t, document, window) {
			alice[integrationKey(document)] = true
		}
	}
	if !reflect.DeepEqual(integrationRecordKeys(setRecords), alice) {
		t.Errorf("user=alice returned %d keys, want %d", len(setRecords), len(alice))
	}
	if len(alice) == 0 || len(alice) == len(expected) {
		t.Errorf("the user filter is not selective: %d of %d", len(alice), len(expected))
	}
}

func TestIntegrationPITExpiryAfterFirstPage(t *testing.T) {
	environment := integrationEnvironment(t)
	options := integrationOptions(t, 20)
	integrationSeed(t, environment, options)
	window := integrationFullWindow(options)
	index := options.IndexPrefix + "-*"
	instance := integrationInstance(environment, index)
	instance.Defaults.PageSize = 7
	fetcherClient := integrationFetcher(t, instance, os.Getenv)

	var currentPIT atomic.Value
	fetcherClient.onPIT = func(pitID string) { currentPIT.Store(pitID) }

	var records []fetcher.SourceRecord
	pages := 0
	status, err := fetcherClient.Fetch(context.Background(), integrationFetchRequest(integrationTemplate(), index, window), func(page []fetcher.SourceRecord) error {
		records = append(records, page...)
		pages++
		if pages != 1 {
			return nil
		}
		pitID, _ := currentPIT.Load().(string)
		if pitID == "" {
			return errors.New("point in time id not captured")
		}
		integrationDeletePIT(t, environment, pitID)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v, want nil for PARTIAL", err)
	}
	if status.Status != fetcher.StatusPartial || !status.Truncated {
		t.Errorf("status = %q truncated = %t, want PARTIAL/true", status.Status, status.Truncated)
	}
	if len(records) == 0 || status.PageCount != 1 || status.RecordCount != len(records) {
		t.Errorf("records = %d page count = %d record count = %d, want the first page to stand", len(records), status.PageCount, status.RecordCount)
	}
	requirePartial(t, status, fetcher.ErrorCodePITExpired, true)
}

func TestIntegrationPITClosed(t *testing.T) {
	environment := integrationEnvironment(t)
	options := integrationOptions(t, 10)
	integrationSeed(t, environment, options)
	window := integrationFullWindow(options)
	index := options.IndexPrefix + "-*"
	instance := integrationInstance(environment, index)
	baseline := integrationOpenContexts(t, environment)

	t.Run("success", func(t *testing.T) {
		fetcherClient := integrationFetcher(t, instance, os.Getenv)
		integrationFetch(t, fetcherClient, integrationFetchRequest(integrationTemplate(), index, window))
		integrationWaitOpenContexts(t, environment, baseline)
	})

	t.Run("emit error", func(t *testing.T) {
		fetcherClient := integrationFetcher(t, instance, os.Getenv)
		status, err := fetcherClient.Fetch(context.Background(), integrationFetchRequest(integrationTemplate(), index, window),
			func([]fetcher.SourceRecord) error { return errTestEmit })
		requireFailure(t, status, err, fetcher.ErrorCodeEmitFailed, false)
		integrationWaitOpenContexts(t, environment, baseline)
	})

	t.Run("cancellation", func(t *testing.T) {
		fetcherClient := integrationFetcher(t, instance, os.Getenv)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		status, err := fetcherClient.Fetch(ctx, integrationFetchRequest(integrationTemplate(), index, window),
			func([]fetcher.SourceRecord) error {
				cancel()
				return nil
			})
		requireFailure(t, status, err, fetcher.ErrorCodeCanceled, false)
		integrationWaitOpenContexts(t, environment, baseline)
	})
}

var errTestEmit = errors.New("the caller rejected the page")

type integrationEnvironmentValues struct {
	url      string
	username string
	password string
}

func integrationEnvironment(t *testing.T) integrationEnvironmentValues {
	t.Helper()
	environment := integrationEnvironmentValues{
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
	status, _, err := integrationHTTP(environment, http.MethodGet, "/")
	if err != nil {
		t.Fatalf("Elasticsearch at %s is unreachable: %v", environment.url, err)
	}
	if status != http.StatusOK {
		t.Fatalf("Elasticsearch health check returned %d, want 200", status)
	}
	return environment
}

func integrationOptions(t *testing.T, background int) devdata.Options {
	t.Helper()
	return devdata.Options{
		Seed:        7,
		End:         time.Now().UTC().Truncate(time.Second),
		IndexPrefix: integrationPrefix(t),
		Background:  background,
	}
}

func integrationPrefix(t *testing.T) string {
	t.Helper()
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatalf("random prefix: %v", err)
	}
	return "t-" + hex.EncodeToString(random[:])
}

func integrationSeed(t *testing.T, environment integrationEnvironmentValues, options devdata.Options) (string, []devdata.Document) {
	t.Helper()
	writer := &devdata.Writer{URL: environment.url, Username: environment.username, Password: environment.password}
	ctx := context.Background()
	if err := writer.PutIndexTemplate(ctx, options.IndexPrefix); err != nil {
		t.Fatalf("put index template: %v", err)
	}
	documents := devdata.GenerateAuthLogs(options)
	t.Cleanup(func() { integrationCleanup(t, environment, options.IndexPrefix, documents) })
	if _, err := writer.Write(ctx, documents); err != nil {
		t.Fatalf("seed documents: %v", err)
	}
	return options.IndexPrefix, documents
}

func integrationCleanup(t *testing.T, environment integrationEnvironmentValues, prefix string, documents []devdata.Document) {
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
		if _, _, err := integrationHTTP(environment, http.MethodDelete, "/"+strings.Join(indexes, ",")); err != nil {
			t.Logf("cleanup indexes: %v", err)
		}
	}
	if _, _, err := integrationHTTP(environment, http.MethodDelete, "/_index_template/"+prefix+"-dev-auth"); err != nil {
		t.Logf("cleanup index template: %v", err)
	}
}

func integrationFetcher(t *testing.T, instance config.FetcherInstance, getenv func(string) string) *Fetcher {
	t.Helper()
	fetcherClient, err := New(instance, getenv)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return fetcherClient
}

func integrationInstance(environment integrationEnvironmentValues, allowedIndex string) config.FetcherInstance {
	return config.FetcherInstance{
		ID:        "integration",
		Type:      "elasticsearch",
		Addresses: []string{environment.url},
		Auth: config.FetcherAuth{
			Username: &config.SecretRef{Name: "ELASTICSEARCH_USERNAME"},
			Password: &config.SecretRef{Name: "ELASTICSEARCH_PASSWORD"},
		},
		AllowedIndexes: []string{allowedIndex},
		Defaults: config.FetcherDefaults{
			Timeout:        config.Duration(30 * time.Second),
			MaxResults:     100000,
			PageSize:       1000,
			MaxBytes:       256 << 20,
			KeepAlive:      config.Duration(time.Minute),
			TimeField:      "@timestamp",
			FetchTimeField: "event.ingested",
		},
	}
}

func integrationTemplate() config.QueryTemplate {
	return config.QueryTemplate{
		ID:          "integration-auth",
		FetcherType: "elasticsearch",
		Version:     "0.1.0",
		Parameters:  map[string]config.TemplateParameter{},
		RawQuery: map[string]any{"query": map[string]any{"term": map[string]any{
			"event.category": "authentication",
		}}},
	}
}

func integrationUserTemplate() config.QueryTemplate {
	return config.QueryTemplate{
		ID:          "integration-auth-user",
		FetcherType: "elasticsearch",
		Version:     "0.1.0",
		Parameters:  map[string]config.TemplateParameter{"user": {Type: "string"}},
		RawQuery: map[string]any{"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"event.category": "authentication"}},
			map[string]any{"term": map[string]any{"user.name": "${parameters.user}"}},
		}}}},
	}
}

func integrationFetchRequest(template config.QueryTemplate, index string, window fetcher.Window) fetcher.FetchRequest {
	return fetcher.FetchRequest{
		PipelineRunID: "integration-run",
		Index:         index,
		Template:      template,
		Values:        map[string]string{},
		Window:        window,
	}
}

func integrationFullWindow(options devdata.Options) fetcher.Window {
	return fetcher.Window{
		Start: options.End.Add(-2*time.Hour - time.Minute),
		End:   options.End.Add(time.Minute),
	}
}

func integrationFetch(t *testing.T, fetcherClient *Fetcher, request fetcher.FetchRequest) ([]fetcher.SourceRecord, fetcher.FetchStatus) {
	t.Helper()
	var records []fetcher.SourceRecord
	status, err := fetcherClient.Fetch(context.Background(), request, func(page []fetcher.SourceRecord) error {
		records = append(records, page...)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	for index := 1; index < len(records); index++ {
		if records[index].FetchTime.Before(records[index-1].FetchTime) {
			t.Fatalf("records are not in fetch-time order at %d", index)
		}
	}
	return records, status
}

func integrationExpectedKeys(t *testing.T, documents []devdata.Document, window fetcher.Window) map[dataset.SourceKey]bool {
	t.Helper()
	expected := map[dataset.SourceKey]bool{}
	for _, document := range documents {
		if integrationInWindow(t, document, window) {
			expected[integrationKey(document)] = true
		}
	}
	return expected
}

func integrationInWindow(t *testing.T, document devdata.Document, window fetcher.Window) bool {
	t.Helper()
	ingested := integrationIngested(t, document)
	return !ingested.Before(window.Start) && ingested.Before(window.End)
}

func integrationIngested(t *testing.T, document devdata.Document) time.Time {
	t.Helper()
	event, ok := document.Source["event"].(map[string]any)
	if !ok {
		t.Fatalf("document %s has no event object", document.ID)
	}
	text, ok := event["ingested"].(string)
	if !ok {
		t.Fatalf("document %s has no event.ingested string", document.ID)
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		t.Fatalf("document %s event.ingested: %v", document.ID, err)
	}
	return parsed
}

func integrationKey(document devdata.Document) dataset.SourceKey {
	return dataset.SourceKey{
		FetcherInstanceID: "integration",
		Index:             document.Index,
		DocumentID:        document.ID,
	}
}

func integrationRecordKeys(records []fetcher.SourceRecord) map[dataset.SourceKey]bool {
	keys := map[dataset.SourceKey]bool{}
	for _, record := range records {
		keys[record.Key] = true
	}
	return keys
}

func integrationAssertKeys(t *testing.T, records []fetcher.SourceRecord, expected map[dataset.SourceKey]bool) {
	t.Helper()
	actual := integrationRecordKeys(records)
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("records = %d keys, want %d proper keys", len(actual), len(expected))
	}
}

func integrationAssertPayloads(t *testing.T, records []fetcher.SourceRecord, documents []devdata.Document) {
	t.Helper()
	byKey := map[dataset.SourceKey]devdata.Document{}
	for _, document := range documents {
		byKey[integrationKey(document)] = document
	}
	for _, record := range records {
		document, exists := byKey[record.Key]
		if !exists {
			t.Errorf("record key %#v is not a seeded document", record.Key)
			continue
		}
		want, err := json.Marshal(document.Source)
		if err != nil {
			t.Fatalf("marshal seeded source: %v", err)
		}
		if !reflect.DeepEqual(decodeJSON(t, record.Payload), decodeJSON(t, want)) {
			t.Errorf("payload for %s does not match the seeded source", document.ID)
		}
	}
}

func decodeJSON(t *testing.T, data []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	return value
}

func integrationOpenContexts(t *testing.T, environment integrationEnvironmentValues) int64 {
	t.Helper()
	status, body, err := integrationHTTP(environment, http.MethodGet, "/_nodes/stats/indices/search")
	if err != nil {
		t.Fatalf("read search stats: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("read search stats: status %d", status)
	}
	var stats struct {
		Indices struct {
			Search struct {
				OpenContexts int64 `json:"open_contexts"`
			} `json:"search"`
		} `json:"indices"`
	}
	if err := json.Unmarshal(body, &stats); err != nil {
		t.Fatalf("decode search stats: %v", err)
	}
	return stats.Indices.Search.OpenContexts
}

func integrationWaitOpenContexts(t *testing.T, environment integrationEnvironmentValues, want int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if integrationOpenContexts(t, environment) == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("open search contexts = %d, want %d", integrationOpenContexts(t, environment), want)
}

func integrationDeletePIT(t *testing.T, environment integrationEnvironmentValues, pitID string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"id": pitID})
	if err != nil {
		t.Fatalf("marshal PIT close body: %v", err)
	}
	request, err := http.NewRequest(http.MethodDelete, strings.TrimSuffix(environment.url, "/")+"/_pit", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build PIT close request: %v", err)
	}
	request.SetBasicAuth(environment.username, environment.password)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("close point in time: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("close point in time: status %d", response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, response.Body)
}

func integrationHTTP(environment integrationEnvironmentValues, method, path string) (int, []byte, error) {
	request, err := http.NewRequest(method, strings.TrimSuffix(environment.url, "/")+path, nil)
	if err != nil {
		return 0, nil, err
	}
	request.SetBasicAuth(environment.username, environment.password)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return response.StatusCode, nil, err
	}
	return response.StatusCode, body, nil
}
