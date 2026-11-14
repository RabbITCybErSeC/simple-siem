package devdata_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/devdata"
)

const (
	testPassword      = "test-password"
	testFilterPath    = "errors,items.*.status,items.*.error.type,items.*.error.reason"
	testResponseLimit = 1 << 20
)

type indexTemplatePayload struct {
	IndexPatterns []string `json:"index_patterns"`
	Priority      int      `json:"priority"`
	Template      struct {
		Mappings struct {
			DynamicTemplates []map[string]struct {
				MatchMappingType string `json:"match_mapping_type"`
				Mapping          struct {
					Type string `json:"type"`
				} `json:"mapping"`
			} `json:"dynamic_templates"`
			Properties map[string]struct {
				Type       string `json:"type"`
				Properties map[string]struct {
					Type string `json:"type"`
				} `json:"properties"`
			} `json:"properties"`
		} `json:"mappings"`
	} `json:"template"`
}

func TestPutIndexTemplate(t *testing.T) {
	var method, path, contentType string
	var body []byte
	var username, password string
	var authenticated bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		contentType = r.Header.Get("Content-Type")
		body, _ = io.ReadAll(r.Body)
		username, password, authenticated = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"acknowledged":true}`)
	}))
	defer server.Close()

	if err := newTestWriter(server).PutIndexTemplate(context.Background(), "auth"); err != nil {
		t.Fatalf("PutIndexTemplate: %v", err)
	}

	if method != http.MethodPut {
		t.Errorf("method = %q, want PUT", method)
	}
	if path != "/_index_template/auth-dev-auth" {
		t.Errorf("path = %q, want /_index_template/auth-dev-auth", path)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	if !authenticated || username != "elastic" || password != testPassword {
		t.Errorf("basic auth = %q/%q (sent %t), want elastic/%s", username, password, authenticated, testPassword)
	}

	var template indexTemplatePayload
	if err := json.Unmarshal(body, &template); err != nil {
		t.Fatalf("decode template: %v", err)
	}
	if !slices.Equal(template.IndexPatterns, []string{"auth-*"}) {
		t.Errorf("index_patterns = %v, want [auth-*]", template.IndexPatterns)
	}
	if template.Priority != 500 {
		t.Errorf("priority = %d, want 500", template.Priority)
	}

	properties := template.Template.Mappings.Properties
	wantTypes := map[string]string{
		"@timestamp": "date",
		"message":    "text",
	}
	for field, want := range wantTypes {
		if got := properties[field].Type; got != want {
			t.Errorf("%s type = %q, want %q", field, got, want)
		}
	}
	wantNestedTypes := map[string]map[string]string{
		"event":   {"ingested": "date"},
		"source":  {"ip": "ip", "port": "long"},
		"related": {"ip": "ip"},
		"winlog":  {"record_id": "long"},
		"process": {"pid": "long"},
	}
	for parent, children := range wantNestedTypes {
		for field, want := range children {
			if got := properties[parent].Properties[field].Type; got != want {
				t.Errorf("%s.%s type = %q, want %q", parent, field, got, want)
			}
		}
	}

	if len(template.Template.Mappings.DynamicTemplates) != 1 {
		t.Fatalf("dynamic_templates = %d, want 1", len(template.Template.Mappings.DynamicTemplates))
	}
	for _, rule := range template.Template.Mappings.DynamicTemplates[0] {
		if rule.MatchMappingType != "string" {
			t.Errorf("dynamic template match_mapping_type = %q, want string", rule.MatchMappingType)
		}
		if rule.Mapping.Type != "keyword" {
			t.Errorf("dynamic template mapping type = %q, want keyword", rule.Mapping.Type)
		}
	}
}

func TestWriteSendsBulkNDJSON(t *testing.T) {
	var method, path, contentType string
	var query url.Values
	var body string
	var username, password string
	var authenticated bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ := io.ReadAll(r.Body)
		method = r.Method
		path = r.URL.Path
		query = r.URL.Query()
		contentType = r.Header.Get("Content-Type")
		body = string(rawBody)
		username, password, authenticated = r.BasicAuth()
		writeBulkResponse(w, bulkActionCount(body))
	}))
	defer server.Close()

	documents := []devdata.Document{
		{
			Index:    "auth-linux-2026.11.13",
			ID:       "id-one",
			Scenario: "test",
			Source:   map[string]any{"@timestamp": "2026-11-13T11:00:00.000Z", "message": "first"},
		},
		{
			Index:    "auth-windows-2026.11.13",
			ID:       "id-two",
			Scenario: "test",
			Source:   map[string]any{"@timestamp": "2026-11-13T11:01:00.000Z", "message": "second"},
		},
	}
	counts, err := newTestWriter(server).Write(context.Background(), documents)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if path != "/_bulk" {
		t.Errorf("path = %q, want /_bulk", path)
	}
	if query.Get("filter_path") != testFilterPath {
		t.Errorf("filter_path = %q, want %q", query.Get("filter_path"), testFilterPath)
	}
	if query.Get("refresh") != "wait_for" {
		t.Errorf("refresh = %q, want wait_for on the last chunk", query.Get("refresh"))
	}
	if contentType != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", contentType)
	}
	if !authenticated || username != "elastic" || password != testPassword {
		t.Errorf("basic auth = %q/%q (sent %t), want elastic/%s", username, password, authenticated, testPassword)
	}
	wantCounts := map[string]int{"auth-linux-2026.11.13": 1, "auth-windows-2026.11.13": 1}
	if len(counts) != len(wantCounts) {
		t.Errorf("counts = %v, want %v", counts, wantCounts)
	}
	for index, want := range wantCounts {
		if counts[index] != want {
			t.Errorf("counts[%s] = %d, want %d", index, counts[index], want)
		}
	}

	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("bulk lines = %d, want 4", len(lines))
	}
	var action struct {
		Index struct {
			Index string `json:"_index"`
			ID    string `json:"_id"`
		} `json:"index"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &action); err != nil {
		t.Fatalf("decode action line: %v", err)
	}
	if action.Index.Index != "auth-linux-2026.11.13" || action.Index.ID != "id-one" {
		t.Errorf("action = %+v, want auth-linux-2026.11.13/id-one", action.Index)
	}
	var source map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &source); err != nil {
		t.Fatalf("decode source line: %v", err)
	}
	if got := stringAt(t, source, "message"); got != "first" {
		t.Errorf("source message = %q, want first", got)
	}
}

func TestWriteChunksAtThousand(t *testing.T) {
	var lineCounts []int
	var queries []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ := io.ReadAll(r.Body)
		body := string(rawBody)
		lineCounts = append(lineCounts, bulkActionCount(body)*2)
		queries = append(queries, r.URL.Query())
		writeBulkResponse(w, bulkActionCount(body))
	}))
	defer server.Close()

	documents := make([]devdata.Document, 1500)
	for index := range documents {
		documents[index] = devdata.Document{
			Index: "auth-linux-2026.11.13",
			ID:    fmt.Sprintf("id-%04d", index),
			Source: map[string]any{
				"@timestamp": "2026-11-13T11:00:00.000Z",
				"sequence":   index,
			},
		}
	}
	counts, err := newTestWriter(server).Write(context.Background(), documents)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if !slices.Equal(lineCounts, []int{2000, 1000}) {
		t.Errorf("bulk body lines = %v, want [2000 1000]", lineCounts)
	}
	if len(queries) != 2 {
		t.Fatalf("requests = %d, want 2", len(queries))
	}
	for index, query := range queries {
		if got := query.Get("filter_path"); got != testFilterPath {
			t.Errorf("request %d filter_path = %q, want %q", index, got, testFilterPath)
		}
	}
	if got := queries[0].Get("refresh"); got != "" {
		t.Errorf("first refresh = %q, want none", got)
	}
	if got := queries[1].Get("refresh"); got != "wait_for" {
		t.Errorf("last refresh = %q, want wait_for", got)
	}
	if counts["auth-linux-2026.11.13"] != 1500 {
		t.Errorf("count = %d, want 1500", counts["auth-linux-2026.11.13"])
	}
}

func TestWriteRejectsOversizedResponse(t *testing.T) {
	var query url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"errors":false,"items":[]}`)
		_, _ = fmt.Fprint(w, strings.Repeat(" ", testResponseLimit))
	}))
	defer server.Close()

	_, err := newTestWriter(server).Write(context.Background(), []devdata.Document{{
		Index: "auth-linux-2026.11.13", ID: "id-one", Source: map[string]any{},
	}})
	if err == nil {
		t.Fatal("Write() error = nil, want the read-limit error")
	}
	want := fmt.Sprintf("response larger than %d bytes", testResponseLimit)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err, want)
	}
	if got := query.Get("filter_path"); got != testFilterPath {
		t.Errorf("filter_path = %q, want %q", got, testFilterPath)
	}
}

func TestWriteSurfacesItemError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"errors":true,"items":[
			{"index":{"status":201}},
			{"index":{"status":400,"error":{"type":"mapper_parsing_exception","reason":"failed to parse field [source.ip]"}}}
		]}`)
	}))
	defer server.Close()

	documents := []devdata.Document{
		{Index: "auth-linux-2026.11.13", ID: "id-one", Source: map[string]any{}},
		{Index: "auth-linux-2026.11.13", ID: "id-two", Source: map[string]any{}},
	}
	_, err := newTestWriter(server).Write(context.Background(), documents)
	if err == nil {
		t.Fatal("Write() error = nil, want the item error")
	}
	for _, want := range []string{"400", "mapper_parsing_exception", "failed to parse field [source.ip]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Errorf("error %q contains the password", err)
	}
}

func TestWriteHTTPErrorOmitsPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":{"type":"security_exception","reason":"unable to authenticate"},"status":401}`)
	}))
	defer server.Close()

	_, err := newTestWriter(server).Write(context.Background(), []devdata.Document{{
		Index: "auth-linux-2026.11.13", ID: "id-one", Source: map[string]any{},
	}})
	if err == nil {
		t.Fatal("Write() error = nil, want the HTTP error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q does not name status 401", err)
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Errorf("error %q contains the password", err)
	}
}

func TestWriteWithoutDocumentsMakesNoRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	defer server.Close()

	counts, err := newTestWriter(server).Write(context.Background(), nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(counts) != 0 {
		t.Errorf("counts = %v, want none", counts)
	}
	if requests != 0 {
		t.Errorf("requests = %d, want 0", requests)
	}
}

func newTestWriter(server *httptest.Server) *devdata.Writer {
	return &devdata.Writer{
		URL:      server.URL,
		Username: "elastic",
		Password: testPassword,
		Client:   server.Client(),
	}
}

func writeBulkResponse(w http.ResponseWriter, items int) {
	w.Header().Set("Content-Type", "application/json")
	if items == 0 {
		_, _ = fmt.Fprint(w, `{"errors":false,"items":[]}`)
		return
	}
	response := strings.TrimSuffix(strings.Repeat(`{"index":{"status":201}},`, items), ",")
	_, _ = fmt.Fprintf(w, `{"errors":false,"items":[%s]}`, response)
}

// bulkActionCount counts the action lines in a bulk request body; every
// document contributes one action line and one source line.
func bulkActionCount(body string) int {
	return len(strings.Split(strings.TrimSuffix(body, "\n"), "\n")) / 2
}
