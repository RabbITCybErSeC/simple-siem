package devdata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	bulkChunkSize  = 1000
	bulkFilterPath = "errors,items.*.status,items.*.error.type,items.*.error.reason"
	responseLimit  = 1 << 20
)

// PutIndexTemplate installs the typed index template for a prefix.
func (writer *Writer) PutIndexTemplate(ctx context.Context, prefix string) error {
	template := map[string]any{
		"index_patterns": []string{prefix + "-*"},
		"priority":       500,
		"template": map[string]any{
			"mappings": map[string]any{
				"dynamic_templates": []any{
					map[string]any{
						"strings_as_keywords": map[string]any{
							"match_mapping_type": "string",
							"mapping":            map[string]any{"type": "keyword"},
						},
					},
				},
				"properties": map[string]any{
					"@timestamp": map[string]any{"type": "date"},
					"event": map[string]any{"properties": map[string]any{
						"ingested": map[string]any{"type": "date"},
					}},
					"source": map[string]any{"properties": map[string]any{
						"ip":   map[string]any{"type": "ip"},
						"port": map[string]any{"type": "long"},
					}},
					"related": map[string]any{"properties": map[string]any{
						"ip": map[string]any{"type": "ip"},
					}},
					"winlog": map[string]any{"properties": map[string]any{
						"record_id": map[string]any{"type": "long"},
					}},
					"process": map[string]any{"properties": map[string]any{
						"pid": map[string]any{"type": "long"},
					}},
					"message": map[string]any{"type": "text"},
				},
			},
		},
	}
	body, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("encode index template: %w", err)
	}

	path := "/_index_template/" + url.PathEscape(prefix+"-dev-auth")
	if _, err := writer.send(ctx, http.MethodPut, path, body, "application/json"); err != nil {
		return fmt.Errorf("put index template: %w", err)
	}
	return nil
}

// Write indexes documents in bulk and returns the count per index.
func (writer *Writer) Write(ctx context.Context, documents []Document) (map[string]int, error) {
	counts := map[string]int{}
	for start := 0; start < len(documents); start += bulkChunkSize {
		end := start + bulkChunkSize
		if end > len(documents) {
			end = len(documents)
		}
		if err := writer.writeChunk(ctx, documents[start:end], end == len(documents), counts); err != nil {
			return nil, err
		}
	}
	return counts, nil
}

func (writer *Writer) writeChunk(ctx context.Context, documents []Document, refresh bool, counts map[string]int) error {
	var body bytes.Buffer
	for _, document := range documents {
		action, err := json.Marshal(map[string]any{
			"index": map[string]string{"_index": document.Index, "_id": document.ID},
		})
		if err != nil {
			return fmt.Errorf("encode bulk action: %w", err)
		}
		source, err := json.Marshal(document.Source)
		if err != nil {
			return fmt.Errorf("encode %s document %s: %w", document.Index, document.ID, err)
		}
		body.Write(action)
		body.WriteByte('\n')
		body.Write(source)
		body.WriteByte('\n')
	}

	query := url.Values{}
	query.Set("filter_path", bulkFilterPath)
	if refresh {
		query.Set("refresh", "wait_for")
	}
	path := "/_bulk?" + query.Encode()
	response, err := writer.send(ctx, http.MethodPost, path, body.Bytes(), "application/x-ndjson")
	if err != nil {
		return fmt.Errorf("bulk request: %w", err)
	}
	if err := checkBulkResponse(response); err != nil {
		return err
	}
	for _, document := range documents {
		counts[document.Index]++
	}
	return nil
}

func checkBulkResponse(response []byte) error {
	var result bulkResponse
	if err := json.Unmarshal(response, &result); err != nil {
		return fmt.Errorf("decode bulk response: %w", err)
	}
	if !result.Errors {
		return nil
	}
	for position, item := range result.Items {
		for _, outcome := range item {
			if outcome.Error != nil {
				return fmt.Errorf("bulk item %d failed: status %d: %s: %s",
					position, outcome.Status, outcome.Error.Type, outcome.Error.Reason)
			}
		}
	}
	return errors.New("bulk response reports errors without an item error")
}

// send performs one request with basic auth and never puts the credentials in
// an error.
func (writer *Writer) send(ctx context.Context, method, path string, body []byte, contentType string) ([]byte, error) {
	if writer.URL == "" {
		return nil, errors.New("elasticsearch URL is empty")
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(writer.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.SetBasicAuth(writer.Username, writer.Password)

	client := writer.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(responseBody) > responseLimit {
		return nil, fmt.Errorf("response larger than %d bytes", responseLimit)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		reason := strings.TrimSpace(string(responseBody))
		if reason == "" {
			return nil, fmt.Errorf("%s %s: %s", method, path, response.Status)
		}
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, response.Status, reason)
	}
	return responseBody, nil
}
