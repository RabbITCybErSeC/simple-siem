package elasticsearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher"
)

const (
	dateFormat      = "strict_date_optional_time_nanos"
	maxErrorMessage = 256
)

var errBodyTooLarge = errors.New("response body exceeds the read limit")

// fetchFailure is one failure before a final FetchStatus is built.
type fetchFailure struct {
	code      fetcher.ErrorCode
	message   string
	retryable bool
	partial   bool
}

// pageResult is one decoded search page and the bytes it cost.
type pageResult struct {
	hits      []searchHit
	pitID     string
	bytesRead int64
}

// New builds a fetcher for one instance. Secrets are resolved once here.
func New(instance config.FetcherInstance, getenv func(string) string) (*Fetcher, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: instance.TLS.InsecureSkipVerify,
	}
	if instance.TLS.CARef != nil {
		caPEM, err := instance.TLS.CARef.Resolve(getenv)
		if err != nil {
			return nil, fmt.Errorf("tls.ca_ref: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("tls.ca_ref: no certificates parsed")
		}
		tlsConfig.RootCAs = roots
	}

	authorization, err := authorizationHeader(instance.Auth, getenv)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyFromEnvironment,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Fetcher{instance: instance, client: client, authorization: authorization}, nil
}

// Fetch streams one fetch-time window page by page.
func (fetcherInstance *Fetcher) Fetch(ctx context.Context, request fetcher.FetchRequest, emit func(page []fetcher.SourceRecord) error) (fetcher.FetchStatus, error) {
	status := fetcher.FetchStatus{Status: fetcher.StatusOK}

	if !config.IndexAllowed(request.Index, fetcherInstance.instance.AllowedIndexes) {
		return failedStatus(status, fetcher.ErrorCodeIndexNotAllowed,
			fmt.Sprintf("index %q is not allowed", request.Index), false)
	}
	if !request.Window.Start.Before(request.Window.End) {
		return failedStatus(status, fetcher.ErrorCodeQueryRejected,
			"window start must be before window end", false)
	}
	if err := ValidateQuery(request.Template.RawQuery); err != nil {
		return failedStatus(status, fetcher.ErrorCodeInvalidTemplate,
			"invalid query template: "+err.Error(), false)
	}
	bound, err := fetcher.Bind(request.Template.RawQuery, request.Template.Parameters, request.Values)
	if err != nil {
		return failedStatus(status, fetcher.ErrorCodeInvalidTemplate,
			"bind query template: "+err.Error(), false)
	}

	base := searchBase(bound, fetcherInstance.instance.Defaults.FetchTimeField, request.Window)
	status.RenderedQueryHash = fetcher.RenderedHash(base)

	pitID, failure := fetcherInstance.openPIT(ctx, request.Index)
	if failure != nil {
		return failedStatus(status, failure.code, failure.message, failure.retryable)
	}
	currentPIT := pitID
	defer func() { fetcherInstance.closePIT(currentPIT) }()

	remaining := fetcherInstance.instance.Defaults.MaxResults
	var searchAfter []json.RawMessage
	for {
		if err := ctx.Err(); err != nil {
			failure := contextFailure(err)
			return failedStatus(status, failure.code, failure.message, failure.retryable)
		}

		size := min(remaining, fetcherInstance.instance.Defaults.PageSize)
		keepAlive := time.Duration(fetcherInstance.instance.Defaults.KeepAlive)
		body, err := json.Marshal(searchPage(base, size, currentPIT, keepAlive, searchAfter))
		if err != nil {
			return failedStatus(status, fetcher.ErrorCodeMalformedResponse, "encode search request", false)
		}

		page, failure := fetcherInstance.search(ctx, body, status.BytesRead)
		status.BytesRead += page.bytesRead
		if failure != nil {
			if failure.partial {
				return partialStatus(status, failure.code, failure.message, failure.retryable)
			}
			return failedStatus(status, failure.code, failure.message, failure.retryable)
		}
		if page.pitID != "" {
			currentPIT = page.pitID
		}
		if len(page.hits) == 0 {
			return status, nil
		}

		fetchedAt := time.Now().UTC()
		records := make([]fetcher.SourceRecord, 0, min(len(page.hits), remaining))
		var lastSort []json.RawMessage
		for _, hit := range page.hits {
			if len(records) == remaining {
				break
			}
			record, err := sourceRecord(hit, fetcherInstance.instance.ID, fetchedAt)
			if err != nil {
				return failedStatus(status, fetcher.ErrorCodeMalformedResponse, "search page: "+err.Error(), false)
			}
			records = append(records, record)
			lastSort = hit.Sort
		}

		if err := emit(records); err != nil {
			return failedStatus(status, fetcher.ErrorCodeEmitFailed, "emit page: "+err.Error(), false)
		}
		status.PageCount++
		status.RecordCount += len(records)
		last := records[len(records)-1]
		status.LastRecord = &fetcher.LastRecord{FetchTime: last.FetchTime, Key: last.Key}
		remaining -= len(records)
		if remaining == 0 {
			return partialStatus(status, fetcher.ErrorCodeResultLimitReached,
				"the fetch reached the maximum number of results", false)
		}
		searchAfter = lastSort
	}
}

func (fetcherInstance *Fetcher) openPIT(ctx context.Context, index string) (string, *fetchFailure) {
	keepAlive := time.Duration(fetcherInstance.instance.Defaults.KeepAlive)
	path := "/" + url.PathEscape(index) + "/_pit?keep_alive=" + url.QueryEscape(keepAliveValue(keepAlive))

	status, body, err := fetcherInstance.doRequest(ctx, http.MethodPost, path, nil, maxControlBody)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return "", &fetchFailure{code: fetcher.ErrorCodeMalformedResponse, message: "open point in time: response too large"}
		}
		return "", transportFailure(ctx, err)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return "", responseFailure(status, body)
	}

	var response pitResponse
	if err := json.Unmarshal(body, &response); err != nil || response.ID == "" {
		return "", &fetchFailure{code: fetcher.ErrorCodeMalformedResponse, message: "open point in time: malformed response"}
	}
	return response.ID, nil
}

func (fetcherInstance *Fetcher) search(ctx context.Context, body []byte, bytesRead int64) (pageResult, *fetchFailure) {
	limit := fetcherInstance.instance.Defaults.MaxBytes - bytesRead
	if limit < 1 {
		return pageResult{}, byteLimitFailure()
	}

	status, responseBody, err := fetcherInstance.doRequest(ctx, http.MethodPost, "/_search", body, limit)
	result := pageResult{bytesRead: int64(len(responseBody))}
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return result, byteLimitFailure()
		}
		return result, transportFailure(ctx, err)
	}
	if status == http.StatusNotFound && errorType(responseBody) == searchContextMissingException {
		return result, &fetchFailure{
			code:      fetcher.ErrorCodePITExpired,
			message:   "the point in time expired before the fetch completed",
			retryable: true,
			partial:   true,
		}
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return result, responseFailure(status, responseBody)
	}

	var response searchResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return result, &fetchFailure{code: fetcher.ErrorCodeMalformedResponse, message: "search: malformed response"}
	}
	result.hits = response.Hits.Hits
	result.pitID = response.PITID
	return result, nil
}

// closePIT always uses a fresh context so cancellation cannot skip it.
func (fetcherInstance *Fetcher) closePIT(pitID string) {
	if pitID == "" {
		return
	}
	body, err := json.Marshal(map[string]string{"id": pitID})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), pitCloseTimeout)
	defer cancel()

	status, _, err := fetcherInstance.exchange(ctx, http.MethodDelete, "/_pit", body, maxControlBody)
	if err != nil {
		slog.Warn("close elasticsearch point in time", "fetcher", fetcherInstance.instance.ID, "error", err)
		return
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		slog.Warn("close elasticsearch point in time", "fetcher", fetcherInstance.instance.ID, "status", status)
	}
}

func (fetcherInstance *Fetcher) doRequest(ctx context.Context, method, path string, body []byte, limit int64) (int, []byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(fetcherInstance.instance.Defaults.Timeout))
	defer cancel()
	return fetcherInstance.exchange(requestCtx, method, path, body, limit)
}

// exchange tries each configured address in order on a transport error and
// never retries after a response.
func (fetcherInstance *Fetcher) exchange(ctx context.Context, method, path string, body []byte, limit int64) (int, []byte, error) {
	var lastErr error
	for _, address := range fetcherInstance.instance.Addresses {
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		request, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(address, "/")+path, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		request.Header.Set("Authorization", fetcherInstance.authorization)
		request.Header.Set("Accept", "application/json")
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}

		response, err := fetcherInstance.client.Do(request)
		if err != nil {
			lastErr = err
			continue
		}
		responseBody, readErr := readLimited(response.Body, limit)
		_ = response.Body.Close()
		if readErr != nil {
			return response.StatusCode, responseBody, readErr
		}
		return response.StatusCode, responseBody, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no addresses configured")
	}
	return 0, nil, lastErr
}

func readLimited(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return data, err
	}
	if int64(len(data)) > limit {
		return data, errBodyTooLarge
	}
	return data, nil
}

func responseFailure(status int, body []byte) *fetchFailure {
	switch {
	case status >= http.StatusMultipleChoices && status < http.StatusBadRequest:
		return &fetchFailure{code: fetcher.ErrorCodeQueryRejected, message: fmt.Sprintf("backend returned status %d", status)}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &fetchFailure{code: fetcher.ErrorCodeAuthFailed, message: fmt.Sprintf("backend returned status %d", status)}
	case status >= http.StatusInternalServerError:
		return &fetchFailure{code: fetcher.ErrorCodeBackendUnavailable, message: fmt.Sprintf("backend returned status %d", status), retryable: true}
	case status >= http.StatusBadRequest:
		errorType, reason, ok := decodeError(body)
		if !ok {
			return &fetchFailure{code: fetcher.ErrorCodeMalformedResponse,
				message: fmt.Sprintf("backend returned status %d with an undecodable error body", status)}
		}
		return &fetchFailure{code: fetcher.ErrorCodeQueryRejected,
			message: fmt.Sprintf("backend rejected the query (%d): %s: %s", status, errorType, reason)}
	default:
		return &fetchFailure{code: fetcher.ErrorCodeMalformedResponse, message: fmt.Sprintf("unexpected backend status %d", status)}
	}
}

func transportFailure(parent context.Context, err error) *fetchFailure {
	if contextErr := parent.Err(); contextErr != nil {
		return contextFailure(contextErr)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return timeoutFailure()
	}
	if errors.Is(err, context.Canceled) {
		return &fetchFailure{code: fetcher.ErrorCodeCanceled, message: "fetch canceled"}
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return timeoutFailure()
	}
	if isTLSError(err) {
		return &fetchFailure{code: fetcher.ErrorCodeTLSFailed, message: "TLS handshake failed: " + err.Error()}
	}
	return &fetchFailure{code: fetcher.ErrorCodeBackendUnavailable,
		message: "request to the backend failed: " + err.Error(), retryable: true}
}

func contextFailure(err error) *fetchFailure {
	if errors.Is(err, context.DeadlineExceeded) {
		return timeoutFailure()
	}
	return &fetchFailure{code: fetcher.ErrorCodeCanceled, message: "fetch canceled"}
}

func timeoutFailure() *fetchFailure {
	return &fetchFailure{code: fetcher.ErrorCodeTimeout, message: "backend did not answer within the timeout", retryable: true}
}

func byteLimitFailure() *fetchFailure {
	return &fetchFailure{
		code:    fetcher.ErrorCodeByteLimitReached,
		message: "the fetch reached the maximum number of bytes",
		partial: true,
	}
}

func isTLSError(err error) bool {
	var certificateError *tls.CertificateVerificationError
	if errors.As(err, &certificateError) {
		return true
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return true
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return true
	}
	var invalidCertificate x509.CertificateInvalidError
	if errors.As(err, &invalidCertificate) {
		return true
	}
	var recordHeaderError tls.RecordHeaderError
	return errors.As(err, &recordHeaderError)
}

func decodeError(body []byte) (errorType, reason string, ok bool) {
	var response errorResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", "", false
	}
	if response.Error.Type == "" && response.Error.Reason == "" {
		return "", "", false
	}
	errorType = response.Error.Type
	if len(errorType) > maxErrorMessage {
		errorType = errorType[:maxErrorMessage]
	}
	reason = response.Error.Reason
	if len(reason) > maxErrorMessage {
		reason = reason[:maxErrorMessage]
	}
	return errorType, reason, true
}

func errorType(body []byte) string {
	value, _, _ := decodeError(body)
	return value
}

func sourceRecord(hit searchHit, instanceID string, fetchedAt time.Time) (fetcher.SourceRecord, error) {
	if hit.Index == "" || hit.ID == "" {
		return fetcher.SourceRecord{}, errors.New("hit without _index or _id")
	}
	if len(hit.Sort) == 0 {
		return fetcher.SourceRecord{}, errors.New("hit without sort values")
	}
	var fetchTimeText string
	if err := json.Unmarshal(hit.Sort[0], &fetchTimeText); err != nil {
		return fetcher.SourceRecord{}, errors.New("hit with a non-string fetch time")
	}
	fetchTime, err := time.Parse(time.RFC3339, fetchTimeText)
	if err != nil {
		return fetcher.SourceRecord{}, fmt.Errorf("hit with an invalid fetch time: %w", err)
	}
	return fetcher.SourceRecord{
		Key: dataset.SourceKey{
			FetcherInstanceID: instanceID,
			Index:             hit.Index,
			DocumentID:        hit.ID,
		},
		FetchTime: fetchTime,
		FetchedAt: fetchedAt,
		Payload:   hit.Source,
	}, nil
}

func failedStatus(status fetcher.FetchStatus, code fetcher.ErrorCode, message string, retryable bool) (fetcher.FetchStatus, error) {
	status.Status = fetcher.StatusFailed
	status.Errors = append(status.Errors, fetcher.FetchError{Code: code, Message: message, Retryable: retryable})
	return status, fmt.Errorf("%s: %s", code, message)
}

func partialStatus(status fetcher.FetchStatus, code fetcher.ErrorCode, message string, retryable bool) (fetcher.FetchStatus, error) {
	status.Status = fetcher.StatusPartial
	status.Truncated = true
	status.Errors = append(status.Errors, fetcher.FetchError{Code: code, Message: message, Retryable: retryable})
	return status, nil
}

func authorizationHeader(auth config.FetcherAuth, getenv func(string) string) (string, error) {
	if auth.APIKey != nil {
		apiKey, err := auth.APIKey.Resolve(getenv)
		if err != nil {
			return "", err
		}
		return "ApiKey " + apiKey, nil
	}
	if auth.Username == nil || auth.Password == nil {
		return "", errors.New("auth: exactly one of api_key or username and password is required")
	}
	username, err := auth.Username.Resolve(getenv)
	if err != nil {
		return "", err
	}
	password, err := auth.Password.Resolve(getenv)
	if err != nil {
		return "", err
	}
	credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + credentials, nil
}

// searchBase is the part of a search body that is identical for every page:
// the bound template, the fetch-time window, the sort, and the source filter.
func searchBase(bound map[string]any, fetchTimeField string, window fetcher.Window) map[string]any {
	base := map[string]any{
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			bound["query"],
			map[string]any{"range": map[string]any{fetchTimeField: map[string]any{
				"gte":    formatFetchTime(window.Start),
				"lt":     formatFetchTime(window.End),
				"format": dateFormat,
			}}},
		}}},
		"sort": []any{
			map[string]any{fetchTimeField: map[string]any{"order": "asc", "format": dateFormat}},
			map[string]any{"_shard_doc": "asc"},
		},
		"track_total_hits": false,
	}
	if source, exists := bound["_source"]; exists {
		base["_source"] = source
	}
	return base
}

// searchPage adds the per-page fields to searchBase: the page size, the point
// in time, and the search_after cursor.
func searchPage(base map[string]any, size int, pitID string, keepAlive time.Duration, searchAfter []json.RawMessage) map[string]any {
	page := make(map[string]any, len(base)+4)
	for key, value := range base {
		page[key] = value
	}
	page["size"] = size
	page["pit"] = map[string]any{"id": pitID, "keep_alive": keepAliveValue(keepAlive)}
	if len(searchAfter) > 0 {
		page["search_after"] = searchAfter
	}
	return page
}

// keepAliveValue renders a duration in the milliseconds form Elasticsearch
// accepts; Go's duration form ("1m0s") is rejected by its time parser.
func keepAliveValue(keepAlive time.Duration) string {
	return fmt.Sprintf("%dms", keepAlive.Milliseconds())
}

func formatFetchTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}
