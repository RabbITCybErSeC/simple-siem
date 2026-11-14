package api_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"gorm.io/gorm"
)

type auditBody struct {
	ID             string         `json:"id"`
	EventName      string         `json:"eventName"`
	EventCategory  string         `json:"eventCategory"`
	EventOutcome   string         `json:"eventOutcome"`
	ActorType      string         `json:"actorType"`
	ActorID        *string        `json:"actorId"`
	ActorSessionID *string        `json:"actorSessionId"`
	RequestID      string         `json:"requestId"`
	TraceID        string         `json:"traceId"`
	SourceIP       *string        `json:"sourceIp"`
	TargetType     string         `json:"targetType"`
	TargetID       string         `json:"targetId"`
	Action         string         `json:"action"`
	Changes        map[string]any `json:"changes"`
	Redactions     []string       `json:"redactions"`
	CreatedAt      string         `json:"createdAt"`
}

type auditListBody struct {
	Data       []auditBody    `json:"data"`
	Pagination paginationBody `json:"pagination"`
}

func TestAuditListFiltersByActorAndTime(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	first, _ := apiAdmin(t, router, service)
	second, err := service.CreateAdmin(
		context.Background(), "auditor@example.com", "Auditor", "auditor horse battery",
	)
	if err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	token := loginTokenFor(t, router, "auditor@example.com", "auditor horse battery")
	loginTokenFor(t, router, "auditor@example.com", "auditor horse battery")

	if err := database.Exec(
		"UPDATE audit_events SET created_at = now() - interval '2 days' WHERE actor_id = ?", first.UserID,
	).Error; err != nil {
		t.Fatalf("age the first actor's events: %v", err)
	}
	if err := database.Exec(
		"UPDATE audit_events SET created_at = now() - interval '1 day' WHERE actor_id = ?", second.ID,
	).Error; err != nil {
		t.Fatalf("age the second actor's events: %v", err)
	}
	createdAfter := time.Now().Add(-36 * time.Hour).UTC().Format(time.RFC3339)

	target := "/api/v1/audit-events?actorId=" + second.ID + "&createdAfter=" + url.QueryEscape(createdAfter)
	response := get(router, target, "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("GET audit events = %d, want 200: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var list auditListBody
	decodeJSON(t, response, &list)
	if len(list.Data) < 2 {
		t.Fatalf("filtered list returned %d events, want both logins", len(list.Data))
	}
	after, err := time.Parse(time.RFC3339, createdAfter)
	if err != nil {
		t.Fatalf("parse createdAfter: %v", err)
	}
	for index, event := range list.Data {
		if event.ActorID == nil || *event.ActorID != second.ID {
			t.Errorf("event %d actor = %v, want %q", index, event.ActorID, second.ID)
		}
		createdAt, err := time.Parse(time.RFC3339, event.CreatedAt)
		if err != nil {
			t.Fatalf("event createdAt %q is not RFC 3339: %v", event.CreatedAt, err)
		}
		if createdAt.Before(after) {
			t.Errorf("event %d createdAt %s is before createdAfter %s", index, createdAt, after)
		}
		if index > 0 {
			previous, _ := time.Parse(time.RFC3339, list.Data[index-1].CreatedAt)
			if createdAt.After(previous) {
				t.Errorf("events are not newest first: %s then %s", previous, createdAt)
			}
		}
	}
	if list.Pagination.TotalItems != int64(len(list.Data)) {
		t.Errorf("pagination totalItems = %d, want %d", list.Pagination.TotalItems, len(list.Data))
	}

	response = get(router, "/api/v1/audit-events?eventName=simple_siem.auth.login", "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("filter by eventName = %d, want 200: %s", response.Code, response.Body)
	}
	decodeJSON(t, response, &list)
	for _, event := range list.Data {
		if event.EventName != "simple_siem.auth.login" {
			t.Errorf("eventName filter returned %q", event.EventName)
		}
	}
}

func TestAuditListValidation(t *testing.T) {
	router, service, _, _ := newAPIRouter(t)
	_, token := apiAdmin(t, router, service)

	tests := []struct {
		name        string
		query       string
		wantMessage string
	}{
		{name: "malformed time", query: "?createdAfter=yesterday", wantMessage: "createdAfter"},
		{name: "page size over the maximum", query: "?pageSize=1000", wantMessage: "pageSize"},
		{name: "page over the maximum", query: "?page=9223372036854775807", wantMessage: "page"},
		{name: "unknown outcome", query: "?eventOutcome=MAYBE", wantMessage: "eventOutcome"},
		{name: "unknown parameter", query: "?sort=createdAt", wantMessage: "sort"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := get(router, "/api/v1/audit-events"+test.query, "", bearer(token))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("GET /api/v1/audit-events%s = %d, want 400: %s", test.query, response.Code, response.Body)
			}
			assertNoStore(t, response)
			assertErrorCode(t, response, "VALIDATION_ERROR", test.wantMessage)
		})
	}

	response := get(router, "/api/v1/audit-events?eventOutcome=SUCCESS", "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/audit-events?eventOutcome=SUCCESS = %d, want 200: %s", response.Code, response.Body)
	}
}

func TestGetAuditEvent(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	_, token := apiAdmin(t, router, service)

	var eventID string
	if err := database.Raw(
		"SELECT id::text FROM audit_events ORDER BY created_at DESC LIMIT 1",
	).Scan(&eventID).Error; err != nil {
		t.Fatalf("read an audit event id: %v", err)
	}
	if eventID == "" {
		t.Fatal("no audit events exist")
	}

	response := get(router, "/api/v1/audit-events/"+eventID, "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("GET audit event = %d, want 200: %s", response.Code, response.Body)
	}
	assertNoStore(t, response)
	var event auditBody
	decodeJSON(t, response, &event)
	if event.ID != eventID || event.EventName == "" || event.Action == "" {
		t.Errorf("audit event = %+v, want the stored event", event)
	}
	if _, err := time.Parse(time.RFC3339, event.CreatedAt); err != nil {
		t.Errorf("createdAt %q is not RFC 3339: %v", event.CreatedAt, err)
	}
	if event.Redactions == nil {
		t.Error("redactions = null, want an array")
	}

	for _, id := range []string{"not-a-uuid", newTestUUID()} {
		response := get(router, "/api/v1/audit-events/"+id, "", bearer(token))
		if response.Code != http.StatusNotFound {
			t.Fatalf("GET audit event %s = %d, want 404: %s", id, response.Code, response.Body)
		}
		assertErrorCode(t, response, "NOT_FOUND", "audit event not found")
	}
}

func TestAuditRedactionReadBack(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	admin, token := apiAdmin(t, router, service)
	const secret = "super-secret-value"

	err := database.Transaction(func(tx *gorm.DB) error {
		return audit.Record(tx, audit.Event{
			EventName:     "test.redaction",
			EventCategory: "TEST",
			EventOutcome:  "SUCCESS",
			ActorType:     "SYSTEM",
			TargetType:    "USER",
			TargetID:      admin.UserID,
			Action:        "test",
			Changes:       map[string]any{"password": secret, "note": "visible"},
		})
	})
	if err != nil {
		t.Fatalf("record the redaction event: %v", err)
	}

	var eventID string
	if err := database.Raw(
		"SELECT id::text FROM audit_events WHERE event_name = 'test.redaction'",
	).Scan(&eventID).Error; err != nil {
		t.Fatalf("read the redaction event id: %v", err)
	}
	response := get(router, "/api/v1/audit-events/"+eventID, "", bearer(token))
	if response.Code != http.StatusOK {
		t.Fatalf("GET the redaction event = %d, want 200: %s", response.Code, response.Body)
	}
	var event auditBody
	decodeJSON(t, response, &event)
	if event.Changes["password"] != "[REDACTED]" {
		t.Errorf("changes.password = %v, want [REDACTED]", event.Changes["password"])
	}
	if event.Changes["note"] != "visible" {
		t.Errorf("changes.note = %v, want visible", event.Changes["note"])
	}
	if !slices.Contains(event.Redactions, "changes.password") {
		t.Errorf("redactions = %v, want changes.password", event.Redactions)
	}
	if body := response.Body.String(); strings.Contains(body, secret) {
		t.Errorf("response leaks the secret: %s", body)
	}
}
