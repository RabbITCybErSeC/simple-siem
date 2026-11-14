package api

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// auditHandler serves the audit event read routes.
type auditHandler struct {
	database *gorm.DB
	logger   *slog.Logger
}

func (events auditHandler) list(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	query, ok := allowedQuery(c,
		"eventName", "eventCategory", "eventOutcome", "actorId", "action",
		"targetType", "targetId", "requestId", "traceId",
		"createdAfter", "createdBefore", "page", "pageSize",
	)
	if !ok {
		return
	}
	outcome := query.Get("eventOutcome")
	if outcome != "" && !audit.ValidOutcome(outcome) {
		invalidParameter(c, "eventOutcome")
		return
	}
	createdAfter, ok := parseTimeParameter(c, query, "createdAfter")
	if !ok {
		return
	}
	createdBefore, ok := parseTimeParameter(c, query, "createdBefore")
	if !ok {
		return
	}
	page, pageSize, ok := parsePagination(c, query, maxAuditPageSize)
	if !ok {
		return
	}

	listed, total, err := audit.List(c.Request.Context(), events.database, audit.Filter{
		EventName:     query.Get("eventName"),
		EventCategory: query.Get("eventCategory"),
		EventOutcome:  outcome,
		ActorID:       query.Get("actorId"),
		Action:        query.Get("action"),
		TargetType:    query.Get("targetType"),
		TargetID:      query.Get("targetId"),
		RequestID:     query.Get("requestId"),
		TraceID:       query.Get("traceId"),
		CreatedAfter:  createdAfter,
		CreatedBefore: createdBefore,
	}, page, pageSize)
	if err != nil {
		internalError(c, events.logger, err)
		return
	}

	data := make([]auditEventResponse, 0, len(listed))
	for _, event := range listed {
		data = append(data, newAuditEventResponse(event))
	}
	c.JSON(http.StatusOK, auditListResponse{Data: data, Pagination: newPagination(page, pageSize, total)})
}

func (events auditHandler) get(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	eventID, ok := pathUUID(c, "auditEventId", "audit event not found")
	if !ok {
		return
	}

	event, err := audit.Get(c.Request.Context(), events.database, eventID)
	if errors.Is(err, audit.ErrNotFound) {
		writeError(c, http.StatusNotFound, codeNotFound, "audit event not found")
		return
	}
	if err != nil {
		internalError(c, events.logger, err)
		return
	}
	c.JSON(http.StatusOK, newAuditEventResponse(event))
}

func parseTimeParameter(c *gin.Context, query url.Values, name string) (*time.Time, bool) {
	raw := query.Get(name)
	if raw == "" {
		return nil, true
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		invalidParameter(c, name)
		return nil, false
	}
	return &parsed, true
}

func newAuditEventResponse(event audit.Event) auditEventResponse {
	response := auditEventResponse{
		ID:             event.ID,
		EventName:      event.EventName,
		EventCategory:  event.EventCategory,
		EventOutcome:   event.EventOutcome,
		ActorType:      event.ActorType,
		ActorID:        event.ActorID,
		ActorSessionID: event.ActorSessionID,
		RequestID:      event.RequestID,
		TraceID:        event.TraceID,
		TargetType:     event.TargetType,
		TargetID:       event.TargetID,
		Action:         event.Action,
		Changes:        event.Changes,
		Redactions:     event.Redactions,
		CreatedAt:      event.CreatedAt.UTC().Format(time.RFC3339),
	}
	if event.SourceIP != nil {
		sourceIP := event.SourceIP.String()
		response.SourceIP = &sourceIP
	}
	if response.Redactions == nil {
		response.Redactions = []string{}
	}
	return response
}
