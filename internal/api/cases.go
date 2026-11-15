package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/RabbITCybErSeC/simple-siem/internal/cases"
	"github.com/gin-gonic/gin"
)

// caseListQueryNames are the documented parameters of each case read.
var (
	caseListQueryNames = []string{
		"status", "scope", "assignee", "severity", "detection", "outcome", "q",
		"from", "to", "timeField", "sort", "limit", "cursor", "tag",
	}
	caseCountsQueryNames = []string{
		"status", "assignee", "severity", "detection", "outcome", "q",
		"from", "to", "timeField", "tag",
	}
	caseHistogramQueryNames = []string{
		"status", "scope", "assignee", "severity", "detection", "outcome", "q",
		"from", "to", "timeField", "tag", "interval", "splitBy",
	}
)

// caseHandler serves the case queue, detail, timeline, counts, and assign
// routes.
type caseHandler struct {
	service *cases.Service
	logger  *slog.Logger
}

func (handler caseHandler) list(c *gin.Context) {
	query, filter, ok := parseCaseFilter(c, caseListQueryNames...)
	if !ok {
		return
	}
	if filter.Statuses, ok = csvParameter(c, query, "status"); !ok {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	page, err := handler.service.List(c.Request.Context(), actor.UserID, filter)
	if err != nil {
		writeCaseError(c, handler.logger, err)
		return
	}
	c.JSON(http.StatusOK, cursorListResponse[cases.CaseSummary]{
		Data:       emptyIfNil(page.Items),
		Pagination: newCursorPagination(page.Limit, page.NextCursor),
	})
}

func (handler caseHandler) counts(c *gin.Context) {
	query, filter, ok := parseCaseFilter(c, caseCountsQueryNames...)
	if !ok {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	counts, err := handler.service.Counts(c.Request.Context(), actor.UserID, filter, query.Get("status"))
	if err != nil {
		writeCaseError(c, handler.logger, err)
		return
	}
	c.JSON(http.StatusOK, counts)
}

func (handler caseHandler) histogram(c *gin.Context) {
	query, filter, ok := parseCaseFilter(c, caseHistogramQueryNames...)
	if !ok {
		return
	}
	if !validateHistogramOptions(c, query) {
		return
	}
	if filter.Statuses, ok = csvParameter(c, query, "status"); !ok {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	histogram, err := handler.service.Histogram(c.Request.Context(), actor.UserID, filter)
	if err != nil {
		writeCaseError(c, handler.logger, err)
		return
	}
	c.JSON(http.StatusOK, histogram)
}

func (handler caseHandler) detail(c *gin.Context) {
	detail, err := handler.service.Get(c.Request.Context(), c.Param("caseId"))
	if err != nil {
		writeCaseError(c, handler.logger, err)
		return
	}
	c.JSON(http.StatusOK, detail)
}

func (handler caseHandler) alerts(c *gin.Context) {
	_, filter, ok := parseCaseFilter(c, "limit", "cursor")
	if !ok {
		return
	}
	caseID, ok := pathUUID(c, "caseId", "case not found")
	if !ok {
		return
	}

	page, err := handler.service.ListAlerts(c.Request.Context(), caseID, filter.Limit, filter.Cursor)
	if err != nil {
		writeCaseError(c, handler.logger, err)
		return
	}
	c.JSON(http.StatusOK, cursorListResponse[cases.AlertSummary]{
		Data:       emptyIfNil(page.Items),
		Pagination: newCursorPagination(page.Limit, page.NextCursor),
	})
}

func (handler caseHandler) timeline(c *gin.Context) {
	query, filter, ok := parseCaseFilter(c, "kind", "limit", "cursor")
	if !ok {
		return
	}
	caseID, ok := pathUUID(c, "caseId", "case not found")
	if !ok {
		return
	}

	page, err := handler.service.Timeline(
		c.Request.Context(), caseID, query.Get("kind"), filter.Limit, filter.Cursor,
	)
	if err != nil {
		writeCaseError(c, handler.logger, err)
		return
	}
	c.JSON(http.StatusOK, cursorListResponse[cases.TimelineEntry]{
		Data:       emptyIfNil(page.Items),
		Pagination: newCursorPagination(page.Limit, page.NextCursor),
	})
}

func (handler caseHandler) assign(c *gin.Context) {
	caseID, ok := pathUUID(c, "caseId", "case not found")
	if !ok {
		return
	}
	var request assignCaseRequest
	if !decodeJSONBody(c, &request) {
		return
	}
	assigneeID, ok := parseAssigneeID(c, request.AssigneeID)
	if !ok {
		return
	}
	version, ok := requiredVersion(c, request.Version)
	if !ok {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	client := clientInfo(c)
	detail, err := handler.service.Assign(c.Request.Context(), cases.Actor{
		UserID:    actor.UserID,
		SessionID: actor.SessionID,
		RequestID: client.RequestID,
		IP:        client.IP,
	}, caseID, assigneeID, version)
	if err != nil {
		writeCaseError(c, handler.logger, err)
		return
	}
	c.JSON(http.StatusOK, detail)
}

// parseCaseFilter checks the route's query parameters and builds the filter.
// Absent values stay zero, so the service applies its defaults; the service
// validates the values it owns.
func parseCaseFilter(c *gin.Context, allowedNames ...string) (url.Values, cases.ListFilter, bool) {
	query, ok := allowedQuery(c, allowedNames...)
	if !ok {
		return nil, cases.ListFilter{}, false
	}
	for _, name := range allowedNames {
		if len(query[name]) > 1 {
			invalidParameter(c, name)
			return nil, cases.ListFilter{}, false
		}
	}
	if query.Has("tag") {
		writeError(c, http.StatusBadRequest, codeValidationError, "tag filters arrive in Phase 4")
		return nil, cases.ListFilter{}, false
	}

	var filter cases.ListFilter
	var parsed bool
	if filter.AssigneeIDs, parsed = csvParameter(c, query, "assignee"); !parsed {
		return nil, cases.ListFilter{}, false
	}
	if filter.Severities, parsed = csvParameter(c, query, "severity"); !parsed {
		return nil, cases.ListFilter{}, false
	}
	if filter.DetectionIDs, parsed = csvParameter(c, query, "detection"); !parsed {
		return nil, cases.ListFilter{}, false
	}
	if filter.Outcomes, parsed = csvParameter(c, query, "outcome"); !parsed {
		return nil, cases.ListFilter{}, false
	}

	filter.Scope = query.Get("scope")
	filter.Query = query.Get("q")
	filter.TimeField = query.Get("timeField")
	filter.Sort = query.Get("sort")
	filter.Cursor = query.Get("cursor")
	if query.Has("limit") {
		limit, err := strconv.Atoi(query.Get("limit"))
		if err != nil {
			invalidParameter(c, "limit")
			return nil, cases.ListFilter{}, false
		}
		filter.Limit = &limit
	}

	// One now anchors both bounds, so a relative range is never a second wide.
	now := time.Now()
	if query.Has("from") {
		filter.FromExpression = query.Get("from")
		from, err := cases.ParseTime(filter.FromExpression, now)
		if err != nil {
			invalidParameter(c, "from")
			return nil, cases.ListFilter{}, false
		}
		filter.From = &from
	}
	if query.Has("to") {
		filter.ToExpression = query.Get("to")
		to, err := cases.ParseTime(filter.ToExpression, now)
		if err != nil {
			invalidParameter(c, "to")
			return nil, cases.ListFilter{}, false
		}
		filter.To = &to
	}
	return query, filter, true
}

// csvParameter splits a comma list and rejects an empty item, so no filter
// value has to be guessed at.
func csvParameter(c *gin.Context, query url.Values, name string) ([]string, bool) {
	if !query.Has(name) {
		return nil, true
	}
	items := strings.Split(query.Get(name), ",")
	if slices.Contains(items, "") {
		invalidParameter(c, name)
		return nil, false
	}
	return items, true
}

// validateHistogramOptions accepts only the options the histogram implements.
func validateHistogramOptions(c *gin.Context, query url.Values) bool {
	if query.Has("interval") && query.Get("interval") != "auto" {
		invalidParameter(c, "interval")
		return false
	}
	if query.Has("splitBy") && query.Get("splitBy") != "severity" {
		invalidParameter(c, "splitBy")
		return false
	}
	return true
}

// parseAssigneeID tells an absent assigneeId from the literal null: only null
// clears the assignee.
func parseAssigneeID(c *gin.Context, raw json.RawMessage) (*string, bool) {
	if raw == nil {
		invalidParameter(c, "assigneeId")
		return nil, false
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return nil, true
	}
	var assigneeID string
	if err := json.Unmarshal(raw, &assigneeID); err != nil || !audit.ValidID(assigneeID) {
		invalidParameter(c, "assigneeId")
		return nil, false
	}
	return &assigneeID, true
}

func writeCaseError(c *gin.Context, logger *slog.Logger, err error) {
	var validation cases.ValidationError
	switch {
	case errors.As(err, &validation):
		writeError(c, http.StatusBadRequest, codeValidationError, "invalid "+validation.Parameter)
	case errors.Is(err, cases.ErrCaseNotFound):
		writeError(c, http.StatusNotFound, codeNotFound, "case not found")
	case errors.Is(err, cases.ErrVersionConflict):
		writeError(c, http.StatusConflict, codeVersionConflict, cases.ErrVersionConflict.Error())
	case errors.Is(err, cases.ErrCaseClosed):
		writeError(c, http.StatusConflict, codeStateConflict, cases.ErrCaseClosed.Error())
	default:
		internalError(c, logger, err)
	}
}

// emptyIfNil keeps a cursor list's data an empty array instead of null.
func emptyIfNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

// newCursorPagination reports the limit the service applied.
func newCursorPagination(limit int, nextCursor *string) cursorPagination {
	return cursorPagination{Limit: limit, NextCursor: nextCursor}
}
