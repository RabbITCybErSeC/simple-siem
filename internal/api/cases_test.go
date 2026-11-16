package api_test

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/RabbITCybErSeC/simple-siem/internal/cases"
	"gorm.io/gorm"
)

const (
	caseAnalystEmail    = "case-analyst@example.com"
	caseAnalystPassword = "case analyst horse battery"
	readOnlyEmail       = "read-only@example.com"
	readOnlyPassword    = "read only horse battery"
)

// caseSeed describes one cases row an API test inserts.
type caseSeed struct {
	Title      string
	Status     string
	AssigneeID *string
	Version    int
}

// caseState is the part of a cases row an assign test reads back.
type caseState struct {
	Status     string  `gorm:"column:status"`
	AssigneeID *string `gorm:"column:assignee_user_id"`
	Version    int     `gorm:"column:version"`
}

func TestCaseRoutes(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	admin, _ := apiAdmin(t, router, service)
	analystID, analystToken := caseAnalystLogin(t, router, service, admin)
	reader := apiCreateUser(t, service, admin, readOnlyEmail, "Read Only", "READ_ONLY")
	apiActivateUser(t, service, admin, reader.User.ID, readOnlyPassword)
	readerToken := loginTokenFor(t, router, readOnlyEmail, readOnlyPassword)

	readCaseID, readCaseNumber := insertCaseRow(t, database, caseSeed{Title: "Queue"})
	assignCaseID, _ := insertCaseRow(t, database, caseSeed{Title: "Assign"})
	routes := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{"list", http.MethodGet, "/api/v1/cases", ""},
		{"list with zero offset", http.MethodGet, "/api/v1/cases?from=2026-11-15T08:30:00%2B00:00", ""},
		{"counts", http.MethodGet, "/api/v1/cases/counts", ""},
		{"histogram", http.MethodGet, "/api/v1/cases/histogram?from=now-24h&to=now", ""},
		{"detail by id", http.MethodGet, "/api/v1/cases/" + readCaseID, ""},
		{"detail by number", http.MethodGet, fmt.Sprintf("/api/v1/cases/%d", readCaseNumber), ""},
		{"alerts", http.MethodGet, "/api/v1/cases/" + readCaseID + "/alerts", ""},
		{"timeline", http.MethodGet, "/api/v1/cases/" + readCaseID + "/timeline", ""},
		{"assign", http.MethodPatch, "/api/v1/cases/" + assignCaseID,
			`{"assigneeId":"` + analystID + `","version":1}`},
	}

	t.Run("analyst", func(t *testing.T) {
		for _, route := range routes {
			t.Run(route.name, func(t *testing.T) {
				response := caseRequest(router, route.method, route.target, route.body, analystToken)
				if response.Code != http.StatusOK {
					t.Fatalf("%s %s = %d, want 200: %s",
						route.method, route.target, response.Code, response.Body)
				}
				assertNoStore(t, response)
			})
		}
	})

	t.Run("authentication required", func(t *testing.T) {
		for _, route := range routes {
			t.Run(route.name, func(t *testing.T) {
				response := caseRequest(router, route.method, route.target, route.body, "")
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("%s %s = %d, want 401: %s",
						route.method, route.target, response.Code, response.Body)
				}
			})
		}
	})

	t.Run("read only cannot assign", func(t *testing.T) {
		response := get(router, "/api/v1/cases", "", bearer(readerToken))
		if response.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/cases = %d, want 200: %s", response.Code, response.Body)
		}
		assertNoStore(t, response)

		caseID, _ := insertCaseRow(t, database, caseSeed{Title: "Read only"})
		response = caseRequest(router, http.MethodPatch, "/api/v1/cases/"+caseID,
			`{"assigneeId":null,"version":1}`, readerToken)
		if response.Code != http.StatusForbidden {
			t.Fatalf("read-only PATCH = %d, want 403: %s", response.Code, response.Body)
		}
		assertErrorCode(t, response, "FORBIDDEN", "permission denied")
	})

	t.Run("counts is not a case lookup", func(t *testing.T) {
		insertCaseRow(t, database, caseSeed{Title: "Counts are not a case"})
		response := get(router, "/api/v1/cases/counts", "", bearer(analystToken))
		if response.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/cases/counts = %d, want 200: %s", response.Code, response.Body)
		}
		var counts map[string]any
		decodeJSON(t, response, &counts)
		assertJSONKeys(t, counts, []string{"cap", "scope", "status"})
		if counts["cap"] != float64(cases.CountsCap) {
			t.Errorf("cap = %v, want %d", counts["cap"], cases.CountsCap)
		}

		response = get(router, "/api/v1/cases/counts?status=OPEN", "", bearer(analystToken))
		if response.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/cases/counts?status=OPEN = %d, want 200: %s", response.Code, response.Body)
		}
		var tabCounts cases.Counts
		decodeJSON(t, response, &tabCounts)
		if tabCounts.Scope.All != tabCounts.Status.Open {
			t.Errorf("open tab scope all = %d, want the OPEN count %d",
				tabCounts.Scope.All, tabCounts.Status.Open)
		}
	})

	t.Run("pagination reports the applied limit", func(t *testing.T) {
		targets := []string{
			"/api/v1/cases?limit=2",
			"/api/v1/cases/" + readCaseID + "/alerts?limit=2",
			"/api/v1/cases/" + readCaseID + "/timeline?limit=2",
		}
		for _, target := range targets {
			response := get(router, target, "", bearer(analystToken))
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200: %s", target, response.Code, response.Body)
			}
			var body struct {
				Pagination struct {
					Limit int `json:"limit"`
				} `json:"pagination"`
			}
			decodeJSON(t, response, &body)
			if body.Pagination.Limit != 2 {
				t.Errorf("GET %s pagination limit = %d, want 2", target, body.Pagination.Limit)
			}
		}

		response := get(router, "/api/v1/cases", "", bearer(analystToken))
		var body struct {
			Pagination struct {
				Limit int `json:"limit"`
			} `json:"pagination"`
		}
		decodeJSON(t, response, &body)
		if body.Pagination.Limit != cases.DefaultListLimit {
			t.Errorf("default pagination limit = %d, want %d",
				body.Pagination.Limit, cases.DefaultListLimit)
		}
	})

	t.Run("detail by number and unknown references", func(t *testing.T) {
		caseID, caseNumber := insertCaseRow(t, database, caseSeed{Title: "By number"})

		response := get(router, fmt.Sprintf("/api/v1/cases/%d", caseNumber), "", bearer(analystToken))
		if response.Code != http.StatusOK {
			t.Fatalf("GET /api/v1/cases/%d = %d, want 200: %s", caseNumber, response.Code, response.Body)
		}
		var detail cases.CaseDetail
		decodeJSON(t, response, &detail)
		if detail.ID != caseID {
			t.Errorf("detail id = %q, want %q", detail.ID, caseID)
		}

		for _, reference := range []string{newTestUUID(), "abc"} {
			response = get(router, "/api/v1/cases/"+reference, "", bearer(analystToken))
			if response.Code != http.StatusNotFound {
				t.Errorf("GET /api/v1/cases/%s = %d, want 404: %s", reference, response.Code, response.Body)
				continue
			}
			assertErrorCode(t, response, "NOT_FOUND", "case not found")
		}
	})

	t.Run("query validation", func(t *testing.T) {
		caseID, _ := insertCaseRow(t, database, caseSeed{Title: "Validation"})
		cursor := strings.Repeat("a", cases.MaxCursorBytes+1)

		tests := []struct {
			name      string
			target    string
			parameter string
		}{
			{"unknown list parameter", "/api/v1/cases?bogus=1", "bogus"},
			{"repeated list parameter", "/api/v1/cases?status=OPEN&status=CLOSED", "status"},
			{"empty comma item", "/api/v1/cases?status=OPEN,", "status"},
			{"invalid status", "/api/v1/cases?status=BOGUS", "status"},
			{"too many status values", "/api/v1/cases?status=" + strings.Repeat("OPEN,", cases.MaxFilterValues) + "OPEN", "status"},
			{"invalid scope", "/api/v1/cases?scope=everyone", "scope"},
			{"invalid time field", "/api/v1/cases?timeField=bogus", "timeField"},
			{"invalid sort", "/api/v1/cases?sort=title:asc", "sort"},
			{"tag filter", "/api/v1/cases?tag=phishing", "tag"},
			{"oversized cursor", "/api/v1/cases?cursor=" + cursor, "cursor"},
			{"non-numeric limit", "/api/v1/cases?limit=ten", "limit"},
			{"zero limit", "/api/v1/cases?limit=0", "limit"},
			{"zero alerts limit", "/api/v1/cases/" + caseID + "/alerts?limit=0", "limit"},
			{"zero timeline limit", "/api/v1/cases/" + caseID + "/timeline?limit=0", "limit"},
			{"repeated query", "/api/v1/cases?q=a&q=b", "q"},
			{"NUL query", "/api/v1/cases?q=%00", "q"},
			{"invalid UTF-8 query", "/api/v1/cases?q=%FF", "q"},
			{"unknown counts parameter", "/api/v1/cases/counts?limit=10", "limit"},
			{"repeated counts status", "/api/v1/cases/counts?status=OPEN&status=CLOSED", "status"},
			{"invalid counts status", "/api/v1/cases/counts?status=BOGUS", "status"},
			{"unknown histogram parameter", "/api/v1/cases/histogram?cursor=x", "cursor"},
			{"invalid histogram interval", "/api/v1/cases/histogram?interval=1h", "interval"},
			{"invalid histogram split", "/api/v1/cases/histogram?splitBy=status", "splitBy"},
			{"invalid histogram from", "/api/v1/cases/histogram?from=yesterday&to=now", "from"},
			{"histogram without from", "/api/v1/cases/histogram", "from"},
			{"unknown alerts parameter", "/api/v1/cases/" + caseID + "/alerts?kind=EVIDENCE", "kind"},
			{"unknown timeline parameter", "/api/v1/cases/" + caseID + "/timeline?sort=x", "sort"},
			{"invalid timeline kind", "/api/v1/cases/" + caseID + "/timeline?kind=NOTE", "kind"},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				response := get(router, test.target, "", bearer(analystToken))
				if response.Code != http.StatusBadRequest {
					t.Fatalf("GET %s = %d, want 400: %s", test.target, response.Code, response.Body)
				}
				assertErrorCode(t, response, "VALIDATION_ERROR", test.parameter)
				assertNoStore(t, response)
			})
		}
	})

	t.Run("assign", func(t *testing.T) {
		t.Run("missing assignee", func(t *testing.T) {
			caseID, _ := insertCaseRow(t, database, caseSeed{Title: "Missing assignee"})
			response := caseRequest(router, http.MethodPatch, "/api/v1/cases/"+caseID, `{"version":1}`, analystToken)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("PATCH = %d, want 400: %s", response.Code, response.Body)
			}
			assertErrorCode(t, response, "VALIDATION_ERROR", "assigneeId")
			assertNoStore(t, response)
			if state := loadCaseState(t, database, caseID); state.Status != cases.StatusOpen ||
				state.AssigneeID != nil || state.Version != 1 {
				t.Errorf("case changed on a rejected assign: %+v", state)
			}
		})

		t.Run("null clears the assignee", func(t *testing.T) {
			caseID, _ := insertCaseRow(t, database, caseSeed{
				Title: "Unassign", Status: cases.StatusInProgress, AssigneeID: &analystID,
			})
			response := caseRequest(router, http.MethodPatch, "/api/v1/cases/"+caseID,
				`{"assigneeId":null,"version":1}`, analystToken)
			if response.Code != http.StatusOK {
				t.Fatalf("PATCH = %d, want 200: %s", response.Code, response.Body)
			}
			var detail cases.CaseDetail
			decodeJSON(t, response, &detail)
			if detail.Assignee != nil {
				t.Errorf("assignee = %+v, want none", detail.Assignee)
			}
			if detail.Status != cases.StatusInProgress {
				t.Errorf("status = %q, want %q", detail.Status, cases.StatusInProgress)
			}
			if detail.Version != 2 {
				t.Errorf("version = %d, want 2", detail.Version)
			}
		})

		t.Run("assign moves an open case", func(t *testing.T) {
			caseID, _ := insertCaseRow(t, database, caseSeed{Title: "Assign"})
			response := caseRequest(router, http.MethodPatch, "/api/v1/cases/"+caseID,
				`{"assigneeId":"`+analystID+`","version":1}`, analystToken)
			if response.Code != http.StatusOK {
				t.Fatalf("PATCH = %d, want 200: %s", response.Code, response.Body)
			}
			var detail cases.CaseDetail
			decodeJSON(t, response, &detail)
			if detail.Assignee == nil || detail.Assignee.ID != analystID {
				t.Errorf("assignee = %+v, want %q", detail.Assignee, analystID)
			}
			if detail.Status != cases.StatusInProgress || detail.Version != 2 {
				t.Errorf("assigned case = %s version %d, want IN_PROGRESS version 2",
					detail.Status, detail.Version)
			}
		})

		disabled := apiCreateUser(t, service, admin, "disabled@example.com", "Disabled", "READ_ONLY")
		apiActivateUser(t, service, admin, disabled.User.ID, "disabled horse battery")
		if err := database.Exec("UPDATE users SET status = 'DISABLED' WHERE id = ?", disabled.User.ID).Error; err != nil {
			t.Fatalf("disable user: %v", err)
		}

		failures := []struct {
			name      string
			seed      caseSeed
			body      string
			status    int
			errorCode string
		}{
			{"stale version", caseSeed{Title: "Stale", Version: 3},
				`{"assigneeId":"` + analystID + `","version":2}`, http.StatusConflict, "VERSION_CONFLICT"},
			{"closed case", caseSeed{Title: "Closed", Status: cases.StatusClosed},
				`{"assigneeId":"` + analystID + `","version":1}`, http.StatusConflict, "STATE_CONFLICT"},
			{"disabled assignee", caseSeed{Title: "Disabled assignee"},
				`{"assigneeId":"` + disabled.User.ID + `","version":1}`, http.StatusBadRequest, "VALIDATION_ERROR"},
			{"non-uuid assignee", caseSeed{Title: "Bad assignee"},
				`{"assigneeId":42,"version":1}`, http.StatusBadRequest, "VALIDATION_ERROR"},
		}
		for _, test := range failures {
			t.Run(test.name, func(t *testing.T) {
				caseID, _ := insertCaseRow(t, database, test.seed)
				response := caseRequest(router, http.MethodPatch, "/api/v1/cases/"+caseID, test.body, analystToken)
				if response.Code != test.status {
					t.Fatalf("PATCH = %d, want %d: %s", response.Code, test.status, response.Body)
				}
				assertErrorCode(t, response, test.errorCode, "")
			})
		}
	})

	t.Run("response shapes", func(t *testing.T) {
		caseID, _ := insertCaseRow(t, database, caseSeed{Title: "Shape"})
		alertID := insertCaseAlert(t, database, caseID)
		insertCaseEvidence(t, database, alertID)
		insertCaseActivity(t, database, caseID, analystID)
		insertCaseCreatedActivity(t, database, caseID)

		t.Run("list item", func(t *testing.T) {
			item := caseDataItem(t, get(router, "/api/v1/cases?q=Shape", "", bearer(analystToken)))
			assertJSONKeys(t, item, []string{
				"assignee", "caseNumber", "closedAt", "closureReason", "createdAt",
				"firstEventAt", "id", "lastEventAt", "outcome", "severity", "status",
				"title", "version",
			})
		})

		t.Run("detail", func(t *testing.T) {
			response := get(router, "/api/v1/cases/"+caseID, "", bearer(analystToken))
			if response.Code != http.StatusOK {
				t.Fatalf("GET detail = %d, want 200: %s", response.Code, response.Body)
			}
			var detail map[string]any
			decodeJSON(t, response, &detail)
			assertJSONKeys(t, detail, []string{
				"alertCount", "assignee", "caseNumber", "closedAt", "closedBy",
				"closureReason", "conclusion", "createdAt", "firstEventAt", "id",
				"lastActivityAt", "lastEventAt", "linkedCases", "mergedInto", "outcome",
				"severity", "status", "title", "version",
			})
		})

		t.Run("alert", func(t *testing.T) {
			item := caseDataItem(t, get(router, "/api/v1/cases/"+caseID+"/alerts", "", bearer(analystToken)))
			assertJSONKeys(t, item, []string{
				"closureReason", "detectionId", "detectionVersion", "evidenceCount",
				"firstEventAt", "id", "lastEventAt", "occurrenceCount", "outcome",
				"severity", "status", "title",
			})
		})

		t.Run("evidence entry", func(t *testing.T) {
			item := caseDataItem(t, get(router,
				"/api/v1/cases/"+caseID+"/timeline?kind=EVIDENCE", "", bearer(analystToken)))
			assertJSONKeys(t, item, []string{"alertId", "at", "id", "kind", "sourceId", "udm"})
			if item["udm"] != nil {
				t.Errorf("udm = %v, want null for evidence without a cached event", item["udm"])
			}
		})

		t.Run("activity entry", func(t *testing.T) {
			items := caseDataItems(t, get(router,
				"/api/v1/cases/"+caseID+"/timeline?kind=ACTIVITY", "", bearer(analystToken)))
			var created, assigned map[string]any
			for _, item := range items {
				switch item["action"] {
				case "CASE_CREATED":
					created = item
				case "ASSIGNED":
					assigned = item
				}
			}
			if created == nil || assigned == nil {
				t.Fatalf("activity entries = %v, want CASE_CREATED and ASSIGNED", items)
			}
			assertJSONKeys(t, created, []string{"action", "actor", "at", "details", "id", "kind"})
			details, ok := created["details"].(map[string]any)
			if !ok || len(details) != 0 {
				t.Errorf("CASE_CREATED details = %v, want {}", created["details"])
			}
			assertJSONKeys(t, assigned, []string{"action", "actor", "at", "details", "id", "kind"})
		})
	})
}

func TestCaseListRelativeRangePaginates(t *testing.T) {
	router, service, database, _ := newAPIRouter(t)
	admin, _ := apiAdmin(t, router, service)
	_, token := caseAnalystLogin(t, router, service, admin)

	titles := []string{"Relative one", "Relative two", "Relative three"}
	for _, title := range titles {
		caseID, _ := insertCaseRow(t, database, caseSeed{Title: title, Status: cases.StatusClosed})
		// Keep the rows an hour inside the range, so request-time clock
		// differences cannot move them out of it.
		if err := database.Exec(`
			UPDATE cases
			SET first_event_at = now() - interval '2 hours',
			    last_event_at = now() - interval '1 hour',
			    closed_at = now() - interval '1 hour'
			WHERE id = ?`, caseID).Error; err != nil {
			t.Fatalf("move case %q into the range: %v", title, err)
		}
	}

	target := "/api/v1/cases?status=CLOSED&from=now-24h&to=now&limit=1"
	seen := make(map[string]bool)
	for page := 1; page <= len(titles)+1; page++ {
		response := get(router, target, "", bearer(token))
		if response.Code != http.StatusOK {
			t.Fatalf("page %d = %d, want 200: %s", page, response.Code, response.Body)
		}
		var body struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Pagination struct {
				NextCursor *string `json:"nextCursor"`
			} `json:"pagination"`
		}
		decodeJSON(t, response, &body)
		for _, item := range body.Data {
			seen[item.ID] = true
		}
		if body.Pagination.NextCursor == nil {
			break
		}
		if page == len(titles)+1 {
			t.Fatalf("pagination did not finish after %d pages", page)
		}
		target = "/api/v1/cases?status=CLOSED&from=now-24h&to=now&limit=1&cursor=" +
			url.QueryEscape(*body.Pagination.NextCursor)
	}

	if len(seen) != len(titles) {
		t.Errorf("paged through %d cases, want %d", len(seen), len(titles))
	}
}

// caseAnalystLogin creates, activates, and signs in the analyst the case route
// tests share, returning the analyst id and session token.
func caseAnalystLogin(t *testing.T, router http.Handler, service *auth.Service, admin auth.Actor) (string, string) {
	t.Helper()
	analyst := apiCreateUser(t, service, admin, caseAnalystEmail, "Case Analyst", "ANALYST")
	apiActivateUser(t, service, admin, analyst.User.ID, caseAnalystPassword)
	return analyst.User.ID, loginTokenFor(t, router, caseAnalystEmail, caseAnalystPassword)
}

func caseRequest(router http.Handler, method, target, body, token string) *httptest.ResponseRecorder {
	headers := map[string]string{}
	if token != "" {
		headers = bearer(token)
	}
	return sendJSONWithHeaders(router, method, target, headers, body)
}

func insertCaseRow(t *testing.T, db *gorm.DB, seed caseSeed) (string, int64) {
	t.Helper()
	if seed.Title == "" {
		seed.Title = "Test case"
	}
	if seed.Status == "" {
		seed.Status = cases.StatusOpen
	}
	version := seed.Version
	if version == 0 {
		version = 1
	}
	var inserted struct {
		ID         string `gorm:"column:id"`
		CaseNumber int64  `gorm:"column:case_number"`
	}
	err := db.Raw(`
		INSERT INTO cases (title, status, severity, detection_id, assignee_user_id,
		                   first_event_at, last_event_at, version, closed_at)
		VALUES (?, ?, 'HIGH', 'brute-force', ?, now() - interval '10 minutes', now(), ?,
		        CASE WHEN ? = 'CLOSED' THEN now() ELSE NULL END)
		RETURNING id::text AS id, case_number`,
		seed.Title, seed.Status, seed.AssigneeID, version, seed.Status).Scan(&inserted).Error
	if err != nil {
		t.Fatalf("insert case %q: %v", seed.Title, err)
	}
	return inserted.ID, inserted.CaseNumber
}

func insertCaseAlert(t *testing.T, db *gorm.DB, caseID string) string {
	t.Helper()
	var alertID string
	err := db.Raw(`
		INSERT INTO alerts (detection_id, detection_version, identity_hash, identity_schema_version,
		                    identity, subject, summary, severity, status, first_event_at,
		                    last_event_at, evidence_count, occurrence_count)
		VALUES ('brute-force', '1.0.0', gen_random_uuid()::text, 1, '{}'::jsonb, '{}'::jsonb,
		        'Brute force', 'HIGH', 'OPEN', now() - interval '10 minutes', now(), 1, 1)
		RETURNING id::text AS id`).Scan(&alertID).Error
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	err = db.Exec("INSERT INTO case_alerts (case_id, alert_id) VALUES (?, ?)", caseID, alertID).Error
	if err != nil {
		t.Fatalf("link alert to case: %v", err)
	}
	return alertID
}

func insertCaseEvidence(t *testing.T, db *gorm.DB, alertID string) {
	t.Helper()
	hash := sha256.Sum256([]byte("doc-1"))
	err := db.Exec(`
		INSERT INTO alert_evidence (alert_id, source_key_hash, fetcher_instance_id,
		                            source_index, document_id, event_time)
		VALUES (?, ?, 'fetcher-1', 'auth', 'doc-1', now() - interval '1 hour')`,
		alertID, hash[:]).Error
	if err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
}

func insertCaseActivity(t *testing.T, db *gorm.DB, caseID, actorID string) {
	t.Helper()
	changes := fmt.Sprintf(`{"assigneeId":%q}`, actorID)
	err := db.Exec(`
		INSERT INTO audit_events (event_name, event_category, event_outcome, actor_type,
		                          actor_id, target_type, target_id, action, changes)
		VALUES ('simple_siem.case.assigned', 'CASE', 'SUCCESS', 'USER', ?, 'CASE', ?, 'assign', ?::jsonb)`,
		actorID, caseID, changes).Error
	if err != nil {
		t.Fatalf("insert case audit event: %v", err)
	}
}

func insertCaseCreatedActivity(t *testing.T, db *gorm.DB, caseID string) {
	t.Helper()
	err := db.Exec(`
		INSERT INTO audit_events (event_name, event_category, event_outcome, actor_type,
		                          target_type, target_id, action, changes)
		VALUES ('simple_siem.case.created', 'CASE', 'SUCCESS', 'SYSTEM', 'CASE', ?, 'create', '{}'::jsonb)`,
		caseID).Error
	if err != nil {
		t.Fatalf("insert case.created audit event: %v", err)
	}
}

func loadCaseState(t *testing.T, db *gorm.DB, caseID string) caseState {
	t.Helper()
	var state caseState
	err := db.Raw(`
		SELECT status, assignee_user_id::text AS assignee_user_id, version
		FROM cases WHERE id = ?`, caseID).Scan(&state).Error
	if err != nil {
		t.Fatalf("load case %q: %v", caseID, err)
	}
	return state
}

func caseDataItem(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	items := caseDataItems(t, response)
	if len(items) != 1 {
		t.Fatalf("data has %d items, want 1: %s", len(items), response.Body)
	}
	return items[0]
}

func caseDataItems(t *testing.T, response *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200: %s", response.Code, response.Body)
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	decodeJSON(t, response, &body)
	return body.Data
}

func assertJSONKeys(t *testing.T, value map[string]any, want []string) {
	t.Helper()
	got := make([]string, 0, len(value))
	for key := range value {
		got = append(got, key)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("JSON keys = %v, want %v", got, want)
	}
}
