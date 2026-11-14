package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/RabbITCybErSeC/simple-siem/internal/database/databasetest"
	"github.com/gin-gonic/gin"
)

const (
	rbacTestAdminPassword   = "correct horse battery"
	rbacTestAnalystPassword = "analyst horse battery"
)

type denialEvent struct {
	EventName      string  `gorm:"column:event_name"`
	EventCategory  string  `gorm:"column:event_category"`
	EventOutcome   string  `gorm:"column:event_outcome"`
	ActorType      string  `gorm:"column:actor_type"`
	ActorID        *string `gorm:"column:actor_id"`
	ActorSessionID *string `gorm:"column:actor_session_id"`
	TargetType     string  `gorm:"column:target_type"`
	TargetID       string  `gorm:"column:target_id"`
	Action         string  `gorm:"column:action"`
	Changes        []byte  `gorm:"column:changes"`
}

func TestRequirePermission(t *testing.T) {
	database := databasetest.New(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	service, err := auth.NewService(
		context.Background(),
		database,
		auth.Settings{IdleTimeout: 30 * time.Minute, AbsoluteLifetime: 12 * time.Hour},
		logger,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	router := gin.New()
	router.GET("/probe",
		requireSession(service, logger, originPolicy{}),
		requirePermission(service, logger, "user:read"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	client := auth.ClientInfo{IP: net.ParseIP("192.0.2.7"), UserAgent: "test-agent", RequestID: "request-1"}
	admin, err := service.CreateAdmin(context.Background(), "admin@example.com", "Admin User", rbacTestAdminPassword)
	if err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	adminToken := rbacLogin(t, service, client, admin.Email, rbacTestAdminPassword)
	adminActor, err := service.Authenticate(context.Background(), adminToken)
	if err != nil {
		t.Fatalf("Authenticate admin: %v", err)
	}

	analyst, err := service.CreateUser(
		context.Background(),
		adminActor,
		client,
		auth.CreateUserRequest{Email: "analyst@example.com", DisplayName: "Analyst", Roles: []string{"ANALYST"}},
	)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	resetToken, _, err := service.CreateResetToken(context.Background(), adminActor, client, analyst.User.ID)
	if err != nil {
		t.Fatalf("CreateResetToken: %v", err)
	}
	if err := service.UseResetToken(context.Background(), resetToken, rbacTestAnalystPassword, client); err != nil {
		t.Fatalf("UseResetToken: %v", err)
	}
	analystToken := rbacLogin(t, service, client, analyst.User.Email, rbacTestAnalystPassword)
	analystActor, err := service.Authenticate(context.Background(), analystToken)
	if err != nil {
		t.Fatalf("Authenticate analyst: %v", err)
	}

	response := rbacProbe(router, analystToken)
	if response.Code != http.StatusForbidden {
		t.Fatalf("analyst GET /probe = %d, want 403: %s", response.Code, response.Body)
	}
	if want := `{"error":{"code":"FORBIDDEN","message":"permission denied"}}`; response.Body.String() != want {
		t.Errorf("analyst body = %s, want %s", response.Body, want)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("analyst Cache-Control = %q, want no-store", got)
	}

	var events []denialEvent
	err = database.Raw(`
		SELECT event_name, event_category, event_outcome, actor_type, actor_id::text AS actor_id,
		       actor_session_id::text AS actor_session_id, target_type, target_id, action, changes
		FROM audit_events
		WHERE target_id = '/probe'`).Scan(&events).Error
	if err != nil {
		t.Fatalf("read denial audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("permission denial wrote %d audit events, want 1", len(events))
	}
	event := events[0]
	if event.EventName != "simple_siem.auth.permission_denied" || event.EventCategory != "AUTHORIZATION" ||
		event.EventOutcome != "DENIED" {
		t.Errorf("denial audit = %q/%q/%q, want simple_siem.auth.permission_denied/AUTHORIZATION/DENIED",
			event.EventName, event.EventCategory, event.EventOutcome)
	}
	if event.ActorType != "USER" || event.ActorID == nil || *event.ActorID != analyst.User.ID {
		t.Errorf("denial audit actor = %s/%v, want USER/%q", event.ActorType, event.ActorID, analyst.User.ID)
	}
	if event.ActorSessionID == nil || *event.ActorSessionID != analystActor.SessionID {
		t.Errorf("denial audit actor session id = %v, want %q", event.ActorSessionID, analystActor.SessionID)
	}
	if event.TargetType != "ROUTE" || event.TargetID != "/probe" || event.Action != http.MethodGet {
		t.Errorf("denial audit target = %q/%q action %q, want ROUTE//probe GET",
			event.TargetType, event.TargetID, event.Action)
	}
	var changes map[string]any
	if err := json.Unmarshal(event.Changes, &changes); err != nil {
		t.Fatalf("decode denial changes %q: %v", event.Changes, err)
	}
	required, ok := changes["required"].([]any)
	if !ok || len(required) != 1 || required[0] != "user:read" {
		t.Errorf("denial audit required = %v, want [user:read]", changes["required"])
	}

	response = rbacProbe(router, adminToken)
	if response.Code != http.StatusOK {
		t.Fatalf("admin GET /probe = %d, want 200: %s", response.Code, response.Body)
	}

	var count int64
	err = database.Raw("SELECT count(*) FROM audit_events WHERE target_id = '/probe'").Scan(&count).Error
	if err != nil {
		t.Fatalf("count denial audit events: %v", err)
	}
	if count != 1 {
		t.Errorf("allowed request wrote an audit event; count = %d, want 1", count)
	}

	// A client that disconnects cancels the request context. The denial must
	// still be audited, so the middleware writes it on a context that survives
	// the cancellation.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	canceledRouter := gin.New()
	canceledRouter.GET("/probe-canceled",
		func(c *gin.Context) {
			c.Set(ActorKey, analystActor)
			c.Next()
		},
		requirePermission(service, logger, "user:read"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)
	request := httptest.NewRequest(http.MethodGet, "/probe-canceled", nil).WithContext(canceled)
	response = httptest.NewRecorder()
	canceledRouter.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("canceled GET /probe-canceled = %d, want 403: %s", response.Code, response.Body)
	}
	err = database.Raw(
		"SELECT count(*) FROM audit_events WHERE target_id = '/probe-canceled'",
	).Scan(&count).Error
	if err != nil {
		t.Fatalf("count canceled denial audit events: %v", err)
	}
	if count != 1 {
		t.Errorf("canceled denial wrote %d audit events, want 1", count)
	}
}

func rbacLogin(t *testing.T, service *auth.Service, client auth.ClientInfo, email, password string) string {
	t.Helper()
	result, err := service.Login(
		context.Background(),
		auth.LoginRequest{Email: email, Password: password},
		client,
	)
	if err != nil {
		t.Fatalf("Login(%q): %v", email, err)
	}
	return result.Token
}

func rbacProbe(router http.Handler, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/probe", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}
