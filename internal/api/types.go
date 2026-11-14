package api

import (
	"context"
	"io/fs"
	"log/slog"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"gorm.io/gorm"
)

const (
	defaultPageSize        = 50
	maxUserPageSize        = 100
	maxAuditPageSize       = 200
	maxDirectoryQueryRunes = 100
	maxDirectoryIDs        = 50
	maxDirectoryLimit      = 50
	maxRequestBodyBytes    = 4096

	codeVersionConflict = "VERSION_CONFLICT"
	codeStateConflict   = "STATE_CONFLICT"
)

// RequestIDKey is the Gin context key holding the request id, so handlers can
// copy it into audit events.
const RequestIDKey = "request_id"

// ActorKey is the Gin context key holding the authenticated actor.
const ActorKey = "actor"

// ReadinessChecker reports whether the database answers. *sql.DB satisfies
// it; tests pass a fake.
type ReadinessChecker interface {
	PingContext(ctx context.Context) error
}

// originPolicy decides which request origins may use a browser session.
type originPolicy struct {
	publicOrigin string // scheme://host[:port] with default ports removed; "" when unparsable
	development  bool
	secureCookie bool // public URL scheme is https
}

// Dependencies are the collaborators NewRouter needs.
type Dependencies struct {
	Database       ReadinessChecker // readiness probe only
	AuditDatabase  *gorm.DB         // full handle for the audit and role reads
	Logger         *slog.Logger
	Auth           *auth.Service
	Web            fs.FS
	TrustedProxies []string
	PublicURL      string
	Development    bool
	Version        string
	Commit         string
}

type statusResponse struct {
	Status string `json:"status"`
}

type readinessResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

type versionResponse struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// loginRequest keeps both fields as pointers, so a missing field is
// distinguishable from an empty string.
type loginRequest struct {
	Email    *string `json:"email"`
	Password *string `json:"password"`
}

type loginResponse struct {
	SessionToken string    `json:"sessionToken,omitempty"`
	ExpiresAt    string    `json:"expiresAt"`
	User         loginUser `json:"user"`
}

type loginUser struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Roles       []string `json:"roles"`
}

// changePasswordRequest keeps both fields as pointers, so a missing field is a
// 400 rather than an empty password.
type changePasswordRequest struct {
	CurrentPassword *string `json:"currentPassword"`
	NewPassword     *string `json:"newPassword"`
}

type sessionResponse struct {
	ID                string  `json:"id"`
	CreatedAt         string  `json:"createdAt"`
	LastUsedAt        string  `json:"lastUsedAt"`
	IdleExpiresAt     string  `json:"idleExpiresAt"`
	AbsoluteExpiresAt string  `json:"absoluteExpiresAt"`
	ClientIP          *string `json:"clientIp"`
	UserAgent         string  `json:"userAgent"`
	AuthProvider      string  `json:"authProvider"`
	Current           bool    `json:"current"`
}

type sessionListResponse struct {
	Data []sessionResponse `json:"data"`
}

type userResponse struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Status      string   `json:"status"`
	OnCall      bool     `json:"onCall"`
	Roles       []string `json:"roles"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
	Version     int      `json:"version"`
}

type providersResponse struct {
	Data []providerItem `json:"data"`
}

type providerItem struct {
	ID string `json:"id"`
}

// pagination is the list envelope every paginated route shares.
type pagination struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"pageSize"`
	TotalItems int64 `json:"totalItems"`
	TotalPages int   `json:"totalPages"`
}

type userListResponse struct {
	Data       []userResponse `json:"data"`
	Pagination pagination     `json:"pagination"`
}

// directoryEntryResponse is one person a picker can show: no email, roles, or
// on-call state.
type directoryEntryResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Status      string `json:"status"`
}

type directoryListResponse struct {
	Data []directoryEntryResponse `json:"data"`
}

type createUserRequest struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Roles       []string `json:"roles"`
}

// updateUserRequest keeps version a pointer so a missing field is a 400, not a
// silent zero.
type updateUserRequest struct {
	Email       *string `json:"email"`
	DisplayName *string `json:"displayName"`
	Version     *int    `json:"version"`
}

type versionRequest struct {
	Version *int `json:"version"`
}

// onCallRequest keeps OnCall a pointer, so a missing field is a 400.
type onCallRequest struct {
	OnCall *bool `json:"onCall"`
}

type assignRoleRequest struct {
	Role string `json:"role"`
}

type resetTokenResponse struct {
	ResetToken string `json:"resetToken"`
	ExpiresAt  string `json:"expiresAt"`
}

type useResetTokenRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type roleResponse struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type rolesResponse struct {
	Data []roleResponse `json:"data"`
}

type auditEventResponse struct {
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

type auditListResponse struct {
	Data       []auditEventResponse `json:"data"`
	Pagination pagination           `json:"pagination"`
}
