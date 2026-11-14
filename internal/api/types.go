package api

import (
	"context"
	"io/fs"
	"log/slog"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
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
	Database       ReadinessChecker
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
	SessionToken string    `json:"sessionToken"`
	ExpiresAt    string    `json:"expiresAt"`
	User         loginUser `json:"user"`
}

type browserLoginResponse struct {
	ExpiresAt string    `json:"expiresAt"`
	User      loginUser `json:"user"`
}

type loginUser struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Roles       []string `json:"roles"`
}

type userResponse struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName"`
	Status      string   `json:"status"`
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
