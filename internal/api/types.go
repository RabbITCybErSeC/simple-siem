package api

import (
	"context"
	"io/fs"
	"log/slog"
)

// RequestIDKey is the Gin context key holding the request id, so handlers can
// copy it into audit events.
const RequestIDKey = "request_id"

// ReadinessChecker reports whether the database answers. *sql.DB satisfies
// it; tests pass a fake.
type ReadinessChecker interface {
	PingContext(ctx context.Context) error
}

// Dependencies are the collaborators NewRouter needs.
type Dependencies struct {
	Database       ReadinessChecker
	Logger         *slog.Logger
	Web            fs.FS
	TrustedProxies []string
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
