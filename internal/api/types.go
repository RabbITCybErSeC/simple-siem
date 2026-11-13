package api

import (
	"io/fs"
	"log/slog"

	"gorm.io/gorm"
)

// RequestIDKey is the Gin context key holding the request id, so handlers can
// copy it into audit events.
const RequestIDKey = "request_id"

// Dependencies are the collaborators NewRouter needs.
type Dependencies struct {
	DB             *gorm.DB
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
