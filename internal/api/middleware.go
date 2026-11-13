package api

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	requestIDHeader = "X-Request-Id"
	requestIDBytes  = 16
	maxRequestID    = 64
	unmatchedRoute  = "unmatched"

	contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

	codeInternalError = "INTERNAL_ERROR"
)

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", contentSecurityPolicy)
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "same-origin")
		c.Next()
	}
}

func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		identifier := c.GetHeader(requestIDHeader)
		if !validRequestID(identifier) {
			identifier = newRequestID()
		}
		c.Header(requestIDHeader, identifier)
		c.Set(RequestIDKey, identifier)
		c.Next()
	}
}

// validRequestID accepts only the characters that are safe in a header and a
// log line, so an incoming value can never inject either.
func validRequestID(identifier string) bool {
	if len(identifier) < 1 || len(identifier) > maxRequestID {
		return false
	}
	for _, character := range identifier {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-', character == '_':
		default:
			return false
		}
	}
	return true
}

func newRequestID() string {
	identifier := make([]byte, requestIDBytes)
	// crypto/rand.Read never returns an error since Go 1.24.
	_, _ = rand.Read(identifier)
	return hex.EncodeToString(identifier)
}

func recovery(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			logger.Error("panic recovered",
				"request_id", c.GetString(RequestIDKey),
				"panic", recovered,
				"stack", string(debug.Stack()),
			)
			if c.Writer.Written() {
				c.Abort()
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, errorResponse{
				Error: errorDetail{Code: codeInternalError, Message: "internal server error"},
			})
		}()
		c.Next()
	}
}

func requestLog(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = c.GetString(routeLabelKey)
		}
		if route == "" {
			route = unmatchedRoute
		}
		logger.Info("request",
			"method", c.Request.Method,
			"route", route,
			"status", c.Writer.Status(),
			"duration", time.Since(started),
			"client_address", c.ClientIP(),
			"request_id", c.GetString(RequestIDKey),
		)
	}
}
