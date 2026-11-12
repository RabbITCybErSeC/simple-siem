package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	requestIDHeader = "X-Request-Id"
	apiPathPrefix   = "/api/v1"
	unmatchedRoute  = "unmatched"

	requestIDBytes   = 16
	maxRequestID     = 64
	readinessTimeout = time.Second

	codeNotFound      = "NOT_FOUND"
	codeInternalError = "INTERNAL_ERROR"
)

// NewRouter builds the HTTP engine with request ids, panic recovery, request
// logging, health routes, and the API error format.
func NewRouter(dependencies Dependencies) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	if err := router.SetTrustedProxies(dependencies.TrustedProxies); err != nil {
		dependencies.Logger.Error("configure trusted proxies", "error", err)
		_ = router.SetTrustedProxies(nil)
	}

	router.Use(
		requestID(),
		requestLog(dependencies.Logger),
		recovery(dependencies.Logger),
	)
	router.GET("/healthz", healthz)
	router.GET("/readyz", readyz(dependencies.DB, dependencies.Logger))
	router.GET("/version", version(dependencies.Version, dependencies.Commit))
	router.NoRoute(noRoute)
	return router
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

func healthz(c *gin.Context) {
	c.JSON(http.StatusOK, statusResponse{Status: "ok"})
}

func readyz(db *gorm.DB, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		pingContext, cancel := context.WithTimeout(c.Request.Context(), readinessTimeout)
		defer cancel()

		sqlDatabase, err := db.DB()
		if err == nil {
			err = sqlDatabase.PingContext(pingContext)
		}
		if err != nil {
			logger.Warn("readiness check failed",
				"request_id", c.GetString(RequestIDKey),
				"error", err,
			)
			c.JSON(http.StatusServiceUnavailable, readinessResponse{
				Status: "unavailable",
				Checks: map[string]string{"database": "unreachable"},
			})
			return
		}
		c.JSON(http.StatusOK, readinessResponse{Status: "ready"})
	}
}

func version(version, commit string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, versionResponse{Version: version, Commit: commit})
	}
}

func noRoute(c *gin.Context) {
	requestPath := c.Request.URL.Path
	if requestPath == apiPathPrefix || strings.HasPrefix(requestPath, apiPathPrefix+"/") {
		c.JSON(http.StatusNotFound, errorResponse{
			Error: errorDetail{Code: codeNotFound, Message: "route not found"},
		})
		return
	}
	c.String(http.StatusNotFound, "not found")
}
