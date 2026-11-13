package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const readinessTimeout = time.Second

var errNoReadinessChecker = errors.New("no readiness checker")

type healthHandler struct {
	database     ReadinessChecker
	logger       *slog.Logger
	buildVersion string
	buildCommit  string
}

func (health healthHandler) healthz(c *gin.Context) {
	c.JSON(http.StatusOK, statusResponse{Status: "ok"})
}

func (health healthHandler) readyz(c *gin.Context) {
	pingContext, cancel := context.WithTimeout(c.Request.Context(), readinessTimeout)
	defer cancel()

	err := errNoReadinessChecker
	if health.database != nil {
		err = health.database.PingContext(pingContext)
	}
	if err != nil {
		health.logger.Warn("readiness check failed",
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

func (health healthHandler) version(c *gin.Context) {
	c.JSON(http.StatusOK, versionResponse{Version: health.buildVersion, Commit: health.buildCommit})
}
