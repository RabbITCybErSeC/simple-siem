package api

import (
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

// accountHandler serves the signed-in user's own account routes.
type accountHandler struct {
	service *auth.Service
	logger  *slog.Logger
	policy  originPolicy
}

func (account accountHandler) changePassword(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var request changePasswordRequest
	if !decodeJSONBody(c, &request) {
		return
	}
	if request.CurrentPassword == nil || request.NewPassword == nil {
		writeError(c, http.StatusBadRequest, codeValidationError, "invalid request body")
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	_, err := account.service.ChangePassword(
		c.Request.Context(), actor, clientInfo(c), *request.CurrentPassword, *request.NewPassword,
	)
	if err == nil {
		c.Status(http.StatusNoContent)
		return
	}

	var rateLimited auth.RateLimitedError
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(c, http.StatusBadRequest, codeValidationError, "current password is incorrect")
	case errors.Is(err, auth.ErrPasswordLength):
		writeError(c, http.StatusBadRequest, codeValidationError, err.Error())
	case errors.As(err, &rateLimited):
		retryAfter := max(int(math.Ceil(rateLimited.RetryAfter.Seconds())), 1)
		c.Header("Retry-After", strconv.Itoa(retryAfter))
		writeError(c, http.StatusTooManyRequests, codeRateLimited, "too many failed logins")
	default:
		internalError(c, account.logger, err)
	}
}

func (account accountHandler) listSessions(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	actor := c.MustGet(ActorKey).(auth.Actor)
	sessions, err := account.service.ListSessions(c.Request.Context(), actor)
	if err != nil {
		internalError(c, account.logger, err)
		return
	}

	data := make([]sessionResponse, 0, len(sessions))
	for _, session := range sessions {
		item := sessionResponse{
			ID:                session.ID,
			CreatedAt:         session.CreatedAt.UTC().Format(time.RFC3339),
			LastUsedAt:        session.LastUsedAt.UTC().Format(time.RFC3339),
			IdleExpiresAt:     session.IdleExpiresAt.UTC().Format(time.RFC3339),
			AbsoluteExpiresAt: session.AbsoluteExpiresAt.UTC().Format(time.RFC3339),
			UserAgent:         session.UserAgent,
			AuthProvider:      session.AuthProvider,
			Current:           session.Current,
		}
		if session.ClientIP != nil {
			clientIP := session.ClientIP.String()
			item.ClientIP = &clientIP
		}
		data = append(data, item)
	}
	c.JSON(http.StatusOK, sessionListResponse{Data: data})
}

func (account accountHandler) revokeSession(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	sessionID, ok := pathUUID(c, "sessionId", "session not found")
	if !ok {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	err := account.service.RevokeSession(c.Request.Context(), actor, clientInfo(c), sessionID)
	if err != nil {
		if errors.Is(err, auth.ErrSessionNotFound) {
			writeError(c, http.StatusNotFound, codeNotFound, "session not found")
			return
		}
		internalError(c, account.logger, err)
		return
	}
	if sessionID == actor.SessionID && c.GetString(credentialKey) == credentialCookie {
		clearSessionCookie(c, account.policy)
	}
	c.Status(http.StatusNoContent)
}
