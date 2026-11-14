package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

const (
	maxLoginBodyBytes = 4096

	codeAuthenticationRequired = "AUTHENTICATION_REQUIRED"
	codeValidationError        = "VALIDATION_ERROR"
	codeRateLimited            = "RATE_LIMITED"
)

type authHandler struct {
	service *auth.Service
	logger  *slog.Logger
}

// requireSession accepts only a bearer token for a live session of an active
// user and puts the actor on the context for the handlers in its group.
func requireSession(service *auth.Service, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme, token, found := strings.Cut(c.GetHeader("Authorization"), " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.Contains(token, " ") {
			abortAuthenticationRequired(c)
			return
		}

		actor, err := service.Authenticate(c.Request.Context(), token)
		if err != nil {
			if errors.Is(err, auth.ErrUnauthenticated) {
				abortAuthenticationRequired(c)
				return
			}
			internalError(c, logger, err)
			return
		}
		c.Set(ActorKey, actor)
		c.Next()
	}
}

// internalError keeps database and configuration details out of responses while
// attaching the request id to the log line.
func internalError(c *gin.Context, logger *slog.Logger, err error) {
	logger.Error("auth request failed",
		"request_id", c.GetString(RequestIDKey),
		"error", err,
	)
	c.AbortWithStatusJSON(http.StatusInternalServerError, errorResponse{
		Error: errorDetail{Code: codeInternalError, Message: "internal server error"},
	})
}

func abortAuthenticationRequired(c *gin.Context) {
	c.Header("WWW-Authenticate", "Bearer")
	c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse{
		Error: errorDetail{Code: codeAuthenticationRequired, Message: "authentication required"},
	})
}

func (authentication authHandler) providers(c *gin.Context) {
	identifiers := authentication.service.Providers()
	items := make([]providerItem, 0, len(identifiers))
	for _, identifier := range identifiers {
		items = append(items, providerItem{ID: identifier})
	}
	c.JSON(http.StatusOK, providersResponse{Data: items})
}

func (authentication authHandler) login(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxLoginBodyBytes)

	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var request loginRequest
	if err := decoder.Decode(&request); err != nil || decoder.More() ||
		request.Email == nil || request.Password == nil {
		c.JSON(http.StatusBadRequest, errorResponse{
			Error: errorDetail{Code: codeValidationError, Message: "invalid request body"},
		})
		return
	}

	result, err := authentication.service.Login(
		c.Request.Context(),
		auth.LoginRequest{Email: *request.Email, Password: *request.Password},
		clientInfo(c),
	)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, errorResponse{
				Error: errorDetail{Code: codeAuthenticationRequired, Message: "invalid email or password"},
			})
			return
		}
		var rateLimited auth.RateLimitedError
		if errors.As(err, &rateLimited) {
			retryAfter := max(int(math.Ceil(rateLimited.RetryAfter.Seconds())), 1)
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.JSON(http.StatusTooManyRequests, errorResponse{
				Error: errorDetail{Code: codeRateLimited, Message: "too many failed logins"},
			})
			return
		}
		internalError(c, authentication.logger, err)
		return
	}

	roles := result.Roles
	if roles == nil {
		roles = []string{}
	}
	c.JSON(http.StatusOK, loginResponse{
		SessionToken: result.Token,
		ExpiresAt:    result.ExpiresAt.UTC().Format(time.RFC3339),
		User: loginUser{
			ID:          result.User.ID,
			Email:       result.User.Email,
			DisplayName: result.User.DisplayName,
			Roles:       roles,
		},
	})
}

func (authentication authHandler) logout(c *gin.Context) {
	actor := c.MustGet(ActorKey).(auth.Actor)
	if err := authentication.service.Logout(c.Request.Context(), actor, clientInfo(c)); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			abortAuthenticationRequired(c)
			return
		}
		internalError(c, authentication.logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (authentication authHandler) me(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	actor := c.MustGet(ActorKey).(auth.Actor)
	user, roles, err := authentication.service.CurrentUser(c.Request.Context(), actor)
	if err != nil {
		internalError(c, authentication.logger, err)
		return
	}
	if roles == nil {
		roles = []string{}
	}
	c.JSON(http.StatusOK, userResponse{
		ID:          user.ID,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Status:      user.Status,
		Roles:       roles,
		CreatedAt:   user.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   user.UpdatedAt.UTC().Format(time.RFC3339),
		Version:     user.Version,
	})
}

func clientInfo(c *gin.Context) auth.ClientInfo {
	return auth.ClientInfo{
		IP:        net.ParseIP(c.ClientIP()),
		UserAgent: c.GetHeader("User-Agent"),
		RequestID: c.GetString(RequestIDKey),
	}
}
