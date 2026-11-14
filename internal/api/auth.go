package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

const (
	maxLoginBodyBytes = 4096

	sessionCookieName  = "simple_siem_session"
	browserHeader      = "X-Requested-With"
	browserHeaderValue = "simple-siem"

	credentialKey    = "credential"
	credentialCookie = "cookie"
	credentialBearer = "bearer"

	codeAuthenticationRequired = "AUTHENTICATION_REQUIRED"
	codeForbidden              = "FORBIDDEN"
	codeValidationError        = "VALIDATION_ERROR"
	codeRateLimited            = "RATE_LIMITED"
)

type authHandler struct {
	service *auth.Service
	logger  *slog.Logger
	policy  originPolicy
}

// newOriginPolicy reads the public URL once so every request compares against
// the same origin without parsing the configuration again.
func newOriginPolicy(publicURL string, development bool, logger *slog.Logger) originPolicy {
	policy := originPolicy{development: development}
	if publicURL == "" {
		return policy
	}
	parsed, err := url.Parse(publicURL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		logger.Error("public URL is not usable as an origin", "public_url", publicURL, "error", err)
		return policy
	}
	policy.publicOrigin = originFromURL(parsed)
	policy.secureCookie = parsed.Scheme == "https"
	return policy
}

// originFromURL renders scheme://host[:port] and drops a default port.
func originFromURL(publicURL *url.URL) string {
	host := publicURL.Host
	if (publicURL.Scheme == "http" && publicURL.Port() == "80") ||
		(publicURL.Scheme == "https" && publicURL.Port() == "443") {
		host = publicURL.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return publicURL.Scheme + "://" + host
}

// allows reports whether origin may drive a browser session. An empty or
// opaque origin never matches; development only adds the loopback origins of
// the Vite dev server.
func (policy originPolicy) allows(origin string) bool {
	if origin == "" || origin == "null" {
		return false
	}
	if policy.publicOrigin != "" && origin == policy.publicOrigin {
		return true
	}
	if !policy.development {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1"
}

// rejectCrossSite blocks a browser login or cookie request that did not come
// from the console itself. The log line names the origin, never the cookie.
func rejectCrossSite(c *gin.Context, logger *slog.Logger) {
	logger.Warn("cross-site request rejected",
		"request_id", c.GetString(RequestIDKey),
		"origin", c.GetHeader("Origin"),
	)
	c.AbortWithStatusJSON(http.StatusForbidden, errorResponse{
		Error: errorDetail{Code: codeForbidden, Message: "cross-site request rejected"},
	})
}

// sessionCookie is the one place that defines the browser session attributes.
func sessionCookie(token string, maxAge int, policy originPolicy) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/api",
		HttpOnly: true,
		Secure:   policy.secureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
}

func clearSessionCookie(c *gin.Context, policy originPolicy) {
	http.SetCookie(c.Writer, sessionCookie("", -1, policy))
}

// requireSession accepts a bearer token or the browser cookie for a live
// session of an active user, rejects a request that carries both, and puts the
// actor and its credential on the context for the handlers in its group.
func requireSession(service *auth.Service, logger *slog.Logger, policy originPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookieToken, _ := c.Cookie(sessionCookieName)
		bearerToken := ""
		if authorization := c.GetHeader("Authorization"); authorization != "" {
			scheme, token, found := strings.Cut(authorization, " ")
			if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.Contains(token, " ") {
				if cookieToken != "" {
					clearSessionCookie(c, policy)
				}
				abortAuthenticationRequired(c)
				return
			}
			bearerToken = token
		}

		if bearerToken != "" && cookieToken != "" {
			clearSessionCookie(c, policy)
			abortAuthenticationRequired(c)
			return
		}

		token, credential := bearerToken, credentialBearer
		if token == "" {
			token, credential = cookieToken, credentialCookie
		}
		if token == "" {
			abortAuthenticationRequired(c)
			return
		}

		actor, err := service.Authenticate(c.Request.Context(), token)
		if err != nil {
			if errors.Is(err, auth.ErrUnauthenticated) {
				if credential == credentialCookie {
					clearSessionCookie(c, policy)
				}
				abortAuthenticationRequired(c)
				return
			}
			internalError(c, logger, err)
			return
		}
		c.Set(ActorKey, actor)
		c.Set(credentialKey, credential)
		if credential == credentialCookie && c.Request.Method != http.MethodGet &&
			c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions &&
			(c.GetHeader(browserHeader) != browserHeaderValue || !policy.allows(c.GetHeader("Origin"))) {
			rejectCrossSite(c, logger)
			return
		}
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
	browser := c.GetHeader(browserHeader) == browserHeaderValue
	if browser && !authentication.policy.allows(c.GetHeader("Origin")) {
		rejectCrossSite(c, authentication.logger)
		return
	}
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
	user := loginUser{
		ID:          result.User.ID,
		Email:       result.User.Email,
		DisplayName: result.User.DisplayName,
		Roles:       roles,
	}
	expiresAt := result.ExpiresAt.UTC().Format(time.RFC3339)
	if browser {
		maxAge := int(math.Ceil(time.Until(result.ExpiresAt).Seconds()))
		http.SetCookie(c.Writer, sessionCookie(result.Token, maxAge, authentication.policy))
		c.JSON(http.StatusOK, browserLoginResponse{ExpiresAt: expiresAt, User: user})
		return
	}
	c.JSON(http.StatusOK, loginResponse{
		SessionToken: result.Token,
		ExpiresAt:    expiresAt,
		User:         user,
	})
}

func (authentication authHandler) logout(c *gin.Context) {
	actor := c.MustGet(ActorKey).(auth.Actor)
	if err := authentication.service.Logout(c.Request.Context(), actor, clientInfo(c)); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			if c.GetString(credentialKey) == credentialCookie {
				clearSessionCookie(c, authentication.policy)
			}
			abortAuthenticationRequired(c)
			return
		}
		internalError(c, authentication.logger, err)
		return
	}
	if c.GetString(credentialKey) == credentialCookie {
		clearSessionCookie(c, authentication.policy)
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
