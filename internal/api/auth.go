package api

import (
	"context"
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
	sessionCookieName       = "simple_siem_session"
	secureSessionCookieName = "__Host-simple_siem_session"
	browserHeader           = "X-Requested-With"
	browserHeaderValue      = "simple-siem"

	permissionDenialTimeout = 5 * time.Second

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
	if !isASCII(parsed.Hostname()) {
		logger.Error("public URL host must be an ASCII host name", "public_url", publicURL)
		return policy
	}
	policy.publicOrigin = originFromURL(parsed)
	policy.secureCookie = parsed.Scheme == "https"
	return policy
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > 127 {
			return false
		}
	}
	return true
}

// originFromURL renders scheme://host[:port] and drops a default port.
func originFromURL(publicURL *url.URL) string {
	host := strings.ToLower(publicURL.Host)
	if (publicURL.Scheme == "http" && publicURL.Port() == "80") ||
		(publicURL.Scheme == "https" && publicURL.Port() == "443") {
		host = strings.ToLower(publicURL.Hostname())
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

// cookieName is the name of the session cookie in the mode this server runs.
func (policy originPolicy) cookieName() string {
	if policy.secureCookie {
		return secureSessionCookieName
	}
	return sessionCookieName
}

// sessionCookie is the one place that defines the browser session attributes.
// The __Host- prefix requires Secure, Path=/, and no Domain attribute.
func sessionCookie(token string, maxAge int, policy originPolicy) *http.Cookie {
	return &http.Cookie{
		Name:     policy.cookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   policy.secureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
}

func clearSessionCookie(c *gin.Context, policy originPolicy) {
	http.SetCookie(c.Writer, sessionCookie("", -1, policy))
}

// bearerCredential parses an Authorization header. bearer reports the Bearer
// scheme, even when the token is missing or malformed; valid reports a token
// that can be sent to the service.
func bearerCredential(authorization string) (token string, bearer, valid bool) {
	scheme, token, found := strings.Cut(authorization, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", false, false
	}
	if !found || token == "" || strings.Contains(token, " ") {
		return "", true, false
	}
	return token, true, true
}

// requireSameOriginForCookie rejects a state-changing cookie request from a
// foreign origin before any session lookup, so a rejected request costs no
// database work and cannot slide the session.
func requireSameOriginForCookie(policy originPolicy, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		if _, bearer, _ := bearerCredential(c.GetHeader("Authorization")); bearer {
			c.Next()
			return
		}
		if len(c.Request.CookiesNamed(policy.cookieName())) != 1 {
			c.Next()
			return
		}
		if c.GetHeader(browserHeader) != browserHeaderValue || !policy.allows(c.GetHeader("Origin")) {
			rejectCrossSite(c, logger)
			return
		}
		c.Next()
	}
}

// requireSession accepts a bearer token or the browser cookie for a live
// session of an active user, rejects a request that carries both, and puts the
// actor and its credential on the context for the handlers in its group.
func requireSession(service *auth.Service, logger *slog.Logger, policy originPolicy) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookies := c.Request.CookiesNamed(policy.cookieName())
		if len(cookies) > 1 {
			clearSessionCookie(c, policy)
			abortAuthenticationRequired(c)
			return
		}
		cookieToken := ""
		if len(cookies) == 1 {
			cookieToken = cookies[0].Value
		}
		bearerToken, bearer, valid := bearerCredential(c.GetHeader("Authorization"))
		if bearer && !valid {
			if cookieToken != "" {
				clearSessionCookie(c, policy)
			}
			abortAuthenticationRequired(c)
			return
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
		c.Next()
	}
}

// requirePermission rejects the request when the actor's roles lack one of the
// permissions the route declares. The denial is audited on a best-effort
// basis: an audit failure is logged and the request still gets its 403.
func requirePermission(service *auth.Service, logger *slog.Logger, permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor := c.MustGet(ActorKey).(auth.Actor)
		for _, permission := range permissions {
			if actor.Can(permission) {
				continue
			}
			// The client can cancel its request; the denial must still be
			// recorded, but not indefinitely.
			denialContext, cancel := context.WithTimeout(
				context.WithoutCancel(c.Request.Context()), permissionDenialTimeout,
			)
			defer cancel()
			err := service.RecordPermissionDenied(
				denialContext,
				actor, clientInfo(c), c.FullPath(), c.Request.Method, permissions,
			)
			if err != nil {
				logger.Error("record permission denial failed",
					"request_id", c.GetString(RequestIDKey),
					"error", err,
				)
			}
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatusJSON(http.StatusForbidden, errorResponse{
				Error: errorDetail{Code: codeForbidden, Message: "permission denied"},
			})
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
	var request loginRequest
	if !decodeJSONBody(c, &request) {
		return
	}
	if request.Email == nil || request.Password == nil {
		writeError(c, http.StatusBadRequest, codeValidationError, "invalid request body")
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
	response := loginResponse{
		ExpiresAt: result.ExpiresAt.UTC().Format(time.RFC3339),
		User:      user,
	}
	if browser {
		maxAge := max(1, int(math.Ceil(time.Until(result.ExpiresAt).Seconds())))
		http.SetCookie(c.Writer, sessionCookie(result.Token, maxAge, authentication.policy))
	} else {
		response.SessionToken = result.Token
	}
	c.JSON(http.StatusOK, response)
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
