package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const apiPathPrefix = "/api"

// NewRouter builds the HTTP engine: middleware first, then the health and web
// routes, then the fallback for every other path.
func NewRouter(dependencies Dependencies) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	if err := router.SetTrustedProxies(dependencies.TrustedProxies); err != nil {
		dependencies.Logger.Error("configure trusted proxies", "error", err)
		_ = router.SetTrustedProxies(nil)
	}

	router.Use(
		securityHeaders(),
		requestID(),
		requestLog(dependencies.Logger),
		recovery(dependencies.Logger),
	)

	health := healthHandler{
		database:     dependencies.Database,
		logger:       dependencies.Logger,
		buildVersion: dependencies.Version,
		buildCommit:  dependencies.Commit,
	}
	web := newWebHandler(dependencies.Web)

	// Gin does not answer HEAD from GET routes; without these a HEAD /readyz
	// would fall through to the web page and report ready.
	readMethods := []string{http.MethodGet, http.MethodHead}
	router.Match(readMethods, "/healthz", health.healthz)
	router.Match(readMethods, "/readyz", health.readyz)
	router.Match(readMethods, "/version", health.version)
	router.Match(readMethods, "/assets/*filepath", web.assets)

	policy := newOriginPolicy(dependencies.PublicURL, dependencies.Development, dependencies.Logger)
	authentication := authHandler{service: dependencies.Auth, logger: dependencies.Logger, policy: policy}
	users := userHandler{service: dependencies.Auth, logger: dependencies.Logger}
	auditEvents := auditHandler{database: dependencies.AuditDatabase, logger: dependencies.Logger}
	v1 := router.Group("/api/v1")
	v1.GET("/auth/providers", authentication.providers)
	v1.POST("/auth/login", authentication.login)
	v1.POST("/auth/password-reset", users.useResetToken)
	authenticated := v1.Group("",
		requireSameOriginForCookie(policy, dependencies.Logger),
		requireSession(dependencies.Auth, dependencies.Logger, policy),
	)
	authenticated.POST("/auth/logout", authentication.logout)
	authenticated.GET("/me", authentication.me)

	authenticated.GET("/users", requirePermission(dependencies.Auth, dependencies.Logger, "user:read"), users.list)
	authenticated.POST("/users", requirePermission(dependencies.Auth, dependencies.Logger, "user:write", "role:assign"), users.create)
	authenticated.GET("/users/:userId", requirePermission(dependencies.Auth, dependencies.Logger, "user:read"), users.get)
	authenticated.PATCH("/users/:userId", requirePermission(dependencies.Auth, dependencies.Logger, "user:write"), users.update)
	authenticated.POST("/users/:userId/disable", requirePermission(dependencies.Auth, dependencies.Logger, "user:write"), users.disable)
	authenticated.POST("/users/:userId/enable", requirePermission(dependencies.Auth, dependencies.Logger, "user:write"), users.enable)
	authenticated.POST("/users/:userId/password-reset", requirePermission(dependencies.Auth, dependencies.Logger, "user:write"), users.createResetToken)
	authenticated.GET("/roles", requirePermission(dependencies.Auth, dependencies.Logger, "user:read"), users.roles)
	authenticated.POST("/users/:userId/roles", requirePermission(dependencies.Auth, dependencies.Logger, "role:assign"), users.assignRole)
	authenticated.DELETE("/users/:userId/roles/:role", requirePermission(dependencies.Auth, dependencies.Logger, "role:assign"), users.removeRole)
	authenticated.GET("/audit-events", requirePermission(dependencies.Auth, dependencies.Logger, "audit:read"), auditEvents.list)
	authenticated.GET("/audit-events/:auditEventId", requirePermission(dependencies.Auth, dependencies.Logger, "audit:read"), auditEvents.get)

	router.NoRoute(web.page)
	return router
}
