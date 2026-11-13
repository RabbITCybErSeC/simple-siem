package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	apiPathPrefix = "/api"
	// routeLabelKey names a request on the context when it matched no Gin
	// route, so the request log can still say what it was.
	routeLabelKey = "route_label"
)

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
	router.NoRoute(web.page)
	return router
}
