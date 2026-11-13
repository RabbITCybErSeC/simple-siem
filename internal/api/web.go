package api

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	webRouteLabel = "web"

	immutableCacheControl = "public, max-age=31536000, immutable"
	noCacheControl        = "no-cache"

	codeNotFound = "NOT_FOUND"

	frontendNotBuiltPage = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Simple SIEM</title></head>
<body><h1>Simple SIEM</h1><p>The frontend is not built. Run <code>make build</code>.</p></body>
</html>
`
)

type webHandler struct {
	files     fs.FS
	indexHTML []byte
}

// newWebHandler reads index.html once; without a frontend build every page
// path gets the not-built page instead.
func newWebHandler(files fs.FS) webHandler {
	indexHTML := []byte(frontendNotBuiltPage)
	if files != nil {
		if content, err := fs.ReadFile(files, "index.html"); err == nil {
			indexHTML = content
		}
	}
	return webHandler{files: files, indexHTML: indexHTML}
}

// assets serves hashed build files. The path is deliberately not cleaned:
// io/fs rejects any ".." element, which keeps requests inside the build.
func (web webHandler) assets(c *gin.Context) {
	assetPath := "assets" + c.Param("filepath")
	if web.files == nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	info, err := fs.Stat(web.files, assetPath)
	if err != nil || info.IsDir() {
		c.String(http.StatusNotFound, "not found")
		return
	}
	c.Header("Cache-Control", immutableCacheControl)
	http.ServeFileFS(c.Writer, c.Request, web.files, assetPath)
}

// page answers every path no route matched: JSON 404 under /api, the web UI
// for page reads, and a plain 404 for anything else.
func (web webHandler) page(c *gin.Context) {
	requestPath := c.Request.URL.Path
	if requestPath == apiPathPrefix || strings.HasPrefix(requestPath, apiPathPrefix+"/") {
		c.JSON(http.StatusNotFound, errorResponse{
			Error: errorDetail{Code: codeNotFound, Message: "route not found"},
		})
		return
	}
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		c.String(http.StatusNotFound, "not found")
		return
	}
	c.Set(routeLabelKey, webRouteLabel)
	c.Header("Cache-Control", noCacheControl)
	c.Data(http.StatusOK, "text/html; charset=utf-8", web.indexHTML)
}
