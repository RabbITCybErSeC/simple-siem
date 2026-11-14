package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

// userHandler serves the user, role, and password-reset routes.
type userHandler struct {
	service *auth.Service
	logger  *slog.Logger
}

// userTransition is one version-checked state change on a user.
type userTransition func(ctx context.Context, actor auth.Actor, client auth.ClientInfo, userID string, version int) (auth.UserWithRoles, error)

func (users userHandler) list(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	query, ok := allowedQuery(c, "status", "page", "pageSize")
	if !ok {
		return
	}
	status := query.Get("status")
	page, pageSize, ok := parsePagination(c, query, maxUserPageSize)
	if !ok {
		return
	}

	listed, total, err := users.service.ListUsers(c.Request.Context(), auth.UserFilter{
		Status: status, Page: page, PageSize: pageSize,
	})
	if err != nil {
		writeUserError(c, users.logger, err)
		return
	}
	data := make([]userResponse, 0, len(listed))
	for _, user := range listed {
		data = append(data, newUserResponse(user))
	}
	c.JSON(http.StatusOK, userListResponse{Data: data, Pagination: newPagination(page, pageSize, total)})
}

func (users userHandler) create(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var request createUserRequest
	if !decodeJSONBody(c, &request) {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	created, err := users.service.CreateUser(c.Request.Context(), actor, clientInfo(c), auth.CreateUserRequest{
		Email:       request.Email,
		DisplayName: request.DisplayName,
		Roles:       request.Roles,
	})
	if err != nil {
		writeUserError(c, users.logger, err)
		return
	}
	c.JSON(http.StatusCreated, newUserResponse(created))
}

func (users userHandler) get(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	userID, ok := pathUUID(c, "userId", "user not found")
	if !ok {
		return
	}

	user, err := users.service.GetUser(c.Request.Context(), userID)
	if err != nil {
		writeUserError(c, users.logger, err)
		return
	}
	c.JSON(http.StatusOK, newUserResponse(user))
}

func (users userHandler) update(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	userID, ok := pathUUID(c, "userId", "user not found")
	if !ok {
		return
	}
	var request updateUserRequest
	if !decodeJSONBody(c, &request) {
		return
	}
	version, ok := requiredVersion(c, request.Version)
	if !ok {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	updated, err := users.service.UpdateUser(c.Request.Context(), actor, clientInfo(c), userID, auth.UpdateUserRequest{
		Email:       request.Email,
		DisplayName: request.DisplayName,
		Version:     version,
	})
	if err != nil {
		writeUserError(c, users.logger, err)
		return
	}
	c.JSON(http.StatusOK, newUserResponse(updated))
}

func (users userHandler) disable(c *gin.Context) {
	users.setStatus(c, users.service.DisableUser)
}

func (users userHandler) enable(c *gin.Context) {
	users.setStatus(c, users.service.EnableUser)
}

// setStatus serves both state transitions, so their validation and response
// cannot drift apart.
func (users userHandler) setStatus(c *gin.Context, transition userTransition) {
	c.Header("Cache-Control", "no-store")
	userID, ok := pathUUID(c, "userId", "user not found")
	if !ok {
		return
	}
	var request versionRequest
	if !decodeJSONBody(c, &request) {
		return
	}
	version, ok := requiredVersion(c, request.Version)
	if !ok {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	user, err := transition(c.Request.Context(), actor, clientInfo(c), userID, version)
	if err != nil {
		writeUserError(c, users.logger, err)
		return
	}
	c.JSON(http.StatusOK, newUserResponse(user))
}

func (users userHandler) createResetToken(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	userID, ok := pathUUID(c, "userId", "user not found")
	if !ok {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	token, expiresAt, err := users.service.CreateResetToken(c.Request.Context(), actor, clientInfo(c), userID)
	if err != nil {
		writeUserError(c, users.logger, err)
		return
	}
	c.JSON(http.StatusCreated, resetTokenResponse{
		ResetToken: token,
		ExpiresAt:  expiresAt.UTC().Format(time.RFC3339),
	})
}

func (users userHandler) roles(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	roles, err := users.service.ListRoles(c.Request.Context())
	if err != nil {
		internalError(c, users.logger, err)
		return
	}

	data := make([]roleResponse, 0, len(roles))
	for _, role := range roles {
		data = append(data, roleResponse{
			Name:        role.Name,
			Description: role.Description,
			Permissions: role.Permissions,
		})
	}
	c.JSON(http.StatusOK, rolesResponse{Data: data})
}

func (users userHandler) assignRole(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	userID, ok := pathUUID(c, "userId", "user not found")
	if !ok {
		return
	}
	var request assignRoleRequest
	if !decodeJSONBody(c, &request) {
		return
	}
	if request.Role == "" {
		invalidParameter(c, "role")
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	user, err := users.service.AssignRole(c.Request.Context(), actor, clientInfo(c), userID, request.Role)
	if err != nil {
		writeUserError(c, users.logger, err)
		return
	}
	c.JSON(http.StatusOK, newUserResponse(user))
}

func (users userHandler) removeRole(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	userID, ok := pathUUID(c, "userId", "user not found")
	if !ok {
		return
	}

	actor := c.MustGet(ActorKey).(auth.Actor)
	user, err := users.service.RemoveRole(c.Request.Context(), actor, clientInfo(c), userID, c.Param("role"))
	if err != nil {
		writeUserError(c, users.logger, err)
		return
	}
	c.JSON(http.StatusOK, newUserResponse(user))
}

func (users userHandler) useResetToken(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var request useResetTokenRequest
	if !decodeJSONBody(c, &request) {
		return
	}

	err := users.service.UseResetToken(c.Request.Context(), request.Token, request.Password, clientInfo(c))
	if err != nil {
		writeUserError(c, users.logger, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// decodeJSONBody enforces the shared body limits: 4096 bytes, no unknown
// fields, exactly one JSON value.
func decodeJSONBody(c *gin.Context, destination any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.More() {
		writeError(c, http.StatusBadRequest, codeValidationError, "invalid request body")
		return false
	}
	return true
}

// allowedQuery rejects every query parameter a route does not document.
func allowedQuery(c *gin.Context, allowed ...string) (url.Values, bool) {
	query := c.Request.URL.Query()
	for name := range query {
		if !slices.Contains(allowed, name) {
			writeError(c, http.StatusBadRequest, codeValidationError, "unknown query parameter: "+name)
			return nil, false
		}
	}
	return query, true
}

func parsePagination(c *gin.Context, query url.Values, maxPageSize int) (int, int, bool) {
	page := 1
	if raw := query.Get("page"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > audit.MaxPage {
			invalidParameter(c, "page")
			return 0, 0, false
		}
		page = parsed
	}

	pageSize := defaultPageSize
	if raw := query.Get("pageSize"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxPageSize {
			invalidParameter(c, "pageSize")
			return 0, 0, false
		}
		pageSize = parsed
	}
	return page, pageSize, true
}

func newPagination(page, pageSize int, total int64) pagination {
	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return pagination{Page: page, PageSize: pageSize, TotalItems: total, TotalPages: totalPages}
}

func pathUUID(c *gin.Context, parameter, notFoundMessage string) (string, bool) {
	value := c.Param(parameter)
	if !audit.ValidID(value) {
		writeError(c, http.StatusNotFound, codeNotFound, notFoundMessage)
		return "", false
	}
	return value, true
}

func requiredVersion(c *gin.Context, version *int) (int, bool) {
	if version == nil || *version < 1 {
		invalidParameter(c, "version")
		return 0, false
	}
	return *version, true
}

func newUserResponse(user auth.UserWithRoles) userResponse {
	roles := user.Roles
	if roles == nil {
		roles = []string{}
	}
	return userResponse{
		ID:          user.User.ID,
		Email:       user.User.Email,
		DisplayName: user.User.DisplayName,
		Status:      user.User.Status,
		Roles:       roles,
		CreatedAt:   user.User.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   user.User.UpdatedAt.UTC().Format(time.RFC3339),
		Version:     user.User.Version,
	}
}

func writeUserError(c *gin.Context, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, auth.ErrUserNotFound):
		writeError(c, http.StatusNotFound, codeNotFound, "user not found")
	case errors.Is(err, auth.ErrVersionConflict):
		writeError(c, http.StatusConflict, codeVersionConflict, auth.ErrVersionConflict.Error())
	case errors.Is(err, auth.ErrStateConflict):
		writeError(c, http.StatusConflict, codeStateConflict, stateConflictMessage(err))
	case errors.Is(err, auth.ErrUserExists):
		writeError(c, http.StatusConflict, codeStateConflict, "email already in use")
	case errors.Is(err, auth.ErrForbidden):
		writeError(c, http.StatusForbidden, codeForbidden, auth.ErrForbidden.Error())
	case errors.Is(err, audit.ErrInvalidPage):
		invalidParameter(c, "page")
	case errors.Is(err, auth.ErrUnknownRole), errors.Is(err, auth.ErrInvalidEmail),
		errors.Is(err, auth.ErrInvalidDisplayName), errors.Is(err, auth.ErrPasswordLength),
		errors.Is(err, auth.ErrInvalidStatus):
		writeError(c, http.StatusBadRequest, codeValidationError, err.Error())
	case errors.Is(err, auth.ErrInvalidResetToken):
		writeError(c, http.StatusBadRequest, codeValidationError, "invalid or expired token")
	default:
		internalError(c, logger, err)
	}
}

// stateConflictMessage strips the sentinel prefix so the API returns the
// specific reason the service attached.
func stateConflictMessage(err error) string {
	if reason, found := strings.CutPrefix(err.Error(), auth.ErrStateConflict.Error()+": "); found {
		return reason
	}
	return err.Error()
}

func writeError(c *gin.Context, status int, code, message string) {
	c.AbortWithStatusJSON(status, errorResponse{
		Error: errorDetail{Code: code, Message: message},
	})
}

func invalidParameter(c *gin.Context, name string) {
	writeError(c, http.StatusBadRequest, codeValidationError, "invalid "+name)
}
