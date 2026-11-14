package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"gorm.io/gorm"
)

const (
	statusDisabled      = "DISABLED"
	statusInvited       = "INVITED"
	defaultUserPageSize = 50
	lastAdminLockName   = "simple-siem:last-admin"
	resetTokenLifetime  = 24 * time.Hour
	resetTokenLength    = 32
)

// hashPasswordFunction is the hasher UseResetToken calls. It is a test seam:
// the only way an in-package test can prove an invalid token never hashes.
var hashPasswordFunction = HashPassword

// userWithRoleNames scans one user row with its roles aggregated per row.
type userWithRoleNames struct {
	User
	RoleNames string `gorm:"column:role_names"`
}

// resetTokenRow is one usable password reset token.
type resetTokenRow struct {
	ID     string `gorm:"column:id"`
	UserID string `gorm:"column:user_id"`
}

// selectUsersWithRoleNames is shared by the list and the single-user read so
// both produce the same aggregated role names.
const selectUsersWithRoleNames = `
	SELECT users.*,
	       COALESCE(string_agg(user_roles.role_name, ',' ORDER BY user_roles.role_name), '') AS role_names
	FROM users
	LEFT JOIN user_roles ON user_roles.user_id = users.id`

// resetTokenLookup finds a token that is unused, unexpired, and not disabled.
// Both UseResetToken checks use it, so they cannot drift apart.
const resetTokenLookup = `
	SELECT password_reset_tokens.id::text AS id, password_reset_tokens.user_id::text AS user_id
	FROM password_reset_tokens
	JOIN users ON users.id = password_reset_tokens.user_id
	WHERE password_reset_tokens.token_hash = ? AND password_reset_tokens.used_at IS NULL
	  AND password_reset_tokens.expires_at > now() AND users.status <> ?`

func (service *Service) ListUsers(ctx context.Context, filter UserFilter) ([]UserWithRoles, int64, error) {
	switch filter.Status {
	case "", StatusActive, statusDisabled, statusInvited:
	default:
		return nil, 0, ErrInvalidStatus
	}
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = defaultUserPageSize
	}

	condition := ""
	arguments := []any{}
	if filter.Status != "" {
		condition = " WHERE users.status = ?"
		arguments = append(arguments, filter.Status)
	}
	database := service.database.WithContext(ctx)

	var total int64
	if err := database.Raw(
		"SELECT count(*) FROM users"+condition, arguments...,
	).Scan(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	arguments = append(arguments, pageSize, (page-1)*pageSize)
	var rows []userWithRoleNames
	err := database.Raw(selectUsersWithRoleNames+condition+`
		GROUP BY users.id
		ORDER BY users.created_at, users.id
		LIMIT ? OFFSET ?`, arguments...).Scan(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}

	users := make([]UserWithRoles, 0, len(rows))
	for _, row := range rows {
		users = append(users, UserWithRoles{User: row.User, Roles: splitRoleNames(row.RoleNames)})
	}
	return users, total, nil
}

func (service *Service) GetUser(ctx context.Context, userID string) (UserWithRoles, error) {
	return loadUserWithRoles(service.database.WithContext(ctx), userID)
}

func (service *Service) CreateUser(ctx context.Context, actor Actor, client ClientInfo, request CreateUserRequest) (UserWithRoles, error) {
	email, err := NormalizeEmail(request.Email)
	if err != nil {
		return UserWithRoles{}, err
	}
	displayName, err := NormalizeDisplayName(request.DisplayName)
	if err != nil {
		return UserWithRoles{}, err
	}
	roles := uniqueRoles(request.Roles)

	var created UserWithRoles
	err = service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := ensureRolesExist(tx, roles); err != nil {
			return err
		}

		user := User{Email: email, DisplayName: displayName, Status: statusInvited}
		if err := tx.Create(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return ErrUserExists
			}
			return fmt.Errorf("create user: %w", err)
		}
		for _, role := range roles {
			if err := tx.Exec(
				"INSERT INTO user_roles (user_id, role_name) VALUES (?, ?)", user.ID, role,
			).Error; err != nil {
				return fmt.Errorf("assign role %s: %w", role, err)
			}
		}

		event := userAuditEvent(actor, client, "USER")
		event.EventName = "simple_siem.user.created"
		event.TargetID = user.ID
		event.Action = "create"
		event.Changes = map[string]any{
			"email":       user.Email,
			"displayName": user.DisplayName,
			"roles":       roles,
		}
		if err := audit.Record(tx, event); err != nil {
			return err
		}

		var loadErr error
		created, loadErr = loadUserWithRoles(tx, user.ID)
		return loadErr
	})
	if err != nil {
		return UserWithRoles{}, err
	}
	return created, nil
}

func (service *Service) UpdateUser(ctx context.Context, actor Actor, client ClientInfo, userID string, request UpdateUserRequest) (UserWithRoles, error) {
	var email, displayName *string
	if request.Email != nil {
		normalized, err := NormalizeEmail(*request.Email)
		if err != nil {
			return UserWithRoles{}, err
		}
		email = &normalized
	}
	if request.DisplayName != nil {
		normalized, err := NormalizeDisplayName(*request.DisplayName)
		if err != nil {
			return UserWithRoles{}, err
		}
		displayName = &normalized
	}

	var updated UserWithRoles
	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		user, err := loadUser(tx, userID)
		if err != nil {
			return err
		}

		columns := map[string]any{}
		before := map[string]any{}
		after := map[string]any{}
		if email != nil && *email != user.Email {
			columns["email"] = *email
			before["email"] = user.Email
			after["email"] = *email
		}
		if displayName != nil && *displayName != user.DisplayName {
			columns["displayName"] = *displayName
			before["displayName"] = user.DisplayName
			after["displayName"] = *displayName
		}

		if user.Version != request.Version {
			return ErrVersionConflict
		}
		if len(columns) == 0 {
			updated, err = loadUserWithRoles(tx, user.ID)
			return err
		}

		columns["updated_at"] = gorm.Expr("now()")
		columns["version"] = gorm.Expr("version + 1")
		result := tx.Model(&User{}).
			Where("id = ? AND version = ?", user.ID, request.Version).
			Updates(columns)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrDuplicatedKey) {
				return ErrUserExists
			}
			return fmt.Errorf("update user: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return userMutationConflict(tx, user.ID)
		}

		event := userAuditEvent(actor, client, "USER")
		event.EventName = "simple_siem.user.updated"
		event.TargetID = user.ID
		event.Action = "update"
		event.Changes = map[string]any{"before": before, "after": after}
		if err := audit.Record(tx, event); err != nil {
			return err
		}

		updated, err = loadUserWithRoles(tx, user.ID)
		return err
	})
	if err != nil {
		return UserWithRoles{}, err
	}
	return updated, nil
}

func (service *Service) DisableUser(ctx context.Context, actor Actor, client ClientInfo, userID string, version int) (UserWithRoles, error) {
	var disabled UserWithRoles
	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockLastAdminGuard(tx); err != nil {
			return err
		}
		user, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		if actor.UserID == user.ID {
			return fmt.Errorf("%w: cannot disable your own account", ErrStateConflict)
		}
		if user.Status == statusDisabled {
			return fmt.Errorf("%w: user is disabled", ErrStateConflict)
		}
		admin, err := userHasRole(tx, user.ID, RoleAdmin)
		if err != nil {
			return err
		}
		if admin {
			remaining, err := otherActiveAdmins(tx, user.ID)
			if err != nil {
				return err
			}
			if remaining == 0 {
				return fmt.Errorf("%w: the last active admin cannot be removed", ErrStateConflict)
			}
		}

		result := tx.Model(&User{}).
			Where("id = ? AND version = ?", user.ID, version).
			Updates(map[string]any{
				"status":     statusDisabled,
				"updated_at": gorm.Expr("now()"),
				"version":    gorm.Expr("version + 1"),
			})
		if result.Error != nil {
			return fmt.Errorf("disable user: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return userMutationConflict(tx, user.ID)
		}

		sessions := tx.Exec("DELETE FROM sessions WHERE user_id = ?", user.ID)
		if sessions.Error != nil {
			return fmt.Errorf("delete sessions: %w", sessions.Error)
		}
		if err := tx.Exec(
			"DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL", user.ID,
		).Error; err != nil {
			return fmt.Errorf("delete reset tokens: %w", err)
		}

		event := userAuditEvent(actor, client, "USER")
		event.EventName = "simple_siem.user.disabled"
		event.TargetID = user.ID
		event.Action = "disable"
		event.Changes = map[string]any{"revokedCount": sessions.RowsAffected}
		if err := audit.Record(tx, event); err != nil {
			return err
		}

		disabled, err = loadUserWithRoles(tx, user.ID)
		return err
	})
	if err != nil {
		return UserWithRoles{}, err
	}
	return disabled, nil
}

func (service *Service) EnableUser(ctx context.Context, actor Actor, client ClientInfo, userID string, version int) (UserWithRoles, error) {
	var enabled UserWithRoles
	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		user, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		if user.Status != statusDisabled {
			return fmt.Errorf("%w: user is not disabled", ErrStateConflict)
		}

		var passwords int64
		err = tx.Raw(
			"SELECT count(*) FROM user_identities WHERE user_id = ? AND provider = ? AND password_hash IS NOT NULL",
			user.ID, ProviderLocal,
		).Scan(&passwords).Error
		if err != nil {
			return fmt.Errorf("check local password: %w", err)
		}
		status := statusInvited
		if passwords > 0 {
			status = StatusActive
		}

		result := tx.Model(&User{}).
			Where("id = ? AND version = ?", user.ID, version).
			Updates(map[string]any{
				"status":     status,
				"updated_at": gorm.Expr("now()"),
				"version":    gorm.Expr("version + 1"),
			})
		if result.Error != nil {
			return fmt.Errorf("enable user: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return userMutationConflict(tx, user.ID)
		}

		event := userAuditEvent(actor, client, "USER")
		event.EventName = "simple_siem.user.enabled"
		event.TargetID = user.ID
		event.Action = "enable"
		event.Changes = map[string]any{"status": status}
		if err := audit.Record(tx, event); err != nil {
			return err
		}

		enabled, err = loadUserWithRoles(tx, user.ID)
		return err
	})
	if err != nil {
		return UserWithRoles{}, err
	}
	return enabled, nil
}

func (service *Service) AssignRole(ctx context.Context, actor Actor, client ClientInfo, userID, role string) (UserWithRoles, error) {
	var assigned UserWithRoles
	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := ensureRolesExist(tx, []string{role}); err != nil {
			return err
		}
		user, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		held, err := userHasRole(tx, user.ID, role)
		if err != nil {
			return err
		}
		if held {
			assigned, err = loadUserWithRoles(tx, user.ID)
			return err
		}

		if err := tx.Exec(
			"INSERT INTO user_roles (user_id, role_name) VALUES (?, ?)", user.ID, role,
		).Error; err != nil {
			return fmt.Errorf("assign role: %w", err)
		}
		if err := bumpUserVersion(tx, user.ID); err != nil {
			return err
		}

		event := userAuditEvent(actor, client, "AUTHORIZATION")
		event.EventName = "simple_siem.role.assigned"
		event.TargetID = user.ID
		event.Action = "assign_role"
		event.Changes = map[string]any{"role": role}
		if err := audit.Record(tx, event); err != nil {
			return err
		}

		assigned, err = loadUserWithRoles(tx, user.ID)
		return err
	})
	if err != nil {
		return UserWithRoles{}, err
	}
	return assigned, nil
}

func (service *Service) RemoveRole(ctx context.Context, actor Actor, client ClientInfo, userID, role string) (UserWithRoles, error) {
	var removed UserWithRoles
	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if role == RoleAdmin {
			if err := lockLastAdminGuard(tx); err != nil {
				return err
			}
		}
		if err := ensureRolesExist(tx, []string{role}); err != nil {
			return err
		}
		user, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		held, err := userHasRole(tx, user.ID, role)
		if err != nil {
			return err
		}
		if !held {
			removed, err = loadUserWithRoles(tx, user.ID)
			return err
		}
		if role == RoleAdmin {
			remaining, err := otherActiveAdmins(tx, user.ID)
			if err != nil {
				return err
			}
			if remaining == 0 {
				return fmt.Errorf("%w: the last active admin cannot be removed", ErrStateConflict)
			}
		}

		if err := tx.Exec(
			"DELETE FROM user_roles WHERE user_id = ? AND role_name = ?", user.ID, role,
		).Error; err != nil {
			return fmt.Errorf("remove role: %w", err)
		}
		if err := bumpUserVersion(tx, user.ID); err != nil {
			return err
		}

		event := userAuditEvent(actor, client, "AUTHORIZATION")
		event.EventName = "simple_siem.role.removed"
		event.TargetID = user.ID
		event.Action = "remove_role"
		event.Changes = map[string]any{"role": role}
		if err := audit.Record(tx, event); err != nil {
			return err
		}

		removed, err = loadUserWithRoles(tx, user.ID)
		return err
	})
	if err != nil {
		return UserWithRoles{}, err
	}
	return removed, nil
}

func (service *Service) CreateResetToken(ctx context.Context, actor Actor, client ClientInfo, userID string) (string, time.Time, error) {
	rawToken := make([]byte, resetTokenLength)
	if _, err := rand.Read(rawToken); err != nil {
		return "", time.Time{}, fmt.Errorf("generate reset token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256(rawToken)

	var expiresAt time.Time
	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		user, err := loadUser(tx, userID)
		if err != nil {
			return err
		}
		if user.Status == statusDisabled {
			return fmt.Errorf("%w: user is disabled", ErrStateConflict)
		}
		if err := tx.Exec(
			"DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL", user.ID,
		).Error; err != nil {
			return fmt.Errorf("delete reset tokens: %w", err)
		}

		var created struct {
			ExpiresAt time.Time `gorm:"column:expires_at"`
		}
		err = tx.Raw(`
			INSERT INTO password_reset_tokens (user_id, token_hash, created_by, expires_at)
			VALUES (?, ?, ?, now() + make_interval(secs => ?))
			RETURNING expires_at`,
			user.ID, tokenHash[:], actor.UserID, resetTokenLifetime.Seconds(),
		).Scan(&created).Error
		if err != nil {
			return fmt.Errorf("create reset token: %w", err)
		}
		expiresAt = created.ExpiresAt

		event := userAuditEvent(actor, client, "AUTHENTICATION")
		event.EventName = "simple_siem.auth.password_reset_created"
		event.TargetID = user.ID
		event.Action = "create_reset_token"
		return audit.Record(tx, event)
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (service *Service) UseResetToken(ctx context.Context, token, password string, client ClientInfo) error {
	rawToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(rawToken) != resetTokenLength {
		return ErrInvalidResetToken
	}
	tokenHash := sha256.Sum256(rawToken)

	// The token is looked up before ValidatePassword, so no token costs a
	// password validation or a hash; every invalid case returns the same error.
	var lookup resetTokenRow
	err = service.database.WithContext(ctx).Raw(
		resetTokenLookup, tokenHash[:], statusDisabled,
	).Scan(&lookup).Error
	if err != nil {
		return fmt.Errorf("find reset token: %w", err)
	}
	if lookup.ID == "" {
		return ErrInvalidResetToken
	}

	if err := ValidatePassword(password); err != nil {
		return err
	}
	passwordHash, err := hashPasswordFunction(ctx, password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	return service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var locked resetTokenRow
		err := tx.Raw(
			resetTokenLookup+" FOR UPDATE OF password_reset_tokens", tokenHash[:], statusDisabled,
		).Scan(&locked).Error
		if err != nil {
			return fmt.Errorf("lock reset token: %w", err)
		}
		if locked.ID == "" {
			return ErrInvalidResetToken
		}

		var identity struct {
			ID      string `gorm:"column:id"`
			Version int    `gorm:"column:version"`
		}
		err = tx.Raw(
			"SELECT id::text AS id, version FROM user_identities WHERE user_id = ? AND provider = ? FOR UPDATE",
			locked.UserID, ProviderLocal,
		).Scan(&identity).Error
		if err != nil {
			return fmt.Errorf("lock local identity: %w", err)
		}
		if identity.ID == "" {
			err = tx.Exec(
				"INSERT INTO user_identities (user_id, provider, subject, password_hash) VALUES (?, ?, ?, ?)",
				locked.UserID, ProviderLocal, locked.UserID, passwordHash,
			).Error
			if err != nil {
				return fmt.Errorf("create local identity: %w", err)
			}
		} else {
			result := tx.Exec(
				"UPDATE user_identities SET password_hash = ?, version = version + 1, updated_at = now() WHERE id = ? AND version = ?",
				passwordHash, identity.ID, identity.Version,
			)
			if result.Error != nil {
				return fmt.Errorf("update password hash: %w", result.Error)
			}
			if result.RowsAffected == 0 {
				return fmt.Errorf("update password hash: the identity changed concurrently")
			}
		}

		if err := tx.Exec(
			"UPDATE users SET status = ?, version = version + 1, updated_at = now() WHERE id = ? AND status = ?",
			StatusActive, locked.UserID, statusInvited,
		).Error; err != nil {
			return fmt.Errorf("activate user: %w", err)
		}

		consumed := tx.Exec(
			"UPDATE password_reset_tokens SET used_at = now() WHERE id = ? AND used_at IS NULL", locked.ID,
		)
		if consumed.Error != nil {
			return fmt.Errorf("consume reset token: %w", consumed.Error)
		}
		if consumed.RowsAffected == 0 {
			return ErrInvalidResetToken
		}

		sessions := tx.Exec("DELETE FROM sessions WHERE user_id = ?", locked.UserID)
		if sessions.Error != nil {
			return fmt.Errorf("delete sessions: %w", sessions.Error)
		}

		return audit.Record(tx, audit.Event{
			EventName:     "simple_siem.auth.password_reset_used",
			EventCategory: "AUTHENTICATION",
			EventOutcome:  "SUCCESS",
			ActorType:     "ANONYMOUS",
			RequestID:     client.RequestID,
			SourceIP:      normalizedIP(client.IP),
			TargetType:    "USER",
			TargetID:      locked.UserID,
			Action:        "use_reset_token",
			Changes:       map[string]any{"revokedCount": sessions.RowsAffected},
		})
	})
}

func loadUser(database *gorm.DB, userID string) (User, error) {
	var user User
	err := database.Where("id = ?", userID).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("load user: %w", err)
	}
	return user, nil
}

func loadUserWithRoles(database *gorm.DB, userID string) (UserWithRoles, error) {
	var row userWithRoleNames
	err := database.Raw(selectUsersWithRoleNames+`
		WHERE users.id = ?
		GROUP BY users.id`, userID).Scan(&row).Error
	if err != nil {
		return UserWithRoles{}, fmt.Errorf("load user: %w", err)
	}
	if row.ID == "" {
		return UserWithRoles{}, ErrUserNotFound
	}
	return UserWithRoles{User: row.User, Roles: splitRoleNames(row.RoleNames)}, nil
}

func splitRoleNames(names string) []string {
	if names == "" {
		return []string{}
	}
	return strings.Split(names, ",")
}

// uniqueRoles collapses duplicates and sorts the result, so stored and audited
// role lists have one stable order.
func uniqueRoles(roles []string) []string {
	unique := make([]string, 0, len(roles))
	for _, role := range roles {
		if !slices.Contains(unique, role) {
			unique = append(unique, role)
		}
	}
	slices.Sort(unique)
	return unique
}

func ensureRolesExist(database *gorm.DB, roles []string) error {
	if len(roles) == 0 {
		return nil
	}
	var known []string
	if err := database.Raw("SELECT name FROM roles").Scan(&known).Error; err != nil {
		return fmt.Errorf("load roles: %w", err)
	}
	for _, role := range roles {
		if !slices.Contains(known, role) {
			return ErrUnknownRole
		}
	}
	return nil
}

// userMutationConflict tells a version-checked update's zero rows apart: the
// user is gone, or another writer bumped the version first.
func userMutationConflict(database *gorm.DB, userID string) error {
	var count int64
	if err := database.Raw(
		"SELECT count(*) FROM users WHERE id = ?", userID,
	).Scan(&count).Error; err != nil {
		return fmt.Errorf("check user: %w", err)
	}
	if count == 0 {
		return ErrUserNotFound
	}
	return ErrVersionConflict
}

func userHasRole(database *gorm.DB, userID, role string) (bool, error) {
	var count int64
	err := database.Raw(
		"SELECT count(*) FROM user_roles WHERE user_id = ? AND role_name = ?", userID, role,
	).Scan(&count).Error
	if err != nil {
		return false, fmt.Errorf("read user roles: %w", err)
	}
	return count > 0, nil
}

// bumpUserVersion records a role change on the user row, so clients holding a
// stale version see a conflict on their next mutation.
func bumpUserVersion(database *gorm.DB, userID string) error {
	result := database.Exec(
		"UPDATE users SET version = version + 1, updated_at = now() WHERE id = ?", userID,
	)
	if result.Error != nil {
		return fmt.Errorf("bump user version: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return userMutationConflict(database, userID)
	}
	return nil
}

// lockLastAdminGuard serializes the rare actions that can remove the last
// active admin, so two of them cannot both see another admin and both commit.
func lockLastAdminGuard(database *gorm.DB) error {
	if err := database.Exec(
		"SELECT pg_advisory_xact_lock(hashtext(?))", lastAdminLockName,
	).Error; err != nil {
		return fmt.Errorf("lock last admin: %w", err)
	}
	return nil
}

func otherActiveAdmins(database *gorm.DB, userID string) (int64, error) {
	var count int64
	err := database.Raw(`
		SELECT count(*) FROM users
		JOIN user_roles ON user_roles.user_id = users.id
		WHERE user_roles.role_name = ? AND users.status = ? AND users.id <> ?`,
		RoleAdmin, StatusActive, userID,
	).Scan(&count).Error
	if err != nil {
		return 0, fmt.Errorf("count active admins: %w", err)
	}
	return count, nil
}

// userAuditEvent fills the fields every admin mutation of a user shares.
func userAuditEvent(actor Actor, client ClientInfo, category string) audit.Event {
	actorID := actor.UserID
	sessionID := actor.SessionID
	return audit.Event{
		EventCategory:  category,
		EventOutcome:   "SUCCESS",
		ActorType:      "USER",
		ActorID:        &actorID,
		ActorSessionID: &sessionID,
		RequestID:      client.RequestID,
		SourceIP:       normalizedIP(client.IP),
		TargetType:     "USER",
	}
}
