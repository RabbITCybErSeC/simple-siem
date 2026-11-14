package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"gorm.io/gorm"
)

const (
	failureWindowDuration = 15 * time.Minute
	emailFailureLimit     = 10
	addressFailureLimit   = 30
	maxLoginPasswordRunes = 128
	maxUserAgentBytes     = 512
	maxDisplayNameRunes   = 200
)

type failureWindow struct {
	Attempts int64      `gorm:"column:attempts"`
	Oldest   *time.Time `gorm:"column:oldest"`
	Now      time.Time  `gorm:"column:now"`
}

type createdSession struct {
	ID                string    `gorm:"column:id"`
	AbsoluteExpiresAt time.Time `gorm:"column:absolute_expires_at"`
}

type sessionActor struct {
	SessionID       string `gorm:"column:session_id"`
	UserID          string `gorm:"column:user_id"`
	Email           string `gorm:"column:email"`
	DisplayName     string `gorm:"column:display_name"`
	SlideDue        bool   `gorm:"column:slide_due"`
	RoleNames       string `gorm:"column:role_names"`
	PermissionNames string `gorm:"column:permission_names"`
}

type localAccount struct {
	Identity
	Status string `gorm:"column:status"`
}

// Service owns logins, sessions, and local accounts.
type Service struct {
	database *gorm.DB
	settings Settings
	provider IdentityProvider
	logger   *slog.Logger
}

// LocalProvider checks a password against a local identity.
type LocalProvider struct {
	database  *gorm.DB
	dummyHash string
	logger    *slog.Logger
}

func NewService(ctx context.Context, database *gorm.DB, settings Settings, logger *slog.Logger) (*Service, error) {
	dummyPassword := make([]byte, 32)
	if _, err := rand.Read(dummyPassword); err != nil {
		return nil, fmt.Errorf("generate dummy password: %w", err)
	}
	dummyHash, err := HashPassword(ctx, base64.RawStdEncoding.EncodeToString(dummyPassword))
	if err != nil {
		return nil, fmt.Errorf("hash dummy password: %w", err)
	}

	provider := &LocalProvider{database: database, dummyHash: dummyHash, logger: logger}
	return &Service{
		database: database,
		settings: settings,
		provider: provider,
		logger:   logger,
	}, nil
}

// NormalizeEmail trims spaces and accepts only plain ASCII addresses, so Go
// and PostgreSQL agree on the stored form.
func NormalizeEmail(email string) (string, error) {
	trimmed := strings.TrimSpace(email)
	if len(trimmed) < 3 || len(trimmed) > 254 {
		return "", ErrInvalidEmail
	}
	for index := 0; index < len(trimmed); index++ {
		if trimmed[index] < '!' || trimmed[index] > '~' {
			return "", ErrInvalidEmail
		}
	}
	normalized := strings.ToLower(trimmed)
	address, err := mail.ParseAddress(normalized)
	if err != nil || address.Address != normalized {
		return "", ErrInvalidEmail
	}
	return normalized, nil
}

// NormalizeDisplayName trims spaces and accepts 1 to 200 runes without
// control characters.
func NormalizeDisplayName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if count := utf8.RuneCountInString(trimmed); count < 1 || count > maxDisplayNameRunes {
		return "", ErrInvalidDisplayName
	}
	if strings.ContainsFunc(trimmed, unicode.IsControl) {
		return "", ErrInvalidDisplayName
	}
	return trimmed, nil
}

func (service *Service) Providers() []string {
	return []string{service.provider.Name()}
}

func (service *Service) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	if err := service.database.WithContext(ctx).Model(&User{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

func (service *Service) CreateAdmin(ctx context.Context, email, displayName, password string) (User, error) {
	normalizedEmail, err := NormalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	normalizedDisplayName, err := NormalizeDisplayName(displayName)
	if err != nil {
		return User{}, err
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	passwordHash, err := HashPassword(ctx, password)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}

	var user User
	err = service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		user = User{Email: normalizedEmail, DisplayName: normalizedDisplayName, Status: StatusActive}
		if err := tx.Create(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				return ErrUserExists
			}
			return fmt.Errorf("create user: %w", err)
		}

		identity := Identity{
			UserID:       user.ID,
			Provider:     ProviderLocal,
			Subject:      user.ID,
			PasswordHash: &passwordHash,
		}
		if err := tx.Create(&identity).Error; err != nil {
			return fmt.Errorf("create identity: %w", err)
		}
		if err := tx.Exec(
			"INSERT INTO user_roles (user_id, role_name) VALUES (?, ?)", user.ID, RoleAdmin,
		).Error; err != nil {
			return fmt.Errorf("assign admin role: %w", err)
		}

		return audit.Record(tx, audit.Event{
			EventName:     "simple_siem.user.created",
			EventCategory: "USER",
			EventOutcome:  "SUCCESS",
			ActorType:     "SYSTEM",
			TargetType:    "USER",
			TargetID:      user.ID,
			Action:        "create",
			Changes: map[string]any{
				"email": normalizedEmail,
				"roles": []string{RoleAdmin},
				"via":   "cli",
			},
		})
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (service *Service) ResetPassword(ctx context.Context, email, password string) (sessionsRevoked int64, err error) {
	normalizedEmail, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	if err := ValidatePassword(password); err != nil {
		return 0, err
	}
	passwordHash, err := HashPassword(ctx, password)
	if err != nil {
		return 0, fmt.Errorf("hash password: %w", err)
	}

	err = service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		err := tx.Where("email = ?", normalizedEmail).First(&user).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		if err != nil {
			return fmt.Errorf("find user: %w", err)
		}

		var identity Identity
		if err := tx.Where("user_id = ? AND provider = ?", user.ID, ProviderLocal).First(&identity).Error; err != nil {
			return fmt.Errorf("find local identity: %w", err)
		}
		result := tx.Model(&Identity{}).
			Where("id = ? AND version = ?", identity.ID, identity.Version).
			Updates(map[string]any{
				"password_hash": passwordHash,
				"updated_at":    gorm.Expr("now()"),
				"version":       gorm.Expr("version + 1"),
			})
		if result.Error != nil {
			return fmt.Errorf("update password hash: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("update password hash: the identity changed concurrently")
		}

		result = tx.Exec("DELETE FROM sessions WHERE user_id = ?", user.ID)
		if result.Error != nil {
			return fmt.Errorf("delete sessions: %w", result.Error)
		}
		sessionsRevoked = result.RowsAffected

		return audit.Record(tx, audit.Event{
			EventName:     "simple_siem.auth.password_reset",
			EventCategory: "AUTHENTICATION",
			EventOutcome:  "SUCCESS",
			ActorType:     "SYSTEM",
			TargetType:    "USER",
			TargetID:      user.ID,
			Action:        "reset_password",
			Changes: map[string]any{
				"via":          "cli",
				"revokedCount": sessionsRevoked,
			},
		})
	})
	if err != nil {
		return 0, err
	}
	return sessionsRevoked, nil
}

func (service *Service) Login(ctx context.Context, request LoginRequest, client ClientInfo) (result LoginResult, err error) {
	client.IP = normalizedIP(client.IP)
	normalizedEmail, normalizeError := NormalizeEmail(request.Email)
	failureEmail := ""
	providerRequest := request
	if normalizeError == nil {
		failureEmail = normalizedEmail
	} else {
		providerRequest.Email = ""
	}
	hashedEmail := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(request.Email))))

	// The attempt is recorded before the count so concurrent logins see each
	// other's rows. The email lock then the address lock serializes the
	// decision without holding anything across password hashing; the order is
	// fixed so two logins cannot deadlock. A contended lock is the attack case,
	// so it ends the login instead of queueing on a pooled connection.
	var attemptID string
	var emailWindow, addressWindow failureWindow
	limited := false
	lockBusy := false
	err = service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lockKeys := []int64{
			loginLockKey("login-email:", hex.EncodeToString(hashedEmail[:])),
			loginLockKey("login-ip:", client.IP.String()),
		}
		for _, key := range lockKeys {
			var acquired bool
			if err := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", key).Scan(&acquired).Error; err != nil {
				return fmt.Errorf("lock login rate limit: %w", err)
			}
			if !acquired {
				lockBusy = true
				return nil
			}
		}

		attempt := LoginAttempt{EmailHash: hashedEmail[:], ClientIP: client.IP, Succeeded: false}
		if err := tx.Create(&attempt).Error; err != nil {
			return fmt.Errorf("record login attempt: %w", err)
		}
		attemptID = attempt.ID

		var err error
		emailWindow, err = recentFailures(tx, "email_hash = ?", hashedEmail[:])
		if err != nil {
			return fmt.Errorf("count failed logins for the email: %w", err)
		}
		addressWindow, err = recentFailures(tx, "client_ip = ?", client.IP.String())
		if err != nil {
			return fmt.Errorf("count failed logins for the address: %w", err)
		}
		if emailWindow.Attempts > emailFailureLimit || addressWindow.Attempts > addressFailureLimit {
			limited = true
			if err := tx.Exec("DELETE FROM login_attempts WHERE id = ?", attemptID).Error; err != nil {
				return fmt.Errorf("discard rate-limited login attempt: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	if lockBusy {
		service.logRateLimited(client)
		return LoginResult{}, RateLimitedError{RetryAfter: time.Second}
	}
	if limited {
		retryAfter := time.Duration(0)
		if emailWindow.Attempts > emailFailureLimit {
			retryAfter = windowRetryAfter(emailWindow)
		}
		if addressWindow.Attempts > addressFailureLimit {
			if addressRetryAfter := windowRetryAfter(addressWindow); addressRetryAfter > retryAfter {
				retryAfter = addressRetryAfter
			}
		}
		service.logRateLimited(client)
		return LoginResult{}, RateLimitedError{RetryAfter: retryAfter}
	}

	// Only a real credential failure keeps the attempt row; every other
	// outcome after this point is an infrastructure error, not a login result.
	defer func() {
		if err != nil && !errors.Is(err, ErrInvalidCredentials) {
			service.discardLoginAttempt(ctx, attemptID)
		}
	}()

	identity, err := service.provider.Authenticate(ctx, providerRequest)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return LoginResult{}, service.recordFailedLogin(ctx, failureEmail, client, "invalid_credentials")
		}
		return LoginResult{}, fmt.Errorf("authenticate login: %w", err)
	}

	var user User
	err = service.database.WithContext(ctx).Raw(`
		SELECT users.* FROM users
		JOIN user_identities ON user_identities.user_id = users.id
		WHERE user_identities.provider = ? AND user_identities.subject = ? AND users.status = ?`,
		identity.Provider, identity.Subject, StatusActive,
	).Scan(&user).Error
	if err != nil {
		return LoginResult{}, fmt.Errorf("find login user: %w", err)
	}
	if user.ID == "" {
		return LoginResult{}, service.recordFailedLogin(ctx, failureEmail, client, "invalid_credentials")
	}

	return service.startSession(ctx, user, identity, attemptID, client)
}

// discardLoginAttempt removes the row of a login that ended in an
// infrastructure error, using a context that survives client cancellation.
func (service *Service) discardLoginAttempt(ctx context.Context, attemptID string) {
	if err := service.database.WithContext(context.WithoutCancel(ctx)).Exec(
		"DELETE FROM login_attempts WHERE id = ?", attemptID,
	).Error; err != nil {
		service.logger.Warn("discard login attempt failed", "attempt_id", attemptID, "error", err)
	}
}

func (service *Service) Authenticate(ctx context.Context, token string) (Actor, error) {
	rawToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(rawToken) != 32 {
		return Actor{}, ErrUnauthenticated
	}
	tokenHash := sha256.Sum256(rawToken)

	// The roles.name and permissions.name check constraints keep the comma out
	// of every role name and permission, so the aggregate delimiters below are
	// unambiguous. Joining permissions multiplies the rows per role, so both
	// aggregates are DISTINCT.
	var session sessionActor
	err = service.database.WithContext(ctx).Raw(`
		SELECT sessions.id::text AS session_id, users.id::text AS user_id, users.email,
		       users.display_name, sessions.last_used_at < now() - interval '1 minute' AS slide_due,
		       COALESCE(string_agg(DISTINCT user_roles.role_name, ',' ORDER BY user_roles.role_name), '') AS role_names,
		       COALESCE(string_agg(DISTINCT role_permissions.permission, ',' ORDER BY role_permissions.permission), '') AS permission_names
		FROM sessions
		JOIN users ON users.id = sessions.user_id
		LEFT JOIN user_roles ON user_roles.user_id = users.id
		LEFT JOIN role_permissions ON role_permissions.role_name = user_roles.role_name
		WHERE sessions.token_hash = ? AND sessions.idle_expires_at > now()
		  AND sessions.absolute_expires_at > now() AND users.status = ?
		GROUP BY sessions.id, users.id`,
		tokenHash[:], StatusActive,
	).Scan(&session).Error
	if err != nil {
		return Actor{}, fmt.Errorf("find session: %w", err)
	}
	if session.SessionID == "" {
		return Actor{}, ErrUnauthenticated
	}

	var roles []string
	if session.RoleNames != "" {
		roles = strings.Split(session.RoleNames, ",")
	}
	var permissions []string
	if session.PermissionNames != "" {
		permissions = strings.Split(session.PermissionNames, ",")
	}

	// shortcut: one write per minute per session; move to a batched touch if session writes show up in Phase 7 profiles.
	if session.SlideDue {
		err = service.database.WithContext(ctx).Exec(`
			UPDATE sessions
			SET last_used_at = now(), idle_expires_at = LEAST(now() + make_interval(secs => ?), absolute_expires_at)
			WHERE id = ? AND last_used_at < now() - interval '1 minute'`,
			service.settings.IdleTimeout.Seconds(), session.SessionID,
		).Error
		if err != nil {
			return Actor{}, fmt.Errorf("slide session idle expiry: %w", err)
		}
	}

	return Actor{
		UserID:      session.UserID,
		SessionID:   session.SessionID,
		Email:       session.Email,
		DisplayName: session.DisplayName,
		Roles:       roles,
		Permissions: permissions,
	}, nil
}

func (service *Service) CurrentUser(ctx context.Context, actor Actor) (User, []string, error) {
	var user User
	err := service.database.WithContext(ctx).Where("id = ?", actor.UserID).First(&user).Error
	if err != nil {
		return User{}, nil, fmt.Errorf("load current user: %w", err)
	}
	return user, actor.Roles, nil
}

func (service *Service) Logout(ctx context.Context, actor Actor, client ClientInfo) error {
	client.IP = normalizedIP(client.IP)
	return service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Exec("DELETE FROM sessions WHERE id = ?", actor.SessionID)
		if result.Error != nil {
			return fmt.Errorf("delete session: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return ErrUnauthenticated
		}

		actorID := actor.UserID
		sessionID := actor.SessionID
		return audit.Record(tx, audit.Event{
			EventName:      "simple_siem.auth.logout",
			EventCategory:  "AUTHENTICATION",
			EventOutcome:   "SUCCESS",
			ActorType:      "USER",
			ActorID:        &actorID,
			ActorSessionID: &sessionID,
			RequestID:      client.RequestID,
			SourceIP:       client.IP,
			TargetType:     "SESSION",
			TargetID:       actor.SessionID,
			Action:         "logout",
		})
	})
}

func (provider *LocalProvider) Name() string {
	return ProviderLocal
}

func (provider *LocalProvider) Authenticate(ctx context.Context, request LoginRequest) (ExternalIdentity, error) {
	if utf8.RuneCountInString(request.Password) > maxLoginPasswordRunes {
		if _, err := VerifyPassword(ctx, "", provider.dummyHash); err != nil {
			return ExternalIdentity{}, fmt.Errorf("verify dummy password: %w", err)
		}
		return ExternalIdentity{}, ErrInvalidCredentials
	}

	var account localAccount
	normalizedEmail, normalizeError := NormalizeEmail(request.Email)
	if normalizeError == nil {
		err := provider.database.WithContext(ctx).Raw(`
			SELECT user_identities.*, users.status FROM user_identities
			JOIN users ON users.id = user_identities.user_id
			WHERE users.email = ? AND user_identities.provider = ?`,
			normalizedEmail, ProviderLocal,
		).Scan(&account).Error
		if err != nil {
			return ExternalIdentity{}, fmt.Errorf("find local identity: %w", err)
		}
	}

	if account.ID == "" || account.PasswordHash == nil {
		if _, err := VerifyPassword(ctx, request.Password, provider.dummyHash); err != nil {
			return ExternalIdentity{}, fmt.Errorf("verify dummy password: %w", err)
		}
		return ExternalIdentity{}, ErrInvalidCredentials
	}

	matches, err := VerifyPassword(ctx, request.Password, *account.PasswordHash)
	if err != nil {
		provider.logger.Warn("stored password hash is malformed", "user_id", account.UserID, "error", err)
		return ExternalIdentity{}, fmt.Errorf("verify stored password: %w", err)
	}
	if !matches {
		return ExternalIdentity{}, ErrInvalidCredentials
	}

	credentialVersion := account.Version
	if account.Status == StatusActive && needsRehash(*account.PasswordHash) {
		rehashed, lostRace := provider.rehashPassword(ctx, account.Identity, request.Password)
		switch {
		case rehashed:
			credentialVersion++
		case lostRace:
			reloadedVersion, err := provider.verifyReloadedIdentity(ctx, account.ID, request.Password)
			if err != nil {
				return ExternalIdentity{}, err
			}
			credentialVersion = reloadedVersion
		}
	}
	return ExternalIdentity{
		Provider:          ProviderLocal,
		Subject:           account.UserID,
		CredentialVersion: credentialVersion,
	}, nil
}

func (provider *LocalProvider) rehashPassword(ctx context.Context, identity Identity, password string) (rehashed bool, lostRace bool) {
	freshHash, err := HashPassword(ctx, password)
	if err != nil {
		provider.logger.Warn("rehash password failed", "user_id", identity.UserID, "error", err)
		return false, false
	}
	result := provider.database.WithContext(ctx).
		Model(&Identity{}).
		Where("id = ? AND version = ?", identity.ID, identity.Version).
		Updates(map[string]any{
			"password_hash": freshHash,
			"updated_at":    gorm.Expr("now()"),
			"version":       gorm.Expr("version + 1"),
		})
	if result.Error != nil {
		provider.logger.Warn("rehash password failed", "user_id", identity.UserID, "error", result.Error)
		return false, false
	}
	if result.RowsAffected == 0 {
		provider.logger.Warn("rehash password skipped: identity changed", "user_id", identity.UserID)
		return false, true
	}
	return true, false
}

// verifyReloadedIdentity checks the password against a hash reloaded after a
// lost rehash race and returns the loaded version.
func (provider *LocalProvider) verifyReloadedIdentity(ctx context.Context, identityID, password string) (int, error) {
	var reloaded Identity
	if err := provider.database.WithContext(ctx).Where("id = ?", identityID).First(&reloaded).Error; err != nil {
		return 0, fmt.Errorf("reload local identity: %w", err)
	}
	if reloaded.PasswordHash == nil {
		return 0, ErrInvalidCredentials
	}
	matches, err := VerifyPassword(ctx, password, *reloaded.PasswordHash)
	if err != nil {
		provider.logger.Warn("stored password hash is malformed", "user_id", reloaded.UserID, "error", err)
		return 0, fmt.Errorf("verify stored password: %w", err)
	}
	if !matches {
		return 0, ErrInvalidCredentials
	}
	return reloaded.Version, nil
}

func (service *Service) recordFailedLogin(ctx context.Context, email string, client ClientInfo, reason string) error {
	targetID := "unknown"
	if email != "" {
		var user User
		err := service.database.WithContext(ctx).Select("id").Where("email = ?", email).First(&user).Error
		if err == nil {
			targetID = user.ID
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("find failed login target: %w", err)
		}
	}

	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return recordFailedLoginEvent(tx, targetID, client, reason)
	})
	if err != nil {
		return fmt.Errorf("record failed login: %w", err)
	}
	return ErrInvalidCredentials
}

func recordFailedLoginEvent(tx *gorm.DB, targetID string, client ClientInfo, reason string) error {
	return audit.Record(tx, audit.Event{
		EventName:     "simple_siem.auth.login",
		EventCategory: "AUTHENTICATION",
		EventOutcome:  "FAILED",
		ActorType:     "ANONYMOUS",
		RequestID:     client.RequestID,
		SourceIP:      client.IP,
		TargetType:    "USER",
		TargetID:      targetID,
		Action:        "login",
		Changes:       map[string]any{"reason": reason},
	})
}

func (service *Service) startSession(ctx context.Context, user User, identity ExternalIdentity, attemptID string, client ClientInfo) (LoginResult, error) {
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return LoginResult{}, fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256(rawToken)

	var session createdSession
	var roles []string
	credentialRejected := false
	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var lockedIdentity struct {
			Version *int `gorm:"column:version"`
		}
		err := tx.Raw(
			"SELECT version FROM user_identities WHERE provider = ? AND subject = ? FOR UPDATE",
			identity.Provider, identity.Subject,
		).Scan(&lockedIdentity).Error
		if err != nil {
			return fmt.Errorf("lock login identity: %w", err)
		}
		if lockedIdentity.Version == nil {
			credentialRejected = true
			return recordFailedLoginEvent(tx, user.ID, client, "identity_missing")
		}
		if *lockedIdentity.Version != identity.CredentialVersion {
			credentialRejected = true
			return recordFailedLoginEvent(tx, user.ID, client, "credential_changed")
		}

		err = tx.Raw(`
			INSERT INTO sessions (user_id, token_hash, auth_provider, idle_expires_at, absolute_expires_at, client_ip, user_agent)
			VALUES (?, ?, ?, now() + make_interval(secs => ?), now() + make_interval(secs => ?), ?, ?)
			RETURNING id::text AS id, absolute_expires_at`,
			user.ID,
			tokenHash[:],
			identity.Provider,
			service.settings.IdleTimeout.Seconds(),
			service.settings.AbsoluteLifetime.Seconds(),
			client.IP,
			truncateUserAgent(client.UserAgent),
		).Scan(&session).Error
		if err != nil {
			return fmt.Errorf("create session: %w", err)
		}

		if err := tx.Exec(
			"UPDATE login_attempts SET succeeded = true WHERE id = ?", attemptID,
		).Error; err != nil {
			return fmt.Errorf("mark login attempt succeeded: %w", err)
		}
		if err := tx.Exec("UPDATE users SET last_login_at = now() WHERE id = ?", user.ID).Error; err != nil {
			return fmt.Errorf("update last login: %w", err)
		}
		if err := tx.Exec(
			"UPDATE user_identities SET last_used_at = now() WHERE user_id = ? AND provider = ?", user.ID, identity.Provider,
		).Error; err != nil {
			return fmt.Errorf("update identity last used: %w", err)
		}
		roles, err = loadRoles(tx, user.ID)
		if err != nil {
			return err
		}

		actorID := user.ID
		sessionID := session.ID
		return audit.Record(tx, audit.Event{
			EventName:      "simple_siem.auth.login",
			EventCategory:  "AUTHENTICATION",
			EventOutcome:   "SUCCESS",
			ActorType:      "USER",
			ActorID:        &actorID,
			ActorSessionID: &sessionID,
			RequestID:      client.RequestID,
			SourceIP:       client.IP,
			TargetType:     "USER",
			TargetID:       user.ID,
			Action:         "login",
			Changes:        map[string]any{"provider": identity.Provider},
		})
	})
	if err != nil {
		return LoginResult{}, err
	}
	if credentialRejected {
		return LoginResult{}, ErrInvalidCredentials
	}
	return LoginResult{Token: token, ExpiresAt: session.AbsoluteExpiresAt, User: user, Roles: roles}, nil
}

func recentFailures(database *gorm.DB, condition string, value any) (failureWindow, error) {
	var window failureWindow
	err := database.Raw(
		"SELECT count(*) AS attempts, min(created_at) AS oldest, now() AS now "+
			"FROM login_attempts WHERE NOT succeeded AND created_at > now() - make_interval(secs => ?) AND "+condition,
		failureWindowDuration.Seconds(), value,
	).Scan(&window).Error
	if err != nil {
		return failureWindow{}, err
	}
	return window, nil
}

func (service *Service) logRateLimited(client ClientInfo) {
	service.logger.Warn(
		"login rate limited",
		"request_id", client.RequestID,
		"client_address", client.IP.String(),
	)
}

// loginLockKey derives one bigint advisory-lock key from a namespaced value.
func loginLockKey(namespace, value string) int64 {
	digest := sha256.Sum256([]byte(namespace + value))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func windowRetryAfter(window failureWindow) time.Duration {
	if window.Oldest == nil {
		return time.Second
	}
	retryAfter := window.Oldest.Add(failureWindowDuration).Sub(window.Now)
	if retryAfter < time.Second {
		return time.Second
	}
	return ((retryAfter + time.Second - 1) / time.Second) * time.Second
}

func truncateUserAgent(userAgent string) string {
	userAgent = strings.ToValidUTF8(userAgent, "")
	if len(userAgent) <= maxUserAgentBytes {
		return userAgent
	}
	truncated := userAgent[:maxUserAgentBytes]
	for !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

// normalizedIP keeps IPv4 addresses in their 4-byte form, so PostgreSQL does
// not store them as IPv4-mapped IPv6 addresses.
func normalizedIP(address net.IP) net.IP {
	if ipv4 := address.To4(); ipv4 != nil {
		return ipv4
	}
	return address
}

func loadRoles(database *gorm.DB, userID string) ([]string, error) {
	var roles []string
	if err := database.Raw(
		"SELECT role_name FROM user_roles WHERE user_id = ? ORDER BY role_name", userID,
	).Scan(&roles).Error; err != nil {
		return nil, fmt.Errorf("load user roles: %w", err)
	}
	return roles, nil
}
