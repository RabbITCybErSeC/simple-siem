package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"time"
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
	SessionID   string `gorm:"column:session_id"`
	UserID      string `gorm:"column:user_id"`
	Email       string `gorm:"column:email"`
	DisplayName string `gorm:"column:display_name"`
}

// Service owns logins, sessions, and local accounts.
type Service struct {
	database  *gorm.DB
	settings  Settings
	providers []IdentityProvider
	logger    *slog.Logger
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
		database:  database,
		settings:  settings,
		providers: []IdentityProvider{provider},
		logger:    logger,
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

func (service *Service) Providers() []string {
	return []string{ProviderLocal}
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
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	passwordHash, err := HashPassword(ctx, password)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}

	var user User
	err = service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		user = User{Email: normalizedEmail, DisplayName: displayName, Status: StatusActive}
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

func (service *Service) Login(ctx context.Context, request LoginRequest, client ClientInfo) (LoginResult, error) {
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

	emailWindow, err := service.recentFailures(ctx, "email_hash = ?", hashedEmail[:])
	if err != nil {
		return LoginResult{}, fmt.Errorf("count failed logins for the email: %w", err)
	}
	addressWindow, err := service.recentFailures(ctx, "client_ip = ?", client.IP.String())
	if err != nil {
		return LoginResult{}, fmt.Errorf("count failed logins for the address: %w", err)
	}
	emailLimited := emailWindow.Attempts >= emailFailureLimit
	addressLimited := addressWindow.Attempts >= addressFailureLimit
	if emailLimited || addressLimited {
		retryAfter := time.Duration(0)
		if emailLimited {
			retryAfter = windowRetryAfter(emailWindow)
		}
		if addressLimited {
			if addressRetryAfter := windowRetryAfter(addressWindow); addressRetryAfter > retryAfter {
				retryAfter = addressRetryAfter
			}
		}
		service.logger.Warn(
			"login rate limited",
			"request_id", client.RequestID,
			"client_address", client.IP.String(),
		)
		return LoginResult{}, RateLimitedError{RetryAfter: retryAfter}
	}

	identity, err := service.providers[0].Authenticate(ctx, providerRequest)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return LoginResult{}, service.recordFailedLogin(ctx, failureEmail, hashedEmail, client)
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
		return LoginResult{}, service.recordFailedLogin(ctx, failureEmail, hashedEmail, client)
	}

	return service.startSession(ctx, user, identity.Provider, hashedEmail, client)
}

func (service *Service) Authenticate(ctx context.Context, token string) (Actor, error) {
	rawToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(rawToken) != 32 {
		return Actor{}, ErrUnauthenticated
	}
	tokenHash := sha256.Sum256(rawToken)

	var session sessionActor
	err = service.database.WithContext(ctx).Raw(`
		SELECT sessions.id::text AS session_id, users.id::text AS user_id, users.email, users.display_name
		FROM sessions
		JOIN users ON users.id = sessions.user_id
		WHERE sessions.token_hash = ? AND sessions.idle_expires_at > now()
		  AND sessions.absolute_expires_at > now() AND users.status = ?`,
		tokenHash[:], StatusActive,
	).Scan(&session).Error
	if err != nil {
		return Actor{}, fmt.Errorf("find session: %w", err)
	}
	if session.SessionID == "" {
		return Actor{}, ErrUnauthenticated
	}

	// shortcut: one write per minute per session; move to a batched touch if session writes show up in Phase 7 profiles.
	err = service.database.WithContext(ctx).Exec(`
		UPDATE sessions
		SET last_used_at = now(), idle_expires_at = LEAST(now() + make_interval(secs => ?), absolute_expires_at)
		WHERE id = ? AND last_used_at < now() - interval '1 minute'`,
		service.settings.IdleTimeout.Seconds(), session.SessionID,
	).Error
	if err != nil {
		return Actor{}, fmt.Errorf("slide session idle expiry: %w", err)
	}

	roles, err := loadRoles(service.database.WithContext(ctx), session.UserID)
	if err != nil {
		return Actor{}, err
	}

	return Actor{
		UserID:      session.UserID,
		SessionID:   session.SessionID,
		Email:       session.Email,
		DisplayName: session.DisplayName,
		Roles:       roles,
	}, nil
}

func (service *Service) CurrentUser(ctx context.Context, actor Actor) (User, []string, error) {
	var user User
	err := service.database.WithContext(ctx).Where("id = ?", actor.UserID).First(&user).Error
	if err != nil {
		return User{}, nil, fmt.Errorf("load current user: %w", err)
	}

	roles, err := loadRoles(service.database.WithContext(ctx), actor.UserID)
	if err != nil {
		return User{}, nil, err
	}
	return user, roles, nil
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

func (provider *LocalProvider) Authenticate(ctx context.Context, request LoginRequest) (ExternalIdentity, error) {
	if utf8.RuneCountInString(request.Password) > maxLoginPasswordRunes {
		if _, err := VerifyPassword(ctx, "", provider.dummyHash); err != nil {
			return ExternalIdentity{}, fmt.Errorf("verify dummy password: %w", err)
		}
		return ExternalIdentity{}, ErrInvalidCredentials
	}

	var identity Identity
	normalizedEmail, normalizeError := NormalizeEmail(request.Email)
	if normalizeError == nil {
		err := provider.database.WithContext(ctx).Raw(`
			SELECT user_identities.* FROM user_identities
			JOIN users ON users.id = user_identities.user_id
			WHERE users.email = ? AND user_identities.provider = ?`,
			normalizedEmail, ProviderLocal,
		).Scan(&identity).Error
		if err != nil {
			return ExternalIdentity{}, fmt.Errorf("find local identity: %w", err)
		}
	}

	if identity.ID == "" || identity.PasswordHash == nil {
		if _, err := VerifyPassword(ctx, request.Password, provider.dummyHash); err != nil {
			return ExternalIdentity{}, fmt.Errorf("verify dummy password: %w", err)
		}
		return ExternalIdentity{}, ErrInvalidCredentials
	}

	matches, err := VerifyPassword(ctx, request.Password, *identity.PasswordHash)
	if err != nil {
		provider.logger.Warn("stored password hash is malformed", "user_id", identity.UserID, "error", err)
		return ExternalIdentity{}, fmt.Errorf("verify stored password: %w", err)
	}
	if !matches {
		return ExternalIdentity{}, ErrInvalidCredentials
	}

	if needsRehash(*identity.PasswordHash) {
		provider.rehashPassword(ctx, identity, request.Password)
	}
	return ExternalIdentity{Provider: ProviderLocal, Subject: identity.UserID}, nil
}

func (provider *LocalProvider) rehashPassword(ctx context.Context, identity Identity, password string) {
	freshHash, err := HashPassword(ctx, password)
	if err != nil {
		provider.logger.Warn("rehash password failed", "user_id", identity.UserID, "error", err)
		return
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
		return
	}
	if result.RowsAffected == 0 {
		provider.logger.Warn("rehash password skipped: identity changed", "user_id", identity.UserID)
	}
}

func (service *Service) recordFailedLogin(ctx context.Context, email string, hashedEmail [32]byte, client ClientInfo) error {
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
		attempt := LoginAttempt{EmailHash: hashedEmail[:], ClientIP: client.IP, Succeeded: false}
		if err := tx.Create(&attempt).Error; err != nil {
			return fmt.Errorf("record login attempt: %w", err)
		}
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
			Changes:       map[string]any{"reason": "invalid_credentials"},
		})
	})
	if err != nil {
		return fmt.Errorf("record failed login: %w", err)
	}
	return ErrInvalidCredentials
}

func (service *Service) startSession(ctx context.Context, user User, provider string, hashedEmail [32]byte, client ClientInfo) (LoginResult, error) {
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return LoginResult{}, fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256(rawToken)

	var session createdSession
	var roles []string
	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Raw(`
			INSERT INTO sessions (user_id, token_hash, auth_provider, idle_expires_at, absolute_expires_at, client_ip, user_agent)
			VALUES (?, ?, ?, now() + make_interval(secs => ?), now() + make_interval(secs => ?), ?, ?)
			RETURNING id::text AS id, absolute_expires_at`,
			user.ID,
			tokenHash[:],
			provider,
			service.settings.IdleTimeout.Seconds(),
			service.settings.AbsoluteLifetime.Seconds(),
			client.IP,
			truncateUserAgent(client.UserAgent),
		).Scan(&session).Error
		if err != nil {
			return fmt.Errorf("create session: %w", err)
		}

		attempt := LoginAttempt{EmailHash: hashedEmail[:], ClientIP: client.IP, Succeeded: true}
		if err := tx.Create(&attempt).Error; err != nil {
			return fmt.Errorf("record login attempt: %w", err)
		}
		if err := tx.Exec("UPDATE users SET last_login_at = now() WHERE id = ?", user.ID).Error; err != nil {
			return fmt.Errorf("update last login: %w", err)
		}
		if err := tx.Exec(
			"UPDATE user_identities SET last_used_at = now() WHERE user_id = ? AND provider = ?", user.ID, provider,
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
			Changes:        map[string]any{"provider": provider},
		})
	})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Token: token, ExpiresAt: session.AbsoluteExpiresAt, User: user, Roles: roles}, nil
}

func (service *Service) recentFailures(ctx context.Context, condition string, value any) (failureWindow, error) {
	var window failureWindow
	err := service.database.WithContext(ctx).Raw(
		"SELECT count(*) AS attempts, min(created_at) AS oldest, now() AS now "+
			"FROM login_attempts WHERE NOT succeeded AND created_at > now() - make_interval(secs => ?) AND "+condition,
		failureWindowDuration.Seconds(), value,
	).Scan(&window).Error
	if err != nil {
		return failureWindow{}, err
	}
	return window, nil
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
