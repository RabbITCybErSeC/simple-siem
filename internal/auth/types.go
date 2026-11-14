// Package auth holds users, identities, passwords, and sessions.
package auth

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	ProviderLocal = "local"
	StatusActive  = "ACTIVE"
	RoleAdmin     = "ADMIN"
)

// User is one person who can sign in. The database supplies ID, CreatedAt,
// and UpdatedAt.
type User struct {
	ID          string     `gorm:"column:id;default:uuidv7();->"`
	Email       string     `gorm:"column:email"`
	DisplayName string     `gorm:"column:display_name"`
	Status      string     `gorm:"column:status"`
	OnCall      bool       `gorm:"column:on_call"`
	LastLoginAt *time.Time `gorm:"column:last_login_at"`
	CreatedAt   time.Time  `gorm:"column:created_at;default:now();autoCreateTime:false;->"`
	UpdatedAt   time.Time  `gorm:"column:updated_at;default:now();autoUpdateTime:false;->"`
	Version     int        `gorm:"column:version;default:1"`
}

func (User) TableName() string {
	return "users"
}

// Identity links a user to an authentication provider. The database supplies
// ID, CreatedAt, and UpdatedAt.
type Identity struct {
	ID           string     `gorm:"column:id;default:uuidv7();->"`
	UserID       string     `gorm:"column:user_id"`
	Provider     string     `gorm:"column:provider"`
	Subject      string     `gorm:"column:subject"`
	PasswordHash *string    `gorm:"column:password_hash"`
	LastUsedAt   *time.Time `gorm:"column:last_used_at"`
	CreatedAt    time.Time  `gorm:"column:created_at;default:now();autoCreateTime:false;->"`
	UpdatedAt    time.Time  `gorm:"column:updated_at;default:now();autoUpdateTime:false;->"`
	Version      int        `gorm:"column:version;default:1"`
}

func (Identity) TableName() string {
	return "user_identities"
}

// Session is one bearer token. Only the token hash is stored. The database
// supplies ID, CreatedAt, and LastUsedAt.
type Session struct {
	ID                string    `gorm:"column:id;default:uuidv7();->"`
	UserID            string    `gorm:"column:user_id"`
	TokenHash         []byte    `gorm:"column:token_hash"`
	AuthProvider      string    `gorm:"column:auth_provider"`
	CreatedAt         time.Time `gorm:"column:created_at;default:now();autoCreateTime:false;->"`
	LastUsedAt        time.Time `gorm:"column:last_used_at;default:now();autoCreateTime:false;->"`
	IdleExpiresAt     time.Time `gorm:"column:idle_expires_at"`
	AbsoluteExpiresAt time.Time `gorm:"column:absolute_expires_at"`
	ClientIP          net.IP    `gorm:"column:client_ip"`
	UserAgent         string    `gorm:"column:user_agent"`
}

func (Session) TableName() string {
	return "sessions"
}

// LoginAttempt is one login outcome, kept for rate limiting. The database
// supplies ID and CreatedAt.
type LoginAttempt struct {
	ID        string    `gorm:"column:id;default:uuidv7();->"`
	EmailHash []byte    `gorm:"column:email_hash"`
	ClientIP  net.IP    `gorm:"column:client_ip"`
	Succeeded bool      `gorm:"column:succeeded"`
	CreatedAt time.Time `gorm:"column:created_at;default:now();autoCreateTime:false;->"`
}

func (LoginAttempt) TableName() string {
	return "login_attempts"
}

type LoginRequest struct {
	Email    string
	Password string
}

type ExternalIdentity struct {
	Provider          string
	Subject           string
	CredentialVersion int
}

// IdentityProvider proves who a person is; the Service turns the result into a session.
type IdentityProvider interface {
	Name() string
	Authenticate(ctx context.Context, request LoginRequest) (ExternalIdentity, error)
}

type Actor struct {
	UserID      string
	SessionID   string
	Email       string
	DisplayName string
	Roles       []string
}

type Settings struct {
	IdleTimeout      time.Duration
	AbsoluteLifetime time.Duration
}

type ClientInfo struct {
	IP        net.IP
	UserAgent string
	RequestID string
}

type LoginResult struct {
	Token     string
	ExpiresAt time.Time
	User      User
	Roles     []string
}

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUnauthenticated    = errors.New("authentication required")
	ErrPasswordLength     = errors.New("password must be 12 to 128 characters")
	ErrInvalidEmail       = errors.New("email must be a plain ASCII address of 3 to 254 characters")
	ErrInvalidDisplayName = errors.New("display name must be 1 to 200 characters without control characters")
	ErrUserExists         = errors.New("a user with this email already exists")
	ErrUserNotFound       = errors.New("no user with this email")
)

// RateLimitedError is returned when too many logins failed recently.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (rateLimited RateLimitedError) Error() string {
	return "too many failed logins"
}
