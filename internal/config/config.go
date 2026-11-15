package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentProduction  Environment = "production"

	defaultListen                  = ":8080"
	defaultPublicURL               = "http://localhost:8080"
	defaultShutdownTimeout         = 30 * time.Second
	defaultSessionIdleTimeout      = 30 * time.Minute
	defaultSessionAbsoluteLifetime = 12 * time.Hour
	defaultMaxCasesPerHour         = 50

	environmentVariable             = "SIMPLE_SIEM_ENV"
	databaseURLVariable             = "SIMPLE_SIEM_DATABASE_URL"
	listenVariable                  = "SIMPLE_SIEM_LISTEN"
	trustedProxiesVariable          = "SIMPLE_SIEM_TRUSTED_PROXIES"
	shutdownTimeoutVariable         = "SIMPLE_SIEM_SHUTDOWN_TIMEOUT"
	sessionIdleTimeoutVariable      = "SIMPLE_SIEM_SESSION_IDLE_TIMEOUT"
	sessionAbsoluteLifetimeVariable = "SIMPLE_SIEM_SESSION_ABSOLUTE_LIFETIME"
	maxCasesPerHourVariable         = "SIMPLE_SIEM_MAX_CASES_PER_HOUR"
)

// PublicURLVariable names the environment variable that holds the externally
// reachable base URL of the API.
const PublicURLVariable = "SIMPLE_SIEM_PUBLIC_URL"

type Environment string

type Config struct {
	Environment             Environment
	DatabaseURL             string
	Listen                  string
	PublicURL               string
	TrustedProxies          []string
	ShutdownTimeout         time.Duration
	SessionIdleTimeout      time.Duration
	SessionAbsoluteLifetime time.Duration
	MaxCasesPerHour         int
}

func Load(getenv func(string) string) (Config, error) {
	settings := Config{
		Environment: EnvironmentProduction,
		DatabaseURL: getenv(databaseURLVariable),
		Listen:      getenv(listenVariable),
		PublicURL:   getenv(PublicURLVariable),
	}
	if settings.Listen == "" {
		settings.Listen = defaultListen
	}

	var problems []error

	environment, environmentError := ParseEnvironment(getenv(environmentVariable))
	if environmentError != nil {
		problems = append(problems, environmentError)
	} else {
		settings.Environment = environment
	}

	if settings.DatabaseURL == "" {
		problems = append(problems, fmt.Errorf("%s is required", databaseURLVariable))
	} else if parsed, err := url.Parse(settings.DatabaseURL); err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		// The parse error can contain the URL, and the URL can contain a password.
		problems = append(problems, fmt.Errorf("%s must be a postgres:// URL", databaseURLVariable))
	}

	if settings.PublicURL == "" {
		if settings.Environment == EnvironmentDevelopment {
			settings.PublicURL = defaultPublicURL
		} else {
			problems = append(problems, fmt.Errorf("%s is required outside development", PublicURLVariable))
		}
	} else if parsed, err := url.Parse(settings.PublicURL); err != nil || !parsed.IsAbs() || parsed.Host == "" {
		problems = append(problems, fmt.Errorf("%s must be an absolute URL", PublicURLVariable))
	} else if parsed.User != nil {
		problems = append(problems, fmt.Errorf("%s must not contain user information", PublicURLVariable))
	} else if !isASCII(parsed.Hostname()) {
		problems = append(problems, fmt.Errorf("%s host must be ASCII; use the punycode form", PublicURLVariable))
	} else if settings.Environment != EnvironmentDevelopment && parsed.Scheme != "https" {
		problems = append(problems, fmt.Errorf("%s must use https outside development", PublicURLVariable))
	} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
		problems = append(problems, fmt.Errorf("%s must use http or https", PublicURLVariable))
	}

	if value := getenv(trustedProxiesVariable); value != "" {
		for _, entry := range strings.Split(value, ",") {
			entry = strings.TrimSpace(entry)
			_, addressError := netip.ParseAddr(entry)
			_, prefixError := netip.ParsePrefix(entry)
			if addressError != nil && prefixError != nil {
				problems = append(problems, fmt.Errorf("%s: %q is not an IP address or CIDR range", trustedProxiesVariable, entry))
				continue
			}
			settings.TrustedProxies = append(settings.TrustedProxies, entry)
		}
	}

	if timeout, err := parsePositiveDuration(getenv, shutdownTimeoutVariable, defaultShutdownTimeout); err != nil {
		problems = append(problems, err)
	} else {
		settings.ShutdownTimeout = timeout
	}

	idleTimeout, idleError := parsePositiveDuration(getenv, sessionIdleTimeoutVariable, defaultSessionIdleTimeout)
	absoluteLifetime, absoluteError := parsePositiveDuration(getenv, sessionAbsoluteLifetimeVariable, defaultSessionAbsoluteLifetime)
	if idleError != nil {
		problems = append(problems, idleError)
	}
	if absoluteError != nil {
		problems = append(problems, absoluteError)
	}
	if idleError == nil && absoluteError == nil && idleTimeout > absoluteLifetime {
		problems = append(problems, fmt.Errorf("%s must not exceed %s", sessionIdleTimeoutVariable, sessionAbsoluteLifetimeVariable))
	}
	settings.SessionIdleTimeout = idleTimeout
	settings.SessionAbsoluteLifetime = absoluteLifetime

	maxCasesPerHour, maxCasesPerHourError := parsePositiveInt(getenv, maxCasesPerHourVariable, defaultMaxCasesPerHour)
	if maxCasesPerHourError != nil {
		problems = append(problems, maxCasesPerHourError)
	}
	settings.MaxCasesPerHour = maxCasesPerHour

	if err := errors.Join(problems...); err != nil {
		return Config{}, err
	}
	return settings, nil
}

// isASCII reports whether value is plain ASCII. Host names in the
// configuration use the punycode form instead of Unicode.
func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > 127 {
			return false
		}
	}
	return true
}

func parsePositiveDuration(getenv func(string) string, variable string, fallback time.Duration) (time.Duration, error) {
	value := getenv(variable)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", variable)
	}
	return duration, nil
}

func parsePositiveInt(getenv func(string) string, variable string, fallback int) (int, error) {
	value := getenv(variable)
	if value == "" {
		return fallback, nil
	}
	number, err := strconv.Atoi(value)
	if err != nil || number <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", variable)
	}
	return number, nil
}
