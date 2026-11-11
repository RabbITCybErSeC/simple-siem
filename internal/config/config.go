package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentProduction  Environment = "production"

	defaultListen          = ":8080"
	defaultPublicURL       = "http://localhost:8080"
	defaultShutdownTimeout = 30 * time.Second

	environmentVariable     = "SIMPLE_SIEM_ENV"
	databaseURLVariable     = "SIMPLE_SIEM_DATABASE_URL"
	listenVariable          = "SIMPLE_SIEM_LISTEN"
	publicURLVariable       = "SIMPLE_SIEM_PUBLIC_URL"
	trustedProxiesVariable  = "SIMPLE_SIEM_TRUSTED_PROXIES"
	shutdownTimeoutVariable = "SIMPLE_SIEM_SHUTDOWN_TIMEOUT"
)

type Environment string

type Config struct {
	Environment     Environment
	DatabaseURL     string
	Listen          string
	PublicURL       string
	TrustedProxies  []string
	ShutdownTimeout time.Duration
}

func Load(getenv func(string) string) (Config, error) {
	settings := Config{
		Environment:     EnvironmentProduction,
		DatabaseURL:     getenv(databaseURLVariable),
		Listen:          getenv(listenVariable),
		PublicURL:       getenv(publicURLVariable),
		ShutdownTimeout: defaultShutdownTimeout,
	}
	if settings.Listen == "" {
		settings.Listen = defaultListen
	}

	var problems []error

	if value := getenv(environmentVariable); value != "" {
		settings.Environment = Environment(value)
	}
	switch settings.Environment {
	case EnvironmentDevelopment, EnvironmentProduction:
	default:
		problems = append(problems, fmt.Errorf("%s must be %q or %q", environmentVariable, EnvironmentDevelopment, EnvironmentProduction))
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
			problems = append(problems, fmt.Errorf("%s is required outside development", publicURLVariable))
		}
	} else if parsed, err := url.Parse(settings.PublicURL); err != nil || !parsed.IsAbs() || parsed.Host == "" {
		problems = append(problems, fmt.Errorf("%s must be an absolute URL", publicURLVariable))
	} else if settings.Environment != EnvironmentDevelopment && parsed.Scheme != "https" {
		problems = append(problems, fmt.Errorf("%s must use https outside development", publicURLVariable))
	} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
		problems = append(problems, fmt.Errorf("%s must use http or https", publicURLVariable))
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

	if value := getenv(shutdownTimeoutVariable); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			problems = append(problems, fmt.Errorf("%s must be a positive duration", shutdownTimeoutVariable))
		} else {
			settings.ShutdownTimeout = timeout
		}
	}

	if err := errors.Join(problems...); err != nil {
		return Config{}, err
	}
	return settings, nil
}
