package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	databaseURL := "postgres://user:password@database:5432/simple_siem"

	tests := []struct {
		name             string
		environment      map[string]string
		want             Config
		wantErrors       []string
		wantNoErrorTexts []string
	}{
		{
			name: "development defaults",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":          "development",
				"SIMPLE_SIEM_DATABASE_URL": databaseURL,
			},
			want: Config{
				Environment:     EnvironmentDevelopment,
				DatabaseURL:     databaseURL,
				Listen:          ":8080",
				PublicURL:       "http://localhost:8080",
				ShutdownTimeout: 30 * time.Second,
			},
		},
		{
			name: "environment defaults to production",
			environment: map[string]string{
				"SIMPLE_SIEM_DATABASE_URL": databaseURL,
			},
			wantErrors: []string{"SIMPLE_SIEM_PUBLIC_URL is required"},
		},
		{
			name: "production without public URL",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":          "production",
				"SIMPLE_SIEM_DATABASE_URL": databaseURL,
			},
			wantErrors:       []string{"SIMPLE_SIEM_PUBLIC_URL is required"},
			wantNoErrorTexts: []string{"password"},
		},
		{
			name: "production with an http public URL",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":          "production",
				"SIMPLE_SIEM_DATABASE_URL": databaseURL,
				"SIMPLE_SIEM_PUBLIC_URL":   "http://siem.example.com",
			},
			wantErrors:       []string{"SIMPLE_SIEM_PUBLIC_URL", "must use https"},
			wantNoErrorTexts: []string{"http://siem.example.com"},
		},
		{
			name: "invalid trusted proxy",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":             "development",
				"SIMPLE_SIEM_DATABASE_URL":    databaseURL,
				"SIMPLE_SIEM_TRUSTED_PROXIES": "10.0.0.0/8,not-an-ip",
			},
			wantErrors: []string{"SIMPLE_SIEM_TRUSTED_PROXIES", "not-an-ip"},
		},
		{
			name: "malformed database URL is not echoed",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":          "development",
				"SIMPLE_SIEM_DATABASE_URL": "postgres://user:sup3rsecret@database:not-a-port/simple_siem",
			},
			wantErrors:       []string{"SIMPLE_SIEM_DATABASE_URL"},
			wantNoErrorTexts: []string{"sup3rsecret"},
		},
		{
			name: "production with full configuration",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":              "production",
				"SIMPLE_SIEM_DATABASE_URL":     databaseURL,
				"SIMPLE_SIEM_LISTEN":           "127.0.0.1:9090",
				"SIMPLE_SIEM_PUBLIC_URL":       "https://siem.example.com",
				"SIMPLE_SIEM_TRUSTED_PROXIES":  "10.0.0.0/8, 192.0.2.7",
				"SIMPLE_SIEM_SHUTDOWN_TIMEOUT": "10s",
			},
			want: Config{
				Environment:     EnvironmentProduction,
				DatabaseURL:     databaseURL,
				Listen:          "127.0.0.1:9090",
				PublicURL:       "https://siem.example.com",
				TrustedProxies:  []string{"10.0.0.0/8", "192.0.2.7"},
				ShutdownTimeout: 10 * time.Second,
			},
		},
		{
			name: "missing database URL",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV": "development",
			},
			wantErrors: []string{"SIMPLE_SIEM_DATABASE_URL is required"},
		},
		{
			name: "invalid environment",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":          "staging",
				"SIMPLE_SIEM_DATABASE_URL": databaseURL,
			},
			wantErrors: []string{"SIMPLE_SIEM_ENV"},
		},
		{
			name: "invalid shutdown timeout",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":              "development",
				"SIMPLE_SIEM_DATABASE_URL":     databaseURL,
				"SIMPLE_SIEM_SHUTDOWN_TIMEOUT": "soon",
			},
			wantErrors: []string{"SIMPLE_SIEM_SHUTDOWN_TIMEOUT"},
		},
		{
			name: "relative public URL",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":          "development",
				"SIMPLE_SIEM_DATABASE_URL": databaseURL,
				"SIMPLE_SIEM_PUBLIC_URL":   "/siem",
			},
			wantErrors: []string{"SIMPLE_SIEM_PUBLIC_URL"},
		},
		{
			name: "every problem is joined",
			environment: map[string]string{
				"SIMPLE_SIEM_ENV":              "production",
				"SIMPLE_SIEM_DATABASE_URL":     "not-a-database-url",
				"SIMPLE_SIEM_TRUSTED_PROXIES":  "not-an-ip",
				"SIMPLE_SIEM_SHUTDOWN_TIMEOUT": "soon",
			},
			wantErrors: []string{
				"SIMPLE_SIEM_PUBLIC_URL is required",
				"SIMPLE_SIEM_DATABASE_URL",
				"SIMPLE_SIEM_TRUSTED_PROXIES",
				"SIMPLE_SIEM_SHUTDOWN_TIMEOUT",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings, err := Load(func(name string) string {
				return test.environment[name]
			})

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("Load() error = %v, want an error containing %q", err, wantError)
				}
			}
			for _, wantNoErrorText := range test.wantNoErrorTexts {
				if err != nil && strings.Contains(err.Error(), wantNoErrorText) {
					t.Fatalf("Load() error = %v, must not contain %q", err, wantNoErrorText)
				}
			}

			if len(test.wantErrors) > 0 {
				if !reflect.DeepEqual(settings, Config{}) {
					t.Fatalf("Load() = %+v, want the zero Config when validation fails", settings)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(settings, test.want) {
				t.Fatalf("Load() = %+v, want %+v", settings, test.want)
			}
		})
	}
}
