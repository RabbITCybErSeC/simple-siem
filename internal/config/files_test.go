package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
)

const (
	validConfigDirectory = "testdata/valid"
	minimalSystem        = "version: \"0.1\"\n"
	emptyFetchers        = "fetchers: {}\n"
)

var validSecrets = map[string]string{
	"ELASTIC_PROD_API_KEY": "prod-api-key",
	"ELASTIC_PROD_CA":      "prod-ca",
	"ELASTIC_EDR_USERNAME": "edr-user",
	"ELASTIC_EDR_PASSWORD": "edr-password",
}

func getenv(values map[string]string) func(string) string {
	return func(name string) string {
		return values[name]
	}
}

func writeConfig(t *testing.T, files map[string]string) string {
	t.Helper()
	directory := t.TempDir()
	for name, content := range files {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}
	return directory
}

func copyConfig(t *testing.T, source string) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.CopyFS(directory, os.DirFS(source)); err != nil {
		t.Fatalf("copy fixture %s: %v", source, err)
	}
	return directory
}

func rewriteFile(t *testing.T, path string, replacements ...string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for index := 0; index < len(replacements); index += 2 {
		data = []byte(strings.ReplaceAll(string(data), replacements[index], replacements[index+1]))
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestLoadFiles(t *testing.T) {
	oversizedPipeline := "id: oversized\n#" + strings.Repeat("x", 1<<20) + "\n"

	tests := []struct {
		name             string
		directory        string
		files            map[string]string
		wantErrors       []string
		wantNoErrorTexts []string
		check            func(t *testing.T, files Files)
	}{
		{
			name:      "valid directory",
			directory: validConfigDirectory,
			check: func(t *testing.T, files Files) {
				t.Helper()
				if files.Directory != validConfigDirectory {
					t.Errorf("Directory = %q, want %q", files.Directory, validConfigDirectory)
				}
				if len(files.Fetchers) != 2 {
					t.Errorf("len(Fetchers) = %d, want 2", len(files.Fetchers))
				}
				if len(files.Pipelines) != 1 {
					t.Fatalf("len(Pipelines) = %d, want 1", len(files.Pipelines))
				}
				if files.Pipelines[0].ID != "auth-events" {
					t.Errorf("Pipeline.ID = %q, want %q", files.Pipelines[0].ID, "auth-events")
				}
			},
		},
		{
			name:       "missing required file",
			files:      map[string]string{"system.yaml": minimalSystem},
			wantErrors: []string{"fetchers.yaml", "required"},
		},
		{
			name: "oversized file",
			files: map[string]string{
				"system.yaml":        minimalSystem,
				"fetchers.yaml":      emptyFetchers,
				"pipelines/big.yaml": oversizedPipeline,
			},
			wantErrors:       []string{"pipelines/big.yaml", "1 MiB"},
			wantNoErrorTexts: []string{"cannot unmarshal"},
		},
		{
			name: "unknown key",
			files: map[string]string{
				"system.yaml":   minimalSystem,
				"fetchers.yaml": "fetchers:\n  elastic-prod:\n    type: elasticsearch\n    adresses: [https://es.example.internal:9200]\n",
			},
			wantErrors: []string{"fetchers.yaml", "elastic-prod", "adresses"},
		},
		{
			name: "duplicate key",
			files: map[string]string{
				"system.yaml":         minimalSystem,
				"fetchers.yaml":       emptyFetchers,
				"pipelines/auth.yaml": "id: auth-events\nid: other-events\n",
			},
			wantErrors: []string{"pipelines/auth.yaml", `"id"`, "already defined"},
		},
		{
			name: "wrong type",
			files: map[string]string{
				"system.yaml":   minimalSystem + "runner:\n  batch_size: lots\n",
				"fetchers.yaml": emptyFetchers,
			},
			wantErrors: []string{"system.yaml", "cannot unmarshal", "int"},
		},
		{
			name: "key from a later phase",
			files: map[string]string{
				"system.yaml":   minimalSystem + "scheduler:\n  max_overlapping_runs_per_pipeline: 1\n",
				"fetchers.yaml": emptyFetchers,
			},
			wantErrors: []string{"system.yaml", "scheduler", "unknown field"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := test.directory
			if directory == "" {
				directory = writeConfig(t, test.files)
			}

			files, err := LoadFiles(directory, EnvironmentDevelopment, getenv(validSecrets))

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("LoadFiles() error = %v, want an error containing %q", err, wantError)
				}
			}
			for _, wantNoErrorText := range test.wantNoErrorTexts {
				if err != nil && strings.Contains(err.Error(), wantNoErrorText) {
					t.Fatalf("LoadFiles() error = %v, must not contain %q", err, wantNoErrorText)
				}
			}
			if len(test.wantErrors) > 0 {
				if !reflect.DeepEqual(files, Files{}) {
					t.Fatalf("LoadFiles() = %+v, want the zero Files when validation fails", files)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFiles() error = %v, want nil", err)
			}
			if test.check != nil {
				test.check(t, files)
			}
		})
	}
}

func TestSystemSettings(t *testing.T) {
	defaultSystem := System{
		Version: "0.1",
		Stores: Stores{DatasetCache: DatasetCacheStore{
			Type:                   "postgres",
			DefaultRetention:       Duration(72 * time.Hour),
			DefaultAllowedLateness: Duration(10 * time.Minute),
		}},
		Secrets: SecretsSettings{Provider: "env"},
		Runner:  RunnerSettings{BatchSize: 5000, MaxQuarantineRatio: 0.10},
	}

	tests := []struct {
		name       string
		system     string
		want       System
		wantErrors []string
	}{
		{
			name:   "defaults applied",
			system: minimalSystem,
			want:   defaultSystem,
		},
		{
			name:   "unquoted version",
			system: "version: 0.1\n",
			want:   defaultSystem,
		},
		{
			name: "explicit values",
			system: `version: "0.1"
stores:
  dataset_cache:
    type: postgres
    default_retention: 24h
    default_allowed_lateness: 5m
secrets:
  provider: env
runner:
  batch_size: 1000
  max_quarantine_ratio: 0.5
`,
			want: System{
				Version: "0.1",
				Stores: Stores{DatasetCache: DatasetCacheStore{
					Type:                   "postgres",
					DefaultRetention:       Duration(24 * time.Hour),
					DefaultAllowedLateness: Duration(5 * time.Minute),
				}},
				Secrets: SecretsSettings{Provider: "env"},
				Runner:  RunnerSettings{BatchSize: 1000, MaxQuarantineRatio: 0.5},
			},
		},
		{
			name:       "unsupported version",
			system:     "version: \"0.2\"\n",
			wantErrors: []string{"version", "0.1"},
		},
		{
			name:       "unsupported store type",
			system:     minimalSystem + "stores:\n  dataset_cache:\n    type: redis\n",
			wantErrors: []string{"dataset_cache", "type", "redis"},
		},
		{
			name:       "unsupported secret provider",
			system:     minimalSystem + "secrets:\n  provider: vault\n",
			wantErrors: []string{"secrets.provider", "vault"},
		},
		{
			name:       "retention below the minimum",
			system:     minimalSystem + "stores:\n  dataset_cache:\n    default_retention: 30m\n",
			wantErrors: []string{"default_retention", "1h"},
		},
		{
			name:       "retention above the maximum",
			system:     minimalSystem + "stores:\n  dataset_cache:\n    default_retention: 2161h\n",
			wantErrors: []string{"default_retention", "2160h"},
		},
		{
			name:       "retention explicitly zero",
			system:     minimalSystem + "stores:\n  dataset_cache:\n    default_retention: 0s\n",
			wantErrors: []string{"default_retention", "1h"},
		},
		{
			name:       "negative allowed lateness",
			system:     minimalSystem + "stores:\n  dataset_cache:\n    default_allowed_lateness: -1m\n",
			wantErrors: []string{"default_allowed_lateness", "0"},
		},
		{
			name: "allowed lateness not less than retention",
			system: minimalSystem + `stores:
  dataset_cache:
    default_retention: 1h
    default_allowed_lateness: 1h
`,
			wantErrors: []string{"default_allowed_lateness", "retention"},
		},
		{
			name:       "batch size below the minimum",
			system:     minimalSystem + "runner:\n  batch_size: 0\n",
			wantErrors: []string{"batch_size", "1"},
		},
		{
			name:       "batch size above the maximum",
			system:     minimalSystem + "runner:\n  batch_size: 50001\n",
			wantErrors: []string{"batch_size", "50000"},
		},
		{
			name:       "quarantine ratio zero",
			system:     minimalSystem + "runner:\n  max_quarantine_ratio: 0\n",
			wantErrors: []string{"max_quarantine_ratio"},
		},
		{
			name:       "quarantine ratio above one",
			system:     minimalSystem + "runner:\n  max_quarantine_ratio: 1.5\n",
			wantErrors: []string{"max_quarantine_ratio"},
		},
		{
			name:       "invalid duration",
			system:     minimalSystem + "stores:\n  dataset_cache:\n    default_retention: soon\n",
			wantErrors: []string{"system.yaml", "invalid duration", "soon"},
		},
		{
			name: "every problem is joined",
			system: `version: "0.2"
runner:
  batch_size: 0
  max_quarantine_ratio: 2
`,
			wantErrors: []string{"version", "batch_size", "max_quarantine_ratio"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := writeConfig(t, map[string]string{
				"system.yaml":   test.system,
				"fetchers.yaml": emptyFetchers,
			})

			files, err := LoadFiles(directory, EnvironmentDevelopment, getenv(validSecrets))

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("LoadFiles() error = %v, want an error containing %q", err, wantError)
				}
			}
			if len(test.wantErrors) > 0 {
				if !reflect.DeepEqual(files, Files{}) {
					t.Fatalf("LoadFiles() = %+v, want the zero Files when validation fails", files)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFiles() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(files.System, test.want) {
				t.Fatalf("System = %+v, want %+v", files.System, test.want)
			}
		})
	}
}

func TestSecretReferences(t *testing.T) {
	fetcherWithAPIKey := func(apiKey string) map[string]string {
		return map[string]string{
			"system.yaml": minimalSystem,
			"fetchers.yaml": fmt.Sprintf(`fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://elastic.example.internal:9200]
    auth:
      api_key: %s
    allowed_indexes: [auth-*]
`, apiKey),
		}
	}

	tests := []struct {
		name             string
		files            map[string]string
		prepare          func(t *testing.T) string
		environment      map[string]string
		wantErrors       []string
		wantNoErrorTexts []string
	}{
		{
			name:             "plaintext credential",
			files:            fetcherWithAPIKey("hunter2"),
			wantErrors:       []string{"fetchers.yaml", "credentials must be secret references"},
			wantNoErrorTexts: []string{"hunter2"},
		},
		{
			name:       "lowercase secret name",
			files:      fetcherWithAPIKey("${secret:lowercase}"),
			wantErrors: []string{"credentials must be secret references"},
		},
		{
			name:       "empty secret name",
			files:      fetcherWithAPIKey("${secret:}"),
			wantErrors: []string{"credentials must be secret references"},
		},
		{
			name:       "partial reference",
			files:      fetcherWithAPIKey("prefix-${secret:TOKEN}"),
			wantErrors: []string{"credentials must be secret references"},
		},
		{
			name: "secret in a pipeline input",
			prepare: func(t *testing.T) string {
				directory := copyConfig(t, validConfigDirectory)
				rewriteFile(t, filepath.Join(directory, "pipelines", "auth.yaml"),
					"index: auth-*", "index: ${secret:INDEX}")
				return directory
			},
			wantErrors: []string{
				"pipelines/auth.yaml",
				"fetchers[0].inputs.index",
				"secret references are only allowed in credential fields",
			},
		},
		{
			name: "secret in a variable default",
			prepare: func(t *testing.T) string {
				directory := copyConfig(t, validConfigDirectory)
				rewriteFile(t, filepath.Join(directory, "pipelines", "auth.yaml"),
					"default: 15m", "default: ${secret:LOOKBACK}")
				return directory
			},
			wantErrors: []string{"variables.lookback.default", "secret references are only allowed in credential fields"},
		},
		{
			name: "secret not set",
			files: map[string]string{
				"system.yaml": minimalSystem,
				"fetchers.yaml": `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://elastic.example.internal:9200]
    auth:
      username: ${secret:ELASTIC_DEV_USERNAME}
      password: ${secret:ELASTIC_DEV_PASSWORD}
    allowed_indexes: [auth-*]
`,
			},
			environment: map[string]string{"ELASTIC_DEV_USERNAME": "dev-user"},
			wantErrors:  []string{"fetchers.yaml", "ELASTIC_DEV_PASSWORD", "not set"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := ""
			if test.prepare != nil {
				directory = test.prepare(t)
			} else {
				directory = writeConfig(t, test.files)
			}

			environment := validSecrets
			if test.environment != nil {
				environment = test.environment
			}
			files, err := LoadFiles(directory, EnvironmentDevelopment, getenv(environment))

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("LoadFiles() error = %v, want an error containing %q", err, wantError)
				}
			}
			for _, wantNoErrorText := range test.wantNoErrorTexts {
				if err != nil && strings.Contains(err.Error(), wantNoErrorText) {
					t.Fatalf("LoadFiles() error = %v, must not contain %q", err, wantNoErrorText)
				}
			}
			if len(test.wantErrors) > 0 {
				if !reflect.DeepEqual(files, Files{}) {
					t.Fatalf("LoadFiles() = %+v, want the zero Files when validation fails", files)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFiles() error = %v, want nil", err)
			}
		})
	}
}

func TestSecretRef(t *testing.T) {
	ref := SecretRef{Name: "ELASTIC_DEV_PASSWORD"}

	if got := ref.String(); got != "${secret:ELASTIC_DEV_PASSWORD}" {
		t.Errorf("String() = %q, want %q", got, "${secret:ELASTIC_DEV_PASSWORD}")
	}

	jsonData, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if want := `"${secret:ELASTIC_DEV_PASSWORD}"`; string(jsonData) != want {
		t.Errorf("json.Marshal() = %s, want %s", jsonData, want)
	}

	yamlData, err := yaml.Marshal(ref)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}
	if !strings.Contains(string(yamlData), "${secret:ELASTIC_DEV_PASSWORD}") {
		t.Errorf("yaml.Marshal() = %s, want the secret reference", yamlData)
	}

	value, err := ref.Resolve(getenv(map[string]string{"ELASTIC_DEV_PASSWORD": "resolved-value"}))
	if err != nil || value != "resolved-value" {
		t.Fatalf("Resolve() = %q, %v, want %q, nil", value, err, "resolved-value")
	}

	_, err = ref.Resolve(getenv(nil))
	if err == nil || !strings.Contains(err.Error(), "ELASTIC_DEV_PASSWORD") || !strings.Contains(err.Error(), "not set") {
		t.Fatalf("Resolve() error = %v, want an error naming ELASTIC_DEV_PASSWORD and not set", err)
	}
}

const knownSecretValue = "s3cr3t-known-value"

func TestSecretValueNotInErrors(t *testing.T) {
	directory := copyConfig(t, validConfigDirectory)
	rewriteFile(t, filepath.Join(directory, "fetchers.yaml"),
		"    allowed_indexes:", "    adresses: []\n    allowed_indexes:")

	environment := map[string]string{
		"ELASTIC_PROD_API_KEY": knownSecretValue,
		"ELASTIC_PROD_CA":      knownSecretValue,
		"ELASTIC_EDR_USERNAME": knownSecretValue,
		"ELASTIC_EDR_PASSWORD": knownSecretValue,
	}
	files, err := LoadFiles(directory, EnvironmentDevelopment, getenv(environment))
	if err == nil {
		t.Fatalf("LoadFiles() error = nil, want an error for the unknown key")
	}
	if strings.Contains(err.Error(), knownSecretValue) {
		t.Fatalf("LoadFiles() error = %v, must not contain the secret value", err)
	}
	if !reflect.DeepEqual(files, Files{}) {
		t.Fatalf("LoadFiles() = %+v, want the zero Files when validation fails", files)
	}
}

var fetcherSecrets = map[string]string{
	"ELASTIC_DEV_API_KEY":  "dev-key",
	"ELASTIC_DEV_USERNAME": "dev-user",
	"ELASTIC_DEV_PASSWORD": "dev-password",
	"ELASTIC_DEV_CA":       "dev-ca",
}

func TestFetcherInstances(t *testing.T) {
	tests := []struct {
		name             string
		directory        string
		fetchers         string
		environment      Environment
		wantErrors       []string
		wantNoErrorTexts []string
		check            func(t *testing.T, files Files)
	}{
		{
			name:      "valid instances from the fixture",
			directory: validConfigDirectory,
			check: func(t *testing.T, files Files) {
				t.Helper()
				prod := files.Fetchers["elastic-prod"]
				if prod.ID != "elastic-prod" {
					t.Errorf("ID = %q, want elastic-prod", prod.ID)
				}
				if prod.Defaults.Timeout != Duration(30*time.Second) {
					t.Errorf("Timeout = %s, want 30s", time.Duration(prod.Defaults.Timeout))
				}
				edr := files.Fetchers["elastic-edr"]
				if edr.Defaults.TimeField != "@timestamp" || edr.Defaults.MaxResults != 10000 {
					t.Errorf("elastic-edr defaults = %+v, want @timestamp and 10000", edr.Defaults)
				}
			},
		},
		{
			name: "defaults applied",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
			check: func(t *testing.T, files Files) {
				t.Helper()
				defaults := files.Fetchers["elastic-dev"].Defaults
				if defaults.Timeout != Duration(30*time.Second) {
					t.Errorf("Timeout = %s, want 30s", time.Duration(defaults.Timeout))
				}
				if defaults.MaxResults != 10000 {
					t.Errorf("MaxResults = %d, want 10000", defaults.MaxResults)
				}
				if defaults.TimeField != "@timestamp" {
					t.Errorf("TimeField = %q, want @timestamp", defaults.TimeField)
				}
			},
		},
		{
			name: "unsupported type",
			fetchers: `fetchers:
  elastic-dev:
    type: misp
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"unsupported fetcher type", "misp"},
		},
		{
			name: "missing addresses",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"addresses", "at least one"},
		},
		{
			name: "relative address",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"addresses[0]", "absolute"},
		},
		{
			name: "address with user information",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://user:password@es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
			wantErrors:       []string{"addresses[0]", "user information"},
			wantNoErrorTexts: []string{"password"},
		},
		{
			name: "address with a query",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200/?pretty=true]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"addresses[0]", "query"},
		},
		{
			name: "http in production",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [http://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
			environment: EnvironmentProduction,
			wantErrors:  []string{"addresses[0]", "development"},
		},
		{
			name: "http in development",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [http://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
		},
		{
			name: "skipping TLS verification in production",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    tls:
      insecure_skip_verify: true
    allowed_indexes: [auth-*]
`,
			environment: EnvironmentProduction,
			wantErrors:  []string{"insecure_skip_verify", "development"},
		},
		{
			name: "skipping TLS verification in development",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    tls:
      insecure_skip_verify: true
    allowed_indexes: [auth-*]
`,
		},
		{
			name: "no authentication",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"auth", "exactly one"},
		},
		{
			name: "two authentication forms",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
      username: ${secret:ELASTIC_DEV_USERNAME}
      password: ${secret:ELASTIC_DEV_PASSWORD}
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"auth", "exactly one"},
		},
		{
			name: "username without password",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      username: ${secret:ELASTIC_DEV_USERNAME}
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"auth"},
		},
		{
			name: "missing index allowlist",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
`,
			wantErrors: []string{"allowed_indexes", "at least one"},
		},
		{
			name: "empty index allowlist",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: []
`,
			wantErrors: []string{"allowed_indexes", "at least one"},
		},
		{
			name: "dangerous index patterns",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes:
      - "*"
      - _all
      - "a,b"
      - remote:auth-*
`,
			wantErrors: []string{"allowed_indexes[0]", "allowed_indexes[1]", "allowed_indexes[2]", "allowed_indexes[3]"},
		},
		{
			name: "uppercase index pattern",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [Auth-*]
`,
			wantErrors: []string{"allowed_indexes[0]", "Auth-*"},
		},
		{
			name: "default index outside the allowlist",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    defaults:
      index: edr-*
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"defaults.index", "edr-*"},
		},
		{
			name: "timeout above the maximum",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    defaults:
      timeout: 11m
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"defaults.timeout", "10m"},
		},
		{
			name: "timeout explicitly zero",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    defaults:
      timeout: 0s
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"defaults.timeout", "positive"},
		},
		{
			name: "max results below the minimum",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    defaults:
      max_results: 0
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"defaults.max_results", "1"},
		},
		{
			name: "max results above the maximum",
			fetchers: `fetchers:
  elastic-dev:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    defaults:
      max_results: 1000001
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"defaults.max_results", "1000000"},
		},
		{
			name: "invalid instance id",
			fetchers: `fetchers:
  Elastic-Prod:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`,
			wantErrors: []string{"Elastic-Prod", "invalid"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := test.directory
			if directory == "" {
				directory = writeConfig(t, map[string]string{
					"system.yaml":   minimalSystem,
					"fetchers.yaml": test.fetchers,
				})
			}
			environment := test.environment
			if environment == "" {
				environment = EnvironmentDevelopment
			}
			secrets := fetcherSecrets
			if test.directory != "" {
				secrets = validSecrets
			}

			files, err := LoadFiles(directory, environment, getenv(secrets))

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("LoadFiles() error = %v, want an error containing %q", err, wantError)
				}
			}
			for _, wantNoErrorText := range test.wantNoErrorTexts {
				if err != nil && strings.Contains(err.Error(), wantNoErrorText) {
					t.Fatalf("LoadFiles() error = %v, must not contain %q", err, wantNoErrorText)
				}
			}
			if len(test.wantErrors) > 0 {
				if !reflect.DeepEqual(files, Files{}) {
					t.Fatalf("LoadFiles() = %+v, want the zero Files when validation fails", files)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFiles() error = %v, want nil", err)
			}
			if test.check != nil {
				test.check(t, files)
			}
		})
	}
}

func TestIndexAllowed(t *testing.T) {
	tests := []struct {
		name      string
		index     string
		allowlist []string
		want      bool
	}{
		{name: "exact match", index: "auth-linux", allowlist: []string{"auth-linux"}, want: true},
		{name: "wildcard allowlist entry", index: "auth-linux-2026.11.13", allowlist: []string{"auth-*"}, want: true},
		{name: "wildcard in the index", index: "auth-linux-*", allowlist: []string{"auth-*"}, want: true},
		{name: "narrow allowlist does not allow a broad index", index: "auth-*", allowlist: []string{"auth-linux-*"}, want: false},
		{name: "different prefix", index: "edr-1", allowlist: []string{"auth-*"}, want: false},
		{name: "second entry matches", index: "edr-1", allowlist: []string{"auth-*", "edr-*"}, want: true},
		{name: "case sensitive", index: "Auth-linux", allowlist: []string{"auth-*"}, want: false},
		{name: "empty allowlist", index: "auth-linux", allowlist: nil, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IndexAllowed(test.index, test.allowlist); got != test.want {
				t.Fatalf("IndexAllowed(%q, %q) = %t, want %t", test.index, test.allowlist, got, test.want)
			}
		})
	}
}

func TestParseEnvironment(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		want       Environment
		wantErrors []string
	}{
		{name: "empty means production", value: "", want: EnvironmentProduction},
		{name: "production", value: "production", want: EnvironmentProduction},
		{name: "development", value: "development", want: EnvironmentDevelopment},
		{name: "unknown", value: "staging", wantErrors: []string{"development", "production"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			environment, err := ParseEnvironment(test.value)

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("ParseEnvironment() error = %v, want an error containing %q", err, wantError)
				}
			}
			if len(test.wantErrors) > 0 {
				return
			}
			if err != nil {
				t.Fatalf("ParseEnvironment() error = %v, want nil", err)
			}
			if environment != test.want {
				t.Fatalf("ParseEnvironment() = %q, want %q", environment, test.want)
			}
		})
	}
}

const (
	pipelineFetchers = `fetchers:
  elastic-prod:
    type: elasticsearch
    addresses: [https://es.example.internal:9200]
    auth:
      api_key: ${secret:ELASTIC_DEV_API_KEY}
    allowed_indexes: [auth-*]
`
	minimalPipeline = `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
fetchers:
  - id: auth
    ref: elastic-prod
    inputs:
      index: auth-*
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events:
    from: udm.auth_events
`
	validPipeline = `id: auth-events
version: 0.1.0
schedule:
  every: 5m
  timeout: 2m
variables:
  lookback:
    type: duration
    default: 15m
  user:
    type: string
fetchers:
  - id: auth
    ref: elastic-prod
    inputs:
      index: auth-*
      lookback: ${variables.lookback}
      user: ${variables.user}
      batch: 10
      active: true
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events:
    from: udm.auth_events
`
)

func pipelineConfig(t *testing.T, pipelines map[string]string) string {
	t.Helper()
	files := map[string]string{
		"system.yaml":        minimalSystem,
		"fetchers.yaml":      pipelineFetchers,
		"mappings/auth.yaml": "id: auth\n",
	}
	for name, content := range pipelines {
		files[filepath.Join("pipelines", name)] = content
	}
	return writeConfig(t, files)
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestPipelines(t *testing.T) {
	tests := []struct {
		name             string
		pipeline         string
		prepare          func(t *testing.T) string
		wantErrors       []string
		wantNoErrorTexts []string
		check            func(t *testing.T, files Files)
	}{
		{
			name:     "valid pipeline",
			pipeline: validPipeline,
			check: func(t *testing.T, files Files) {
				t.Helper()
				if len(files.Pipelines) != 1 {
					t.Fatalf("len(Pipelines) = %d, want 1", len(files.Pipelines))
				}
				pipeline := files.Pipelines[0]
				if pipeline.File != "pipelines/auth.yaml" {
					t.Errorf("File = %q, want pipelines/auth.yaml", pipeline.File)
				}
				if pipeline.Schedule.OverlapPolicy != "skip" {
					t.Errorf("OverlapPolicy = %q, want skip", pipeline.Schedule.OverlapPolicy)
				}
				output := pipeline.Outputs["auth_events"]
				if output.Retention == nil || *output.Retention != Duration(72*time.Hour) {
					t.Errorf("Retention = %v, want the 72h system default", output.Retention)
				}
				if output.AllowedLateness == nil || *output.AllowedLateness != Duration(10*time.Minute) {
					t.Errorf("AllowedLateness = %v, want the 10m system default", output.AllowedLateness)
				}

				inputs := pipeline.Fetchers[0].Inputs
				if inputs["index"].Literal != "auth-*" {
					t.Errorf("index input = %+v, want literal auth-*", inputs["index"])
				}
				if inputs["lookback"].Variable != "lookback" {
					t.Errorf("lookback input = %+v, want variable lookback", inputs["lookback"])
				}
				if inputs["batch"].Literal != "10" || inputs["active"].Literal != "true" {
					t.Errorf("scalar inputs = %+v, want literal 10 and true", inputs)
				}
			},
		},
		{
			name: "pipelines sorted by id",
			prepare: func(t *testing.T) string {
				second := strings.ReplaceAll(minimalPipeline, "auth-events", "z-events")
				second = strings.ReplaceAll(second, "udm.auth_events", "udm.z_events")
				second = strings.ReplaceAll(second, "auth_events:", "z_events:")
				return pipelineConfig(t, map[string]string{
					"b.yaml": second,
					"a.yaml": minimalPipeline,
				})
			},
			check: func(t *testing.T, files Files) {
				t.Helper()
				if len(files.Pipelines) != 2 {
					t.Fatalf("len(Pipelines) = %d, want 2", len(files.Pipelines))
				}
				if files.Pipelines[0].ID != "auth-events" || files.Pipelines[1].ID != "z-events" {
					t.Fatalf("pipeline ids = %q, %q, want auth-events, z-events", files.Pipelines[0].ID, files.Pipelines[1].ID)
				}
			},
		},
		{
			name: "unknown fetcher instance",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"ref: elastic-prod", "ref: elastic-missing"),
			wantErrors: []string{"pipelines/auth.yaml", "fetchers[0].ref:", `unknown fetcher instance "elastic-missing"`},
		},
		{
			name: "no fetchers",
			pipeline: `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
fetchers: []
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events:
    from: udm.auth_events
`,
			wantErrors: []string{"fetchers", "at least one"},
		},
		{
			name: "duplicate step ids",
			pipeline: `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
fetchers:
  - id: auth
    ref: elastic-prod
    inputs:
      index: auth-*
  - id: auth
    ref: elastic-prod
    inputs:
      index: auth-*
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events:
    from: udm.auth_events
`,
			wantErrors: []string{"pipelines/auth.yaml", "fetchers[1].id", "duplicate"},
		},
		{
			name:       "invalid step id",
			pipeline:   strings.ReplaceAll(minimalPipeline, "- id: auth", "- id: Auth"),
			wantErrors: []string{"fetchers[0].id", "invalid fetcher step id"},
		},
		{
			name: "undeclared variable",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"index: auth-*", "index: auth-*\n      user: ${variables.user}"),
			wantErrors: []string{"fetchers[0].inputs.user", `variable "user" is not declared`},
		},
		{
			name: "partial interpolation",
			pipeline: `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
variables:
  user:
    type: string
fetchers:
  - id: auth
    ref: elastic-prod
    inputs:
      index: auth-*
      user: user-${variables.user}
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events:
    from: udm.auth_events
`,
			wantErrors: []string{"pipelines/auth.yaml", "literal or exactly one"},
		},
		{
			name: "index from a variable",
			pipeline: `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
variables:
  index:
    type: string
fetchers:
  - id: auth
    ref: elastic-prod
    inputs:
      index: ${variables.index}
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events:
    from: udm.auth_events
`,
			wantErrors: []string{"fetchers[0].inputs.index", "index must be a literal"},
		},
		{
			name:       "index outside the allowlist",
			pipeline:   strings.ReplaceAll(minimalPipeline, "index: auth-*", "index: edr-*"),
			wantErrors: []string{"fetchers[0].inputs.index", "edr-*", "elastic-prod"},
		},
		{
			name:       "mapping escapes the config directory",
			pipeline:   strings.ReplaceAll(minimalPipeline, "mappings/auth.yaml", "../secrets.yaml"),
			wantErrors: []string{"processors[0].mappings[0]", "inside the config directory"},
		},
		{
			name:       "absolute mapping path",
			pipeline:   strings.ReplaceAll(minimalPipeline, "mappings/auth.yaml", "/etc/passwd"),
			wantErrors: []string{"processors[0].mappings[0]", "inside the config directory"},
		},
		{
			name: "mapping symlink escapes the config directory",
			prepare: func(t *testing.T) string {
				directory := pipelineConfig(t, map[string]string{"auth.yaml": minimalPipeline})
				outside := filepath.Join(t.TempDir(), "outside.yaml")
				writeFile(t, outside, "id: outside\n")
				symlink := filepath.Join(directory, "mappings", "escape.yaml")
				if err := os.Symlink(outside, symlink); err != nil {
					t.Fatalf("create symlink: %v", err)
				}
				rewriteFile(t, filepath.Join(directory, "pipelines", "auth.yaml"),
					"mappings/auth.yaml", "mappings/escape.yaml")
				return directory
			},
			wantErrors: []string{"processors[0].mappings[0]", "inside the config directory"},
		},
		{
			name:       "missing mapping file",
			pipeline:   strings.ReplaceAll(minimalPipeline, "mappings/auth.yaml", "mappings/missing.yaml"),
			wantErrors: []string{"processors[0].mappings[0]", "missing.yaml"},
		},
		{
			name:       "processor reads an unknown step",
			pipeline:   strings.ReplaceAll(minimalPipeline, "from: auth.records", "from: other.records"),
			wantErrors: []string{"processors[0].from", "other.records"},
		},
		{
			name:       "processor from without records",
			pipeline:   strings.ReplaceAll(minimalPipeline, "from: auth.records", "from: auth.events"),
			wantErrors: []string{"processors[0].from", ".records"},
		},
		{
			name:       "unsupported processor type",
			pipeline:   strings.ReplaceAll(minimalPipeline, "type: converter", "type: enrich"),
			wantErrors: []string{"processors[0].type", "unsupported processor type"},
		},
		{
			name: "no processors",
			pipeline: `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
fetchers:
  - id: auth
    ref: elastic-prod
    inputs:
      index: auth-*
processors: []
outputs:
  auth_events:
    from: udm.auth_events
`,
			wantErrors: []string{"processors", "at least one"},
		},
		{
			name: "duplicate processor ids",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"  - id: to-udm\n    type: converter\n    from: auth.records\n    mappings: [mappings/auth.yaml]\n    output: udm.auth_events\n",
				"  - id: to-udm\n    type: converter\n    from: auth.records\n    mappings: [mappings/auth.yaml]\n    output: udm.auth_events\n  - id: to-udm\n    type: converter\n    from: auth.records\n    mappings: [mappings/auth.yaml]\n    output: udm.other_events\n"),
			wantErrors: []string{"processors[1].id", "duplicate"},
		},
		{
			name:       "processor without mappings",
			pipeline:   strings.ReplaceAll(minimalPipeline, "mappings: [mappings/auth.yaml]", "mappings: []"),
			wantErrors: []string{"processors[0].mappings", "at least one"},
		},
		{
			name:       "processor output is not udm",
			pipeline:   strings.ReplaceAll(minimalPipeline, "output: udm.auth_events", "output: records.auth_events"),
			wantErrors: []string{"processors[0].output", "udm.<dataset name>"},
		},
		{
			name:       "output from does not match the dataset",
			pipeline:   strings.ReplaceAll(minimalPipeline, "from: udm.auth_events", "from: udm.other_events"),
			wantErrors: []string{"outputs.auth_events.from", `must be "udm.auth_events"`},
		},
		{
			name: "output is not produced by a processor",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"output: udm.auth_events", "output: udm.other_events"),
			wantErrors: []string{"outputs.auth_events.from", "not produced by a processor"},
		},
		{
			name: "two pipelines write one dataset",
			prepare: func(t *testing.T) string {
				second := strings.ReplaceAll(minimalPipeline, "id: auth-events", "id: other-events")
				second = strings.ReplaceAll(second, "id: auth", "id: other")
				second = strings.ReplaceAll(second, "from: auth.records", "from: other.records")
				return pipelineConfig(t, map[string]string{
					"auth.yaml":  minimalPipeline,
					"other.yaml": second,
				})
			},
			wantErrors: []string{"auth_events", "pipelines/auth.yaml", "pipelines/other.yaml"},
		},
		{
			name: "allowed lateness not less than retention",
			pipeline: `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
fetchers:
  - id: auth
    ref: elastic-prod
    inputs:
      index: auth-*
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs:
  auth_events:
    from: udm.auth_events
    retention: 1h
    allowed_lateness: 1h
`,
			wantErrors: []string{"outputs.auth_events.allowed_lateness", "less than retention"},
		},
		{
			name: "output retention below the minimum",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"from: udm.auth_events", "from: udm.auth_events\n    retention: 30m"),
			wantErrors: []string{"outputs.auth_events.retention", "1h"},
		},
		{
			name: "invalid dataset name",
			pipeline: `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
fetchers:
  - id: auth
    ref: elastic-prod
    inputs:
      index: auth-*
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.Auth-Events
outputs:
  Auth-Events:
    from: udm.Auth-Events
`,
			wantErrors: []string{"outputs.Auth-Events", "invalid dataset name"},
		},
		{
			name: "output short string form",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"auth_events:\n    from: udm.auth_events", "auth_events: udm.auth_events"),
			wantErrors: []string{"pipelines/auth.yaml", "mapping is expected"},
		},
		{
			name:       "missing timeout",
			pipeline:   strings.ReplaceAll(minimalPipeline, "schedule:\n  timeout: 2m\n", ""),
			wantErrors: []string{"schedule.timeout", "positive"},
		},
		{
			name:       "timeout above one hour",
			pipeline:   strings.ReplaceAll(minimalPipeline, "timeout: 2m", "timeout: 2h"),
			wantErrors: []string{"schedule.timeout", "1h"},
		},
		{
			name:       "every explicitly zero",
			pipeline:   strings.ReplaceAll(minimalPipeline, "timeout: 2m", "every: 0s\n  timeout: 2m"),
			wantErrors: []string{"schedule.every", "positive"},
		},
		{
			name:       "invalid overlap policy",
			pipeline:   strings.ReplaceAll(minimalPipeline, "timeout: 2m", "timeout: 2m\n  overlap_policy: drop"),
			wantErrors: []string{"schedule.overlap_policy", "skip, queue or parallel"},
		},
		{
			name: "duplicate pipeline id",
			prepare: func(t *testing.T) string {
				second := strings.ReplaceAll(minimalPipeline, "udm.auth_events", "udm.other_events")
				second = strings.ReplaceAll(second, "auth_events:", "other_events:")
				return pipelineConfig(t, map[string]string{
					"auth.yaml":  minimalPipeline,
					"other.yaml": second,
				})
			},
			wantErrors: []string{"pipelines/auth.yaml", "pipelines/other.yaml", "duplicate pipeline id"},
		},
		{
			name:       "invalid pipeline id",
			pipeline:   strings.ReplaceAll(minimalPipeline, "id: auth-events", "id: Auth-Events"),
			wantErrors: []string{"id", "invalid pipeline id"},
		},
		{
			name:       "invalid version",
			pipeline:   strings.ReplaceAll(minimalPipeline, "version: 0.1.0", "version: \"0.1\""),
			wantErrors: []string{"version", "MAJOR.MINOR.PATCH"},
		},
		{
			name: "invalid variable type",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"version: 0.1.0", "version: 0.1.0\nvariables:\n  user:\n    type: boolean"),
			wantErrors: []string{"variables.user.type", "string, duration, timestamp or int"},
		},
		{
			name: "required variable with a default",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"version: 0.1.0", "version: 0.1.0\nvariables:\n  user:\n    type: string\n    required: true\n    default: alice"),
			wantErrors: []string{"variables.user.default", "must not have a default"},
		},
		{
			name: "variable default does not parse as its type",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"version: 0.1.0", "version: 0.1.0\nvariables:\n  lookback:\n    type: duration\n    default: soon"),
			wantErrors: []string{"variables.lookback.default", "must parse as duration"},
		},
		{
			name: "invalid variable name",
			pipeline: strings.ReplaceAll(minimalPipeline,
				"version: 0.1.0", "version: 0.1.0\nvariables:\n  Lookback:\n    type: string"),
			wantErrors: []string{"variables.Lookback", "invalid variable name"},
		},
		{
			name: "no outputs",
			pipeline: `id: auth-events
version: 0.1.0
schedule:
  timeout: 2m
fetchers:
  - id: auth
    ref: elastic-prod
    inputs:
      index: auth-*
processors:
  - id: to-udm
    type: converter
    from: auth.records
    mappings: [mappings/auth.yaml]
    output: udm.auth_events
outputs: {}
`,
			wantErrors: []string{"outputs", "at least one"},
		},
		{
			name: "non-yaml pipeline files are ignored",
			prepare: func(t *testing.T) string {
				directory := pipelineConfig(t, map[string]string{"auth.yaml": minimalPipeline})
				writeFile(t, filepath.Join(directory, "pipelines", "notes.txt"), "not: [valid")
				return directory
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := ""
			if test.prepare != nil {
				directory = test.prepare(t)
			} else {
				pipeline := test.pipeline
				if pipeline == "" {
					pipeline = validPipeline
				}
				directory = pipelineConfig(t, map[string]string{"auth.yaml": pipeline})
			}

			files, err := LoadFiles(directory, EnvironmentDevelopment, getenv(fetcherSecrets))

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("LoadFiles() error = %v, want an error containing %q", err, wantError)
				}
			}
			for _, wantNoErrorText := range test.wantNoErrorTexts {
				if err != nil && strings.Contains(err.Error(), wantNoErrorText) {
					t.Fatalf("LoadFiles() error = %v, must not contain %q", err, wantNoErrorText)
				}
			}
			if len(test.wantErrors) > 0 {
				if !reflect.DeepEqual(files, Files{}) {
					t.Fatalf("LoadFiles() = %+v, want the zero Files when validation fails", files)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFiles() error = %v, want nil", err)
			}
			if test.check != nil {
				test.check(t, files)
			}
		})
	}
}

func TestResolveVariables(t *testing.T) {
	pointer := func(value string) *string {
		return &value
	}

	tests := []struct {
		name       string
		variables  map[string]Variable
		overrides  map[string]string
		want       map[string]string
		wantErrors []string
	}{
		{
			name: "override wins",
			variables: map[string]Variable{
				"lookback": {Type: "duration", Default: pointer("15m")},
			},
			overrides: map[string]string{"lookback": "1h"},
			want:      map[string]string{"lookback": "1h0m0s"},
		},
		{
			name: "default is used",
			variables: map[string]Variable{
				"lookback": {Type: "duration", Default: pointer("15m")},
			},
			want: map[string]string{"lookback": "15m0s"},
		},
		{
			name: "required variable missing",
			variables: map[string]Variable{
				"user": {Type: "string", Required: true},
			},
			wantErrors: []string{"user", "required"},
		},
		{
			name: "required variable overridden",
			variables: map[string]Variable{
				"user": {Type: "string", Required: true},
			},
			overrides: map[string]string{"user": "alice"},
			want:      map[string]string{"user": "alice"},
		},
		{
			name: "wrong type",
			variables: map[string]Variable{
				"since": {Type: "timestamp"},
			},
			overrides:  map[string]string{"since": "yesterday"},
			wantErrors: []string{"since", "timestamp"},
		},
		{
			name: "unknown override",
			variables: map[string]Variable{
				"lookback": {Type: "duration", Default: pointer("15m")},
			},
			overrides:  map[string]string{"missing": "value"},
			wantErrors: []string{"missing", "not declared"},
		},
		{
			name: "optional variable without a value is absent",
			variables: map[string]Variable{
				"optional": {Type: "string"},
			},
			want: map[string]string{},
		},
		{
			name: "integer is canonical",
			variables: map[string]Variable{
				"count": {Type: "int"},
			},
			overrides: map[string]string{"count": "007"},
			want:      map[string]string{"count": "7"},
		},
		{
			name: "timestamp is canonical UTC",
			variables: map[string]Variable{
				"since": {Type: "timestamp"},
			},
			overrides: map[string]string{"since": "2026-11-14T10:00:00+02:00"},
			want:      map[string]string{"since": "2026-11-14T08:00:00Z"},
		},
		{
			name: "string is unchanged",
			variables: map[string]Variable{
				"user": {Type: "string"},
			},
			overrides: map[string]string{"user": "alice@example.com"},
			want:      map[string]string{"user": "alice@example.com"},
		},
		{
			name: "all declared variables",
			variables: map[string]Variable{
				"lookback": {Type: "duration", Default: pointer("15m")},
				"count":    {Type: "int", Default: pointer("10")},
			},
			want: map[string]string{"lookback": "15m0s", "count": "10"},
		},
		{
			name: "invalid duration override",
			variables: map[string]Variable{
				"lookback": {Type: "duration", Default: pointer("15m")},
			},
			overrides:  map[string]string{"lookback": "soon"},
			wantErrors: []string{"lookback", "duration"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pipeline := Pipeline{Variables: test.variables}
			resolved, err := pipeline.ResolveVariables(test.overrides)

			for _, wantError := range test.wantErrors {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("ResolveVariables() error = %v, want an error containing %q", err, wantError)
				}
			}
			if len(test.wantErrors) > 0 {
				if resolved != nil {
					t.Fatalf("ResolveVariables() = %v, want nil when resolution fails", resolved)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveVariables() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(resolved, test.want) {
				t.Fatalf("ResolveVariables() = %v, want %v", resolved, test.want)
			}
		})
	}
}

func TestSecretValueNotPrinted(t *testing.T) {
	environment := map[string]string{
		"ELASTIC_PROD_API_KEY": knownSecretValue,
		"ELASTIC_PROD_CA":      knownSecretValue,
		"ELASTIC_EDR_USERNAME": knownSecretValue,
		"ELASTIC_EDR_PASSWORD": knownSecretValue,
	}
	files, err := LoadFiles(validConfigDirectory, EnvironmentDevelopment, getenv(environment))
	if err != nil {
		t.Fatalf("LoadFiles() error = %v, want nil", err)
	}

	formatted := fmt.Sprintf("%+v", files)
	if strings.Contains(formatted, knownSecretValue) {
		t.Fatalf("formatted configuration must not contain the secret value")
	}
	if !strings.Contains(formatted, "${secret:ELASTIC_PROD_API_KEY}") {
		t.Fatalf("formatted configuration must show the secret reference")
	}

	jsonData, err := json.Marshal(files)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(jsonData), knownSecretValue) {
		t.Fatalf("JSON configuration must not contain the secret value")
	}
	if !strings.Contains(string(jsonData), "${secret:ELASTIC_PROD_API_KEY}") {
		t.Fatalf("JSON configuration must show the secret reference")
	}

	yamlData, err := yaml.Marshal(files)
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}
	if strings.Contains(string(yamlData), knownSecretValue) {
		t.Fatalf("YAML configuration must not contain the secret value")
	}
	if !strings.Contains(string(yamlData), "${secret:ELASTIC_PROD_API_KEY}") {
		t.Fatalf("YAML configuration must show the secret reference")
	}
}
