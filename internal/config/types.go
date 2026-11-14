package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// Duration is a time.Duration decoded from a YAML string such as "72h".
type Duration time.Duration

func (duration *Duration) UnmarshalYAML(data []byte) error {
	var value string
	if err := yaml.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("duration must be a string such as \"30s\"")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration %q", value)
	}
	*duration = Duration(parsed)
	return nil
}

// SecretRef names an environment variable holding a credential. It prints as
// ${secret:NAME}, never as the value.
type SecretRef struct {
	Name string
}

var secretReferencePattern = regexp.MustCompile(`^\$\{secret:([A-Z][A-Z0-9_]{0,127})\}$`)

func (ref *SecretRef) UnmarshalYAML(data []byte) error {
	var value string
	if err := yaml.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("credentials must be secret references")
	}
	match := secretReferencePattern.FindStringSubmatch(value)
	if match == nil {
		return fmt.Errorf("credentials must be secret references")
	}
	ref.Name = match[1]
	return nil
}

func (ref SecretRef) String() string {
	return "${secret:" + ref.Name + "}"
}

func (ref SecretRef) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(ref.String())), nil
}

func (ref SecretRef) MarshalYAML() ([]byte, error) {
	return []byte(strconv.Quote(ref.String())), nil
}

func (ref SecretRef) Resolve(getenv func(string) string) (string, error) {
	value := getenv(ref.Name)
	if value == "" {
		return "", fmt.Errorf("secret %s is not set", ref.Name)
	}
	return value, nil
}

// Files is the complete, validated file configuration.
type Files struct {
	Directory string
	System    System
	Fetchers  map[string]FetcherInstance // key = instance id
	Pipelines []Pipeline                 // sorted by id
}

type System struct {
	Version string          `yaml:"version"` // must be 0.1
	Stores  Stores          `yaml:"stores"`  // stores.dataset_cache
	Secrets SecretsSettings `yaml:"secrets"` // secrets.provider, only "env"
	Runner  RunnerSettings  `yaml:"runner"`  // runner.batch_size, runner.max_quarantine_ratio
}

type Stores struct {
	DatasetCache DatasetCacheStore `yaml:"dataset_cache"`
}

type DatasetCacheStore struct {
	Type                   string   `yaml:"type"`                     // only "postgres"
	DefaultRetention       Duration `yaml:"default_retention"`        // default 72h; 1h..2160h (90d)
	DefaultAllowedLateness Duration `yaml:"default_allowed_lateness"` // default 10m; >= 0 and < DefaultRetention
}

type SecretsSettings struct {
	Provider string `yaml:"provider"` // only "env"
}

type RunnerSettings struct {
	BatchSize          int     `yaml:"batch_size"`           // default 5000; 1..50000
	MaxQuarantineRatio float64 `yaml:"max_quarantine_ratio"` // default 0.10; > 0 and <= 1
}

type FetcherInstance struct {
	ID             string          `yaml:"-"` // from the map key
	Type           string          `yaml:"type"`
	Addresses      []string        `yaml:"addresses"`
	Auth           FetcherAuth     `yaml:"auth"`
	TLS            FetcherTLS      `yaml:"tls"`
	Defaults       FetcherDefaults `yaml:"defaults"`
	AllowedIndexes []string        `yaml:"allowed_indexes"` // required, non-empty
}

type FetcherAuth struct {
	APIKey   *SecretRef `yaml:"api_key"`
	Username *SecretRef `yaml:"username"`
	Password *SecretRef `yaml:"password"`
}

type FetcherTLS struct {
	CARef              *SecretRef `yaml:"ca_ref"`
	InsecureSkipVerify bool       `yaml:"insecure_skip_verify"`
}

type FetcherDefaults struct {
	Index      string   `yaml:"index"`       // optional; must pass IndexAllowed
	Timeout    Duration `yaml:"timeout"`     // default 30s; <= 10m
	MaxResults int      `yaml:"max_results"` // default 10000; 1..1000000
	TimeField  string   `yaml:"time_field"`  // default "@timestamp"
}

type Pipeline struct {
	File       string              `yaml:"-"` // path relative to the config directory
	ID         string              `yaml:"id"`
	Version    string              `yaml:"version"`
	Schedule   Schedule            `yaml:"schedule"`
	Variables  map[string]Variable `yaml:"variables"`
	Fetchers   []FetcherStep       `yaml:"fetchers"`
	Processors []Processor         `yaml:"processors"`
	Outputs    map[string]Output   `yaml:"outputs"` // key = dataset name
}

type Schedule struct {
	Every         Duration `yaml:"every"`          // optional in Phase 1; > 0 when set
	Timeout       Duration `yaml:"timeout"`        // required; > 0, <= 1h
	OverlapPolicy string   `yaml:"overlap_policy"` // skip (default) | queue | parallel
}

type Variable struct {
	Type     string  `yaml:"type"`     // string | duration | timestamp | int
	Required bool    `yaml:"required"` //
	Default  *string `yaml:"default"`  // must parse as Type
}

type FetcherStep struct {
	ID     string           `yaml:"id"`
	Ref    string           `yaml:"ref"`    // fetcher instance id
	Inputs map[string]Input `yaml:"inputs"` //
}

var variableReferencePattern = regexp.MustCompile(`^\$\{variables\.([^}]+)\}$`)

// Input is a literal or exactly one ${variables.name} reference.
type Input struct {
	Literal  string
	Variable string
}

func (input *Input) UnmarshalYAML(data []byte) error {
	var value string
	if err := yaml.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("an input must be a scalar value")
	}
	if match := variableReferencePattern.FindStringSubmatch(value); match != nil {
		input.Variable = match[1]
		return nil
	}
	if strings.Contains(value, "${") && !strings.Contains(value, "${secret:") {
		return fmt.Errorf("an input must be a literal or exactly one ${variables.NAME} reference")
	}
	input.Literal = value
	return nil
}

type Processor struct {
	ID       string   `yaml:"id"`
	Type     string   `yaml:"type"`     // only "converter"
	From     string   `yaml:"from"`     // "<fetcher step id>.records"
	Mappings []string `yaml:"mappings"` // paths relative to the config directory
	Output   string   `yaml:"output"`   // "udm.<name>"
}

type Output struct {
	From            string    `yaml:"from"`             // "udm.<name>", a processor output
	Retention       *Duration `yaml:"retention"`        // default: system default_retention
	AllowedLateness *Duration `yaml:"allowed_lateness"` // default: system default_allowed_lateness
}
