package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

const (
	maxConfigFileSize = 1 << 20 // 1 MiB

	supportedSystemVersion  = "0.1"
	defaultSecretProvider   = "env"
	defaultDatasetCacheType = "postgres"

	defaultRetention       = 72 * time.Hour
	minRetention           = 1 * time.Hour
	maxRetention           = 2160 * time.Hour
	defaultAllowedLateness = 10 * time.Minute

	defaultBatchSize          = 5000
	minBatchSize              = 1
	maxBatchSize              = 50000
	defaultMaxQuarantineRatio = 0.10

	defaultIngestDelay = time.Minute
	maxIngestDelay     = time.Hour
	defaultOverlap     = time.Minute
	maxOverlap         = time.Hour
	defaultMaxCatchUp  = 6 * time.Hour
	minMaxCatchUp      = time.Minute

	defaultFetcherTimeout    = 30 * time.Second
	maxFetcherTimeout        = 10 * time.Minute
	defaultFetcherMaxResults = 10000
	minFetcherMaxResults     = 1
	maxFetcherMaxResults     = 1000000
	defaultFetcherTimeField  = "@timestamp"

	defaultFetchTimeField = "event.ingested"

	defaultFetcherPageSize = 1000
	minFetcherPageSize     = 1
	maxFetcherPageSize     = 10000

	defaultFetcherMaxBytes = 256 << 20
	minFetcherMaxBytes     = 1 << 20
	maxFetcherMaxBytes     = 2 << 30

	defaultFetcherKeepAlive = time.Minute
	minFetcherKeepAlive     = 10 * time.Second
	maxFetcherKeepAlive     = 10 * time.Minute

	fetcherTypeElasticsearch = "elasticsearch"
)

var (
	identifierPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	indexPattern               = regexp.MustCompile(`^[a-z0-9*][a-z0-9._*-]*$`)
	datasetPattern             = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	variableNamePattern        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	versionPattern             = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	templatePlaceholderPattern = regexp.MustCompile(`^\$\{parameters\.([a-z][a-z0-9_]{0,62})\}$`)
	timeFieldPattern           = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,255}$`)

	reservedTemplateParameterNames = []string{"start", "end", "index"}
)

// LoadFiles loads and validates the file configuration in directory. Every
// problem is returned joined, and the Files value is zero when any exists.
func LoadFiles(directory string, environment Environment, getenv func(string) string) (Files, error) {
	var problems []error

	system, systemLoaded, systemProblems := loadSystem(directory)
	problems = append(problems, systemProblems...)

	fetchers, fetcherProblems := loadFetchers(directory)
	problems = append(problems, fetcherProblems...)

	templates, templateFileProblems := loadQueryTemplates(directory)
	problems = append(problems, templateFileProblems...)
	queryTemplates, templateProblems := validateQueryTemplates(templates)
	problems = append(problems, templateProblems...)

	pipelines, pipelineProblems := loadPipelines(directory)
	problems = append(problems, pipelineProblems...)

	problems = append(problems, checkSecrets(fetchers, getenv)...)
	problems = append(problems, checkSecretPlacement(fetchers, pipelines)...)
	problems = append(problems, validateFetchers(fetchers, environment)...)
	problems = append(problems, validatePipelines(directory, pipelines, system, queryTemplates, fetchers, systemLoaded)...)

	if err := errors.Join(problems...); err != nil {
		return Files{}, err
	}

	return Files{
		Directory:      directory,
		System:         system,
		Fetchers:       fetchers,
		QueryTemplates: queryTemplates,
		Pipelines:      pipelines,
	}, nil
}

func loadSystem(directory string) (System, bool, []error) {
	data, err := readConfigFile(directory, "system.yaml")
	if err != nil {
		return System{}, false, []error{err}
	}

	var file systemFile
	if err := decodeStrict(data, &file); err != nil {
		return System{}, false, []error{fmt.Errorf("system.yaml: %w", err)}
	}

	system := System{
		Version: file.Version,
		Stores: Stores{DatasetCache: DatasetCacheStore{
			Type:                   file.Stores.DatasetCache.Type,
			DefaultRetention:       Duration(defaultRetention),
			DefaultAllowedLateness: Duration(defaultAllowedLateness),
		}},
		Secrets: SecretsSettings{Provider: file.Secrets.Provider},
		Runner:  RunnerSettings{BatchSize: defaultBatchSize, MaxQuarantineRatio: defaultMaxQuarantineRatio},
	}
	if system.Stores.DatasetCache.Type == "" {
		system.Stores.DatasetCache.Type = defaultDatasetCacheType
	}
	if system.Secrets.Provider == "" {
		system.Secrets.Provider = defaultSecretProvider
	}

	var problems []error
	if system.Version != supportedSystemVersion {
		problems = append(problems, fileError("system.yaml", "version", fmt.Sprintf("must be %q", supportedSystemVersion)))
	}
	if system.Stores.DatasetCache.Type != defaultDatasetCacheType {
		problems = append(problems, fileError("system.yaml", "stores.dataset_cache.type",
			fmt.Sprintf("unsupported dataset cache type %q", system.Stores.DatasetCache.Type)))
	}
	if system.Secrets.Provider != defaultSecretProvider {
		problems = append(problems, fileError("system.yaml", "secrets.provider",
			fmt.Sprintf("unsupported secret provider %q", system.Secrets.Provider)))
	}

	if file.Stores.DatasetCache.DefaultRetention != nil {
		retention := *file.Stores.DatasetCache.DefaultRetention
		if retention < Duration(minRetention) || retention > Duration(maxRetention) {
			problems = append(problems, fileError("system.yaml", "stores.dataset_cache.default_retention",
				fmt.Sprintf("must be between %s and %s", minRetention, maxRetention)))
		} else {
			system.Stores.DatasetCache.DefaultRetention = retention
		}
	}
	if file.Stores.DatasetCache.DefaultAllowedLateness != nil {
		lateness := *file.Stores.DatasetCache.DefaultAllowedLateness
		retention := system.Stores.DatasetCache.DefaultRetention
		if lateness < 0 || lateness >= retention {
			problems = append(problems, fileError("system.yaml", "stores.dataset_cache.default_allowed_lateness",
				"must be at least 0 and less than default_retention"))
		} else {
			system.Stores.DatasetCache.DefaultAllowedLateness = lateness
		}
	}

	if file.Runner.BatchSize != nil {
		if *file.Runner.BatchSize < minBatchSize || *file.Runner.BatchSize > maxBatchSize {
			problems = append(problems, fileError("system.yaml", "runner.batch_size",
				fmt.Sprintf("must be between %d and %d", minBatchSize, maxBatchSize)))
		} else {
			system.Runner.BatchSize = *file.Runner.BatchSize
		}
	}
	if file.Runner.MaxQuarantineRatio != nil {
		if *file.Runner.MaxQuarantineRatio <= 0 || *file.Runner.MaxQuarantineRatio > 1 {
			problems = append(problems, fileError("system.yaml", "runner.max_quarantine_ratio",
				"must be greater than 0 and at most 1"))
		} else {
			system.Runner.MaxQuarantineRatio = *file.Runner.MaxQuarantineRatio
		}
	}

	return system, true, problems
}

func loadFetchers(directory string) (map[string]FetcherInstance, []error) {
	data, err := readConfigFile(directory, "fetchers.yaml")
	if err != nil {
		return nil, []error{err}
	}

	var document struct {
		Fetchers map[string]yaml.RawMessage `yaml:"fetchers"`
	}
	if err := decodeStrict(data, &document); err != nil {
		return nil, []error{fmt.Errorf("fetchers.yaml: %w", err)}
	}

	fetchers := make(map[string]FetcherInstance, len(document.Fetchers))
	var problems []error
	for _, id := range slices.Sorted(maps.Keys(document.Fetchers)) {
		var file fetcherFile
		if err := decodeStrict(document.Fetchers[id], &file); err != nil {
			problems = append(problems, fmt.Errorf("fetchers.yaml: fetchers.%s: %w", id, err))
			continue
		}
		instance := FetcherInstance{
			ID:             id,
			Type:           file.Type,
			Addresses:      file.Addresses,
			Auth:           file.Auth,
			TLS:            file.TLS,
			AllowedIndexes: file.AllowedIndexes,
			Defaults: FetcherDefaults{
				Index:          file.Defaults.Index,
				Timeout:        Duration(defaultFetcherTimeout),
				MaxResults:     defaultFetcherMaxResults,
				TimeField:      defaultFetcherTimeField,
				FetchTimeField: defaultFetchTimeField,
				PageSize:       defaultFetcherPageSize,
				MaxBytes:       defaultFetcherMaxBytes,
				KeepAlive:      Duration(defaultFetcherKeepAlive),
			},
		}
		if file.Defaults.Timeout != nil {
			instance.Defaults.Timeout = *file.Defaults.Timeout
		}
		if file.Defaults.MaxResults != nil {
			instance.Defaults.MaxResults = *file.Defaults.MaxResults
		}
		if file.Defaults.TimeField != "" {
			instance.Defaults.TimeField = file.Defaults.TimeField
		}
		if file.Defaults.FetchTimeField != nil {
			instance.Defaults.FetchTimeField = *file.Defaults.FetchTimeField
		}
		if file.Defaults.PageSize != nil {
			instance.Defaults.PageSize = *file.Defaults.PageSize
		}
		if file.Defaults.MaxBytes != nil {
			instance.Defaults.MaxBytes = *file.Defaults.MaxBytes
		}
		if file.Defaults.KeepAlive != nil {
			instance.Defaults.KeepAlive = *file.Defaults.KeepAlive
		}
		fetchers[id] = instance
	}
	return fetchers, problems
}

// yamlDirectoryFiles returns the .yaml files under directory/subdirectory and
// reports .yml or case-mismatched extensions.
func yamlDirectoryFiles(directory string, subdirectory string, kind string) ([]string, []error) {
	entries, err := os.ReadDir(filepath.Join(directory, subdirectory))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("%s: %w", subdirectory, err)}
	}

	var names []string
	var problems []error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := filepath.Join(subdirectory, entry.Name())
		extension := filepath.Ext(entry.Name())
		switch strings.ToLower(extension) {
		case ".yml":
			problems = append(problems, fileError(name, "extension", kind+" files must use the .yaml extension"))
			continue
		case ".yaml":
			if extension != ".yaml" {
				problems = append(problems, fileError(name, "extension", kind+" files must use the .yaml extension"))
				continue
			}
		default:
			continue
		}
		names = append(names, name)
	}
	return names, problems
}

func loadQueryTemplates(directory string) ([]QueryTemplate, []error) {
	names, problems := yamlDirectoryFiles(directory, "query_templates", "query template")

	var templates []QueryTemplate
	for _, name := range names {
		data, err := readConfigFile(directory, name)
		if err != nil {
			problems = append(problems, err)
			continue
		}

		var file queryTemplateFile
		if err := decodeStrict(data, &file); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", name, err))
			continue
		}

		templates = append(templates, QueryTemplate{
			File:        name,
			ID:          file.ID,
			FetcherType: file.FetcherType,
			Version:     file.Version,
			Description: file.Description,
			Parameters:  file.Parameters,
			RawQuery:    file.RawQuery,
		})
	}
	return templates, problems
}

func loadPipelines(directory string) ([]Pipeline, []error) {
	names, problems := yamlDirectoryFiles(directory, "pipelines", "pipeline")

	var pipelines []Pipeline
	for _, name := range names {
		data, err := readConfigFile(directory, name)
		if err != nil {
			problems = append(problems, err)
			continue
		}

		var file pipelineFile
		if err := decodeStrict(data, &file); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", name, err))
			continue
		}

		pipeline := Pipeline{
			File:      name,
			ID:        file.ID,
			Version:   file.Version,
			Variables: file.Variables,
			Fetchers:  file.Fetchers,
			Schedule: Schedule{
				IngestDelay:   Duration(defaultIngestDelay),
				Overlap:       Duration(defaultOverlap),
				OverlapPolicy: file.Schedule.OverlapPolicy,
			},
			Processors: file.Processors,
			Outputs:    file.Outputs,
		}
		if file.Schedule.Every != nil {
			// Pipeline.Schedule cannot tell an absent every from an explicit
			// zero, so reject the zero while its presence is still known.
			pipeline.Schedule.Every = *file.Schedule.Every
			if *file.Schedule.Every <= 0 {
				problems = append(problems, fileError(name, "schedule.every", "must be positive"))
			}
		}
		if file.Schedule.Timeout != nil {
			pipeline.Schedule.Timeout = *file.Schedule.Timeout
		}
		if file.Schedule.IngestDelay != nil {
			pipeline.Schedule.IngestDelay = *file.Schedule.IngestDelay
		}
		if file.Schedule.Overlap != nil {
			pipeline.Schedule.Overlap = *file.Schedule.Overlap
		}
		if file.Schedule.MaxCatchUp != nil {
			pipeline.Schedule.MaxCatchUp = *file.Schedule.MaxCatchUp
			// Zero means absent (the default is applied with the outputs), so
			// the minimum is checked while presence is still known.
			if *file.Schedule.MaxCatchUp < Duration(minMaxCatchUp) {
				problems = append(problems, fileError(name, "schedule.max_catch_up",
					fmt.Sprintf("must be at least %s", minMaxCatchUp)))
			}
		}
		pipelines = append(pipelines, pipeline)
	}

	slices.SortFunc(pipelines, func(a, b Pipeline) int {
		return strings.Compare(a.ID, b.ID)
	})
	return pipelines, problems
}

// IndexAllowed reports whether index matches at least one allowlist entry,
// where only the allowlist entry may contain a wildcard. An index that fails
// the index-pattern rule is never allowed, so a comma or any other separator
// cannot ride a wildcard into another index.
func IndexAllowed(index string, allowlist []string) bool {
	if !validIndexPattern(index) {
		return false
	}
	for _, entry := range allowlist {
		if matched, err := path.Match(entry, index); err == nil && matched {
			return true
		}
	}
	return false
}

// ParseEnvironment parses SIMPLE_SIEM_ENV; empty means production.
func ParseEnvironment(value string) (Environment, error) {
	switch Environment(value) {
	case "":
		return EnvironmentProduction, nil
	case EnvironmentDevelopment, EnvironmentProduction:
		return Environment(value), nil
	default:
		return "", fmt.Errorf("%s must be %q or %q", environmentVariable, EnvironmentDevelopment, EnvironmentProduction)
	}
}

func validateFetchers(fetchers map[string]FetcherInstance, environment Environment) []error {
	var problems []error
	for _, id := range slices.Sorted(maps.Keys(fetchers)) {
		instance := fetchers[id]
		prefix := "fetchers." + id + "."

		if !identifierPattern.MatchString(id) {
			problems = append(problems, fileError("fetchers.yaml", "fetchers."+id, "invalid fetcher instance id"))
		}
		if instance.Type != "elasticsearch" {
			problems = append(problems, fileError("fetchers.yaml", prefix+"type",
				fmt.Sprintf("unsupported fetcher type %q", instance.Type)))
		}
		if len(instance.Addresses) == 0 {
			problems = append(problems, fileError("fetchers.yaml", prefix+"addresses", "at least one address is required"))
		}
		for index, address := range instance.Addresses {
			if err := validateFetcherAddress(address, environment); err != nil {
				problems = append(problems, fileError("fetchers.yaml", fmt.Sprintf("%saddresses[%d]", prefix, index), err.Error()))
			}
		}

		hasAPIKey := instance.Auth.APIKey != nil
		hasUsername := instance.Auth.Username != nil
		hasPassword := instance.Auth.Password != nil
		mixedAuth := hasAPIKey && (hasUsername || hasPassword)
		incompleteBasicAuth := !hasAPIKey && (!hasUsername || !hasPassword)
		if mixedAuth || incompleteBasicAuth {
			problems = append(problems, fileError("fetchers.yaml", prefix+"auth",
				"exactly one of api_key or username and password is required"))
		}
		if instance.TLS.InsecureSkipVerify && environment != EnvironmentDevelopment {
			problems = append(problems, fileError("fetchers.yaml", prefix+"tls.insecure_skip_verify",
				"is only allowed in development"))
		}

		if len(instance.AllowedIndexes) == 0 {
			problems = append(problems, fileError("fetchers.yaml", prefix+"allowed_indexes", "at least one index pattern is required"))
		}
		for index, pattern := range instance.AllowedIndexes {
			if !validIndexPattern(pattern) {
				problems = append(problems, fileError("fetchers.yaml", fmt.Sprintf("%sallowed_indexes[%d]", prefix, index),
					fmt.Sprintf("invalid index pattern %q", pattern)))
			}
		}

		defaults := instance.Defaults
		if defaults.Timeout <= 0 || defaults.Timeout > Duration(maxFetcherTimeout) {
			problems = append(problems, fileError("fetchers.yaml", prefix+"defaults.timeout",
				fmt.Sprintf("must be positive and at most %s", maxFetcherTimeout)))
		}
		if defaults.MaxResults < minFetcherMaxResults || defaults.MaxResults > maxFetcherMaxResults {
			problems = append(problems, fileError("fetchers.yaml", prefix+"defaults.max_results",
				fmt.Sprintf("must be between %d and %d", minFetcherMaxResults, maxFetcherMaxResults)))
		}
		if !timeFieldPattern.MatchString(defaults.FetchTimeField) {
			problems = append(problems, fileError("fetchers.yaml", prefix+"defaults.fetch_time_field",
				"must be 1 to 255 characters from A-Z, a-z, 0-9, _ . @ -"))
		}
		if !timeFieldPattern.MatchString(defaults.TimeField) {
			problems = append(problems, fileError("fetchers.yaml", prefix+"defaults.time_field",
				"must be 1 to 255 characters from A-Z, a-z, 0-9, _ . @ -"))
		}
		if defaults.PageSize < minFetcherPageSize || defaults.PageSize > maxFetcherPageSize {
			problems = append(problems, fileError("fetchers.yaml", prefix+"defaults.page_size",
				fmt.Sprintf("must be between %d and %d", minFetcherPageSize, maxFetcherPageSize)))
		}
		if defaults.MaxBytes < minFetcherMaxBytes || defaults.MaxBytes > maxFetcherMaxBytes {
			problems = append(problems, fileError("fetchers.yaml", prefix+"defaults.max_bytes",
				fmt.Sprintf("must be between %d (1 MiB) and %d (2 GiB) bytes", minFetcherMaxBytes, maxFetcherMaxBytes)))
		}
		if defaults.KeepAlive < Duration(minFetcherKeepAlive) || defaults.KeepAlive > Duration(maxFetcherKeepAlive) {
			problems = append(problems, fileError("fetchers.yaml", prefix+"defaults.keep_alive",
				fmt.Sprintf("must be between %s and %s", minFetcherKeepAlive, maxFetcherKeepAlive)))
		}
		if defaults.Index != "" {
			if !validIndexPattern(defaults.Index) {
				problems = append(problems, fileError("fetchers.yaml", prefix+"defaults.index",
					fmt.Sprintf("invalid index pattern %q", defaults.Index)))
			} else if !IndexAllowed(defaults.Index, instance.AllowedIndexes) {
				problems = append(problems, fileError("fetchers.yaml", prefix+"defaults.index",
					fmt.Sprintf("index %q is not allowed by allowed_indexes", defaults.Index)))
			}
		}
	}
	return problems
}

func validateQueryTemplates(templates []QueryTemplate) (map[string]QueryTemplate, []error) {
	validated := make(map[string]QueryTemplate, len(templates))
	templateFiles := make(map[string]string, len(templates))
	var problems []error

	for _, template := range templates {
		if !identifierPattern.MatchString(template.ID) {
			problems = append(problems, fileError(template.File, "id", "invalid query template id"))
		}
		if previous, exists := templateFiles[template.ID]; exists {
			problems = append(problems, fileError(template.File, "id",
				fmt.Sprintf("duplicate query template id %q, also used by %s", template.ID, previous)))
		} else {
			templateFiles[template.ID] = template.File
		}
		if template.FetcherType != fetcherTypeElasticsearch {
			problems = append(problems, fileError(template.File, "fetcherType",
				fmt.Sprintf("unsupported fetcher type %q", template.FetcherType)))
		}
		if !versionPattern.MatchString(template.Version) {
			problems = append(problems, fileError(template.File, "version", "must be MAJOR.MINOR.PATCH"))
		}
		if template.RawQuery == nil {
			problems = append(problems, fileError(template.File, "rawQuery", "must be a mapping"))
		}

		problems = append(problems, validateTemplateParameters(template)...)
		problems = append(problems, validateTemplatePlaceholders(template)...)

		if _, exists := validated[template.ID]; !exists {
			validated[template.ID] = template
		}
	}
	return validated, problems
}

func validateTemplateParameters(template QueryTemplate) []error {
	var problems []error
	for _, name := range slices.Sorted(maps.Keys(template.Parameters)) {
		path := "parameters." + name
		parameter := template.Parameters[name]
		if !variableNamePattern.MatchString(name) {
			problems = append(problems, fileError(template.File, path, "invalid parameter name"))
		}
		if !validTemplateParameterType(parameter.Type) {
			problems = append(problems, fileError(template.File, path+".type", "must be string, int, bool or timestamp"))
		}
		if slices.Contains(reservedTemplateParameterNames, name) {
			problems = append(problems, fileError(template.File, path, fmt.Sprintf("parameter name %q is reserved", name)))
		}
	}
	return problems
}

func validTemplateParameterType(parameterType string) bool {
	switch parameterType {
	case "string", "int", "bool", "timestamp":
		return true
	default:
		return false
	}
}

func validateTemplatePlaceholders(template QueryTemplate) []error {
	used := make(map[string]string)
	problems := collectTemplatePlaceholders(template.File, template.RawQuery, "rawQuery", used)

	for _, name := range slices.Sorted(maps.Keys(used)) {
		if _, declared := template.Parameters[name]; !declared {
			problems = append(problems, fileError(template.File, used[name],
				fmt.Sprintf("placeholder names undeclared parameter %q", name)))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(template.Parameters)) {
		if _, found := used[name]; !found {
			problems = append(problems, fileError(template.File, "parameters."+name,
				fmt.Sprintf("parameter %q is not used in rawQuery", name)))
		}
	}
	return problems
}

// collectTemplatePlaceholders walks the raw query and records where each
// parameter placeholder appears.
func collectTemplatePlaceholders(file string, value any, path string, used map[string]string) []error {
	switch value := value.(type) {
	case map[string]any:
		var problems []error
		for _, key := range slices.Sorted(maps.Keys(value)) {
			if strings.Contains(key, "${") {
				problems = append(problems, fileError(file, path, "placeholder in a mapping key"))
				continue
			}
			problems = append(problems, collectTemplatePlaceholders(file, value[key], path+"."+key, used)...)
		}
		return problems
	case []any:
		var problems []error
		for index, item := range value {
			problems = append(problems, collectTemplatePlaceholders(file, item, fmt.Sprintf("%s[%d]", path, index), used)...)
		}
		return problems
	case string:
		if !strings.Contains(value, "${") {
			return nil
		}
		match := templatePlaceholderPattern.FindStringSubmatch(value)
		if match == nil {
			return []error{fileError(file, path, "placeholder must be a whole string value of the form ${parameters.NAME}")}
		}
		used[match[1]] = path
	}
	return nil
}

func validateFetcherAddress(address string, environment Environment) error {
	parsed, err := url.Parse(address)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("must be an absolute http or https URL")
	}
	if parsed.User != nil {
		return fmt.Errorf("must not contain user information")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("must not contain a query or fragment")
	}
	if parsed.Scheme == "http" && environment != EnvironmentDevelopment {
		return fmt.Errorf("http is only allowed in development")
	}
	return nil
}

func validIndexPattern(pattern string) bool {
	if len(pattern) == 0 || len(pattern) > 255 || !indexPattern.MatchString(pattern) {
		return false
	}
	for _, character := range pattern {
		if !strings.ContainsRune("*-._", character) {
			return true
		}
	}
	return false
}

// ResolveVariables returns one canonical string per declared variable, from
// run overrides first and pipeline defaults second.
func (pipeline Pipeline) ResolveVariables(overrides map[string]string) (map[string]string, error) {
	var problems []error

	for _, name := range slices.Sorted(maps.Keys(overrides)) {
		if _, declared := pipeline.Variables[name]; !declared {
			problems = append(problems, fmt.Errorf("variable %q is not declared", name))
		}
	}

	resolved := make(map[string]string, len(pipeline.Variables))
	for _, name := range slices.Sorted(maps.Keys(pipeline.Variables)) {
		variable := pipeline.Variables[name]
		value, overridden := overrides[name]
		if !overridden {
			if variable.Default == nil {
				if variable.Required {
					problems = append(problems, fmt.Errorf("required variable %q is not set", name))
				}
				continue
			}
			value = *variable.Default
		}

		canonical, err := canonicalVariableValue(variable.Type, value)
		if err != nil {
			problems = append(problems, fmt.Errorf("variable %q must parse as %s", name, variable.Type))
			continue
		}
		resolved[name] = canonical
	}

	if err := errors.Join(problems...); err != nil {
		return nil, err
	}
	return resolved, nil
}

func validatePipelines(directory string, pipelines []Pipeline, system System, templates map[string]QueryTemplate, fetchers map[string]FetcherInstance, systemLoaded bool) []error {
	resolvedDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		resolvedDirectory = directory
	}

	var problems []error
	pipelineIDs := make(map[string]string, len(pipelines))
	datasetWriters := make(map[string]string)

	for index := range pipelines {
		pipeline := &pipelines[index]
		problems = append(problems, validatePipelineIdentity(pipeline, pipelineIDs)...)
		problems = append(problems, validatePipelineSchedule(pipeline)...)
		problems = append(problems, validatePipelineVariables(pipeline)...)

		stepIDs, stepProblems := validatePipelineFetchers(pipeline, fetchers, templates)
		problems = append(problems, stepProblems...)

		processorOutputs, processorProblems := validatePipelineProcessors(pipeline, resolvedDirectory, stepIDs)
		problems = append(problems, processorProblems...)

		problems = append(problems, validatePipelineOutputs(pipeline, system, processorOutputs, datasetWriters, systemLoaded)...)
	}

	return problems
}

func validatePipelineIdentity(pipeline *Pipeline, pipelineIDs map[string]string) []error {
	var problems []error
	if !identifierPattern.MatchString(pipeline.ID) {
		problems = append(problems, fileError(pipeline.File, "id", "invalid pipeline id"))
	}
	if previous, exists := pipelineIDs[pipeline.ID]; exists {
		problems = append(problems, fileError(pipeline.File, "id",
			fmt.Sprintf("duplicate pipeline id %q, also used by %s", pipeline.ID, previous)))
	} else {
		pipelineIDs[pipeline.ID] = pipeline.File
	}
	if !versionPattern.MatchString(pipeline.Version) {
		problems = append(problems, fileError(pipeline.File, "version", "must be MAJOR.MINOR.PATCH"))
	}
	return problems
}

func validatePipelineSchedule(pipeline *Pipeline) []error {
	var problems []error
	if pipeline.Schedule.Timeout <= 0 || pipeline.Schedule.Timeout > Duration(time.Hour) {
		problems = append(problems, fileError(pipeline.File, "schedule.timeout", "must be positive and at most 1h"))
	}
	if pipeline.Schedule.IngestDelay < 0 || pipeline.Schedule.IngestDelay > Duration(maxIngestDelay) {
		problems = append(problems, fileError(pipeline.File, "schedule.ingest_delay",
			fmt.Sprintf("must be between 0s and %s", maxIngestDelay)))
	}
	if pipeline.Schedule.Overlap < 0 || pipeline.Schedule.Overlap > Duration(maxOverlap) {
		problems = append(problems, fileError(pipeline.File, "schedule.overlap",
			fmt.Sprintf("must be between 0s and %s", maxOverlap)))
	}
	if pipeline.Schedule.OverlapPolicy == "" {
		pipeline.Schedule.OverlapPolicy = "skip"
	} else if !slices.Contains([]string{"skip", "queue", "parallel"}, pipeline.Schedule.OverlapPolicy) {
		problems = append(problems, fileError(pipeline.File, "schedule.overlap_policy", "must be skip, queue or parallel"))
	}
	return problems
}

func validatePipelineVariables(pipeline *Pipeline) []error {
	var problems []error
	for _, name := range slices.Sorted(maps.Keys(pipeline.Variables)) {
		variable := pipeline.Variables[name]
		path := "variables." + name
		if !variableNamePattern.MatchString(name) {
			problems = append(problems, fileError(pipeline.File, path, "invalid variable name"))
		}
		if !validVariableType(variable.Type) {
			problems = append(problems, fileError(pipeline.File, path+".type", "must be string, duration, timestamp or int"))
		}
		if variable.Required && variable.Default != nil {
			problems = append(problems, fileError(pipeline.File, path+".default", "a required variable must not have a default"))
		}
		if variable.Default != nil && validVariableType(variable.Type) {
			if _, err := canonicalVariableValue(variable.Type, *variable.Default); err != nil {
				problems = append(problems, fileError(pipeline.File, path+".default", fmt.Sprintf("must parse as %s", variable.Type)))
			}
		}
	}
	return problems
}

func validatePipelineFetchers(pipeline *Pipeline, fetchers map[string]FetcherInstance, templates map[string]QueryTemplate) (map[string]bool, []error) {
	var problems []error
	if len(pipeline.Fetchers) == 0 {
		problems = append(problems, fileError(pipeline.File, "fetchers", "at least one fetcher step is required"))
	}

	stepIDs := make(map[string]bool, len(pipeline.Fetchers))
	for stepIndex := range pipeline.Fetchers {
		step := &pipeline.Fetchers[stepIndex]
		prefix := fmt.Sprintf("fetchers[%d].", stepIndex)
		if !identifierPattern.MatchString(step.ID) {
			problems = append(problems, fileError(pipeline.File, prefix+"id", "invalid fetcher step id"))
		}
		if stepIDs[step.ID] {
			problems = append(problems, fileError(pipeline.File, prefix+"id", fmt.Sprintf("duplicate fetcher step id %q", step.ID)))
		} else {
			stepIDs[step.ID] = true
		}

		instance, known := fetchers[step.Ref]
		if !known {
			problems = append(problems, fileError(pipeline.File, prefix+"ref", fmt.Sprintf("unknown fetcher instance %q", step.Ref)))
		}

		for _, inputName := range slices.Sorted(maps.Keys(step.Inputs)) {
			input := step.Inputs[inputName]
			path := prefix + "inputs." + inputName
			if input.Variable != "" {
				if _, declared := pipeline.Variables[input.Variable]; !declared {
					problems = append(problems, fileError(pipeline.File, path, fmt.Sprintf("variable %q is not declared", input.Variable)))
				}
			}
			if inputName != "index" {
				continue
			}
			if input.Variable != "" {
				problems = append(problems, fileError(pipeline.File, path, "index must be a literal"))
				continue
			}
			if !validIndexPattern(input.Literal) {
				problems = append(problems, fileError(pipeline.File, path,
					fmt.Sprintf("invalid index pattern %q", input.Literal)))
			}
		}

		if known {
			problems = append(problems, validateEffectiveIndex(pipeline, step, prefix, instance)...)
		}

		if known && instance.Type == fetcherTypeElasticsearch {
			problems = append(problems, validateStepTemplate(pipeline, step, prefix, instance, templates)...)
		}
	}
	return stepIDs, problems
}

// validateEffectiveIndex requires the index a fetcher step will query — its
// index input, else the instance default — to be set and allowed. The runner
// repeats both checks as a defence.
func validateEffectiveIndex(pipeline *Pipeline, step *FetcherStep, prefix string, instance FetcherInstance) []error {
	index := instance.Defaults.Index
	if input, set := step.Inputs["index"]; set {
		if input.Variable != "" || !validIndexPattern(input.Literal) {
			return nil // the input's own error already fails validation
		}
		index = input.Literal
	}

	switch {
	case index == "":
		return []error{fileError(pipeline.File, prefix+"inputs.index",
			fmt.Sprintf("pipeline %q: step %q: fetcher instance %q has no default index and the step sets no index",
				pipeline.ID, step.ID, step.Ref))}
	case !IndexAllowed(index, instance.AllowedIndexes):
		return []error{fileError(pipeline.File, prefix+"inputs.index",
			fmt.Sprintf("pipeline %q: step %q: index %q is not allowed by fetcher instance %q",
				pipeline.ID, step.ID, index, step.Ref))}
	}
	return nil
}

func validateStepTemplate(pipeline *Pipeline, step *FetcherStep, prefix string, instance FetcherInstance, templates map[string]QueryTemplate) []error {
	templateInput, hasTemplate := step.Inputs["query_template"]
	if !hasTemplate {
		return []error{fileError(pipeline.File, prefix+"inputs.query_template", "a query template is required")}
	}
	if templateInput.Variable != "" {
		return []error{fileError(pipeline.File, prefix+"inputs.query_template", "query_template must be a literal")}
	}

	template, found := templates[templateInput.Literal]
	if !found {
		return []error{fileError(pipeline.File, prefix+"inputs.query_template",
			fmt.Sprintf("unknown query template %q", templateInput.Literal))}
	}
	if template.FetcherType != instance.Type {
		return []error{fileError(pipeline.File, prefix+"inputs.query_template",
			fmt.Sprintf("query template %q is for %s, but fetcher instance %q is %s",
				template.ID, template.FetcherType, instance.ID, instance.Type))}
	}

	var problems []error
	for _, inputName := range slices.Sorted(maps.Keys(step.Inputs)) {
		if inputName == "index" || inputName == "query_template" {
			continue
		}
		input := step.Inputs[inputName]
		parameter, declared := template.Parameters[inputName]
		path := prefix + "inputs." + inputName
		if !declared {
			problems = append(problems, fileError(pipeline.File, path,
				fmt.Sprintf("input is not declared by query template %q", template.ID)))
			continue
		}
		if input.Variable != "" {
			variable, found := pipeline.Variables[input.Variable]
			if found && variable.Type != parameter.Type {
				problems = append(problems, fileError(pipeline.File, path,
					fmt.Sprintf("variable %q has type %s, but parameter %q has type %s",
						input.Variable, variable.Type, inputName, parameter.Type)))
			}
			continue
		}
		if !validTemplateParameterValue(parameter.Type, input.Literal) {
			problems = append(problems, fileError(pipeline.File, path,
				fmt.Sprintf("must parse as %s", parameter.Type)))
		}
	}

	for _, name := range slices.Sorted(maps.Keys(template.Parameters)) {
		if _, supplied := step.Inputs[name]; template.Parameters[name].Required && !supplied {
			problems = append(problems, fileError(pipeline.File, prefix+"inputs."+name,
				fmt.Sprintf("query template %q requires parameter %q", template.ID, name)))
		}
	}
	return problems
}

func validTemplateParameterValue(parameterType string, value string) bool {
	switch parameterType {
	case "string":
		return true
	case "int":
		_, err := strconv.ParseInt(value, 10, 64)
		return err == nil
	case "bool":
		_, err := strconv.ParseBool(value)
		return err == nil
	case "timestamp":
		_, err := time.Parse(time.RFC3339, value)
		return err == nil
	default:
		return false
	}
}

func validatePipelineProcessors(pipeline *Pipeline, resolvedDirectory string, stepIDs map[string]bool) (map[string]bool, []error) {
	var problems []error
	if len(pipeline.Processors) == 0 {
		problems = append(problems, fileError(pipeline.File, "processors", "at least one processor is required"))
	}

	processorIDs := make(map[string]bool, len(pipeline.Processors))
	processorOutputs := make(map[string]bool, len(pipeline.Processors))
	for processorIndex := range pipeline.Processors {
		processor := &pipeline.Processors[processorIndex]
		prefix := fmt.Sprintf("processors[%d].", processorIndex)
		if !identifierPattern.MatchString(processor.ID) {
			problems = append(problems, fileError(pipeline.File, prefix+"id", "invalid processor id"))
		}
		if processorIDs[processor.ID] {
			problems = append(problems, fileError(pipeline.File, prefix+"id", fmt.Sprintf("duplicate processor id %q", processor.ID)))
		} else {
			processorIDs[processor.ID] = true
		}
		if processor.Type != "converter" {
			problems = append(problems, fileError(pipeline.File, prefix+"type", fmt.Sprintf("unsupported processor type %q", processor.Type)))
		}

		stepID, suffix, found := strings.Cut(processor.From, ".")
		if !found || suffix != "records" || !stepIDs[stepID] {
			problems = append(problems, fileError(pipeline.File, prefix+"from",
				fmt.Sprintf("%q must name a declared fetcher step followed by .records", processor.From)))
		}

		if len(processor.Mappings) == 0 {
			problems = append(problems, fileError(pipeline.File, prefix+"mappings", "at least one mapping file is required"))
		}
		for mappingIndex := range processor.Mappings {
			cleaned, err := validateMappingFile(resolvedDirectory, processor.Mappings[mappingIndex])
			if err != nil {
				problems = append(problems, fileError(pipeline.File, fmt.Sprintf("%smappings[%d]", prefix, mappingIndex), err.Error()))
				continue
			}
			processor.Mappings[mappingIndex] = cleaned
		}

		dataset, isUDM := strings.CutPrefix(processor.Output, "udm.")
		if !isUDM || !datasetPattern.MatchString(dataset) {
			problems = append(problems, fileError(pipeline.File, prefix+"output", `must be "udm.<dataset name>"`))
		}
		processorOutputs[processor.Output] = true
	}
	return processorOutputs, problems
}

func validatePipelineOutputs(pipeline *Pipeline, system System, processorOutputs map[string]bool, datasetWriters map[string]string, systemLoaded bool) []error {
	var problems []error
	if len(pipeline.Outputs) == 0 {
		problems = append(problems, fileError(pipeline.File, "outputs", "at least one output is required"))
	}

	// Catch-up may not read beyond what the shortest-lived output retains.
	var maxCatchUpRetention Duration
	var maxCatchUpOutput string

	for _, name := range slices.Sorted(maps.Keys(pipeline.Outputs)) {
		output := pipeline.Outputs[name]
		path := "outputs." + name
		if !datasetPattern.MatchString(name) {
			problems = append(problems, fileError(pipeline.File, path, "invalid dataset name"))
			continue
		}
		if output.From != "udm."+name {
			problems = append(problems, fileError(pipeline.File, path+".from", fmt.Sprintf("must be %q", "udm."+name)))
		} else if !processorOutputs[output.From] {
			problems = append(problems, fileError(pipeline.File, path+".from",
				fmt.Sprintf("%q is not produced by a processor", output.From)))
		}

		if systemLoaded {
			retention := system.Stores.DatasetCache.DefaultRetention
			if output.Retention != nil {
				retention = *output.Retention
				if retention < Duration(minRetention) || retention > Duration(maxRetention) {
					problems = append(problems, fileError(pipeline.File, path+".retention",
						fmt.Sprintf("must be between %s and %s", minRetention, maxRetention)))
				}
			}
			lateness := system.Stores.DatasetCache.DefaultAllowedLateness
			if output.AllowedLateness != nil {
				lateness = *output.AllowedLateness
			}
			if lateness < 0 || lateness >= retention {
				problems = append(problems, fileError(pipeline.File, path+".allowed_lateness", "must be at least 0 and less than retention"))
			}

			if retention >= Duration(minRetention) && retention <= Duration(maxRetention) &&
				(maxCatchUpOutput == "" || retention < maxCatchUpRetention) {
				maxCatchUpRetention = retention
				maxCatchUpOutput = name
			}

			if output.Retention == nil {
				output.Retention = &retention
			}
			if output.AllowedLateness == nil {
				output.AllowedLateness = &lateness
			}
		}
		pipeline.Outputs[name] = output

		if previous, exists := datasetWriters[name]; exists {
			problems = append(problems, fileError(pipeline.File, path,
				fmt.Sprintf("dataset %q is already written by %s", name, previous)))
		} else {
			datasetWriters[name] = pipeline.File
		}
	}

	maxCatchUp := pipeline.Schedule.MaxCatchUp
	if maxCatchUp == 0 {
		maxCatchUp = Duration(defaultMaxCatchUp)
		if maxCatchUpOutput != "" && maxCatchUp > maxCatchUpRetention {
			maxCatchUp = maxCatchUpRetention
		}
	} else if maxCatchUpOutput != "" && maxCatchUp > maxCatchUpRetention {
		problems = append(problems, fileError(pipeline.File, "schedule.max_catch_up",
			fmt.Sprintf("must be at most the retention of output %q (%s)", maxCatchUpOutput, time.Duration(maxCatchUpRetention))))
	}
	pipeline.Schedule.MaxCatchUp = maxCatchUp

	return problems
}

func validateMappingFile(resolvedDirectory string, mapping string) (string, error) {
	cleaned := filepath.Clean(mapping)
	if filepath.IsAbs(mapping) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("mapping %q must be a relative path inside the config directory", mapping)
	}

	resolved, err := filepath.EvalSymlinks(filepath.Join(resolvedDirectory, cleaned))
	if err != nil {
		return "", fmt.Errorf("mapping %q does not exist", mapping)
	}
	relative, err := filepath.Rel(resolvedDirectory, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("mapping %q must stay inside the config directory", mapping)
	}

	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("mapping %q must be a regular file", mapping)
	}
	return filepath.ToSlash(cleaned), nil
}

func validVariableType(variableType string) bool {
	switch variableType {
	case "string", "duration", "timestamp", "int":
		return true
	default:
		return false
	}
}

func canonicalVariableValue(variableType string, value string) (string, error) {
	switch variableType {
	case "string":
		return value, nil
	case "duration":
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return "", fmt.Errorf("invalid duration %q", value)
		}
		return parsed.String(), nil
	case "timestamp":
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return "", fmt.Errorf("invalid timestamp %q", value)
		}
		return parsed.UTC().Format(time.RFC3339Nano), nil
	case "int":
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return "", fmt.Errorf("invalid integer %q", value)
		}
		return strconv.Itoa(parsed), nil
	default:
		return "", fmt.Errorf("unsupported variable type %q", variableType)
	}
}

func checkSecrets(fetchers map[string]FetcherInstance, getenv func(string) string) []error {
	var problems []error
	for _, id := range slices.Sorted(maps.Keys(fetchers)) {
		instance := fetchers[id]
		fields := []struct {
			path string
			ref  *SecretRef
		}{
			{"auth.api_key", instance.Auth.APIKey},
			{"auth.username", instance.Auth.Username},
			{"auth.password", instance.Auth.Password},
			{"tls.ca_ref", instance.TLS.CARef},
		}
		for _, field := range fields {
			if field.ref == nil {
				continue
			}
			if _, err := field.ref.Resolve(getenv); err != nil {
				problems = append(problems, fileError("fetchers.yaml", "fetchers."+id+"."+field.path, err.Error()))
			}
		}
	}
	return problems
}

const secretPlacementMessage = "secret references are only allowed in credential fields"

func checkSecretPlacement(fetchers map[string]FetcherInstance, pipelines []Pipeline) []error {
	var problems []error

	for _, id := range slices.Sorted(maps.Keys(fetchers)) {
		instance := fetchers[id]
		check := func(path string, value string) {
			if strings.Contains(value, "${secret:") {
				problems = append(problems, fileError("fetchers.yaml", "fetchers."+id+"."+path, secretPlacementMessage))
			}
		}
		check("defaults.index", instance.Defaults.Index)
		check("defaults.time_field", instance.Defaults.TimeField)
		check("defaults.fetch_time_field", instance.Defaults.FetchTimeField)
		for index, address := range instance.Addresses {
			check(fmt.Sprintf("addresses[%d]", index), address)
		}
		for index, pattern := range instance.AllowedIndexes {
			check(fmt.Sprintf("allowed_indexes[%d]", index), pattern)
		}
	}

	for _, pipeline := range pipelines {
		for _, name := range slices.Sorted(maps.Keys(pipeline.Variables)) {
			variable := pipeline.Variables[name]
			if variable.Default != nil && strings.Contains(*variable.Default, "${secret:") {
				problems = append(problems, fileError(pipeline.File, "variables."+name+".default", secretPlacementMessage))
			}
		}
		for stepIndex, step := range pipeline.Fetchers {
			for _, inputName := range slices.Sorted(maps.Keys(step.Inputs)) {
				if strings.Contains(step.Inputs[inputName].Literal, "${secret:") {
					path := fmt.Sprintf("fetchers[%d].inputs.%s", stepIndex, inputName)
					problems = append(problems, fileError(pipeline.File, path, secretPlacementMessage))
				}
			}
		}
		for processorIndex, processor := range pipeline.Processors {
			for mappingIndex, mapping := range processor.Mappings {
				if strings.Contains(mapping, "${secret:") {
					path := fmt.Sprintf("processors[%d].mappings[%d]", processorIndex, mappingIndex)
					problems = append(problems, fileError(pipeline.File, path, secretPlacementMessage))
				}
			}
		}
	}

	return problems
}

func readConfigFile(directory string, name string) ([]byte, error) {
	path := filepath.Join(directory, name)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: file is required", name)
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: must be a regular file", name)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxConfigFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(data) > maxConfigFileSize {
		return nil, fmt.Errorf("%s: file is larger than 1 MiB", name)
	}
	return data, nil
}

func fileError(file string, path string, message string) error {
	return fmt.Errorf("%s: %s: %s", file, path, message)
}

func decodeStrict(data []byte, target any) error {
	if err := yaml.UnmarshalWithOptions(data, target, yaml.Strict()); err != nil {
		return errors.New(yamlErrorMessage(err))
	}
	return nil
}

// yamlErrorMessage keeps the first line (the message, without the source
// excerpt) and drops the line and column, which do not match nested structs.
func yamlErrorMessage(err error) string {
	message, _, _ := strings.Cut(err.Error(), "\n")
	if strings.HasPrefix(message, "[") {
		if position := strings.Index(message, "] "); position >= 0 {
			message = message[position+2:]
		}
	}
	return message
}
