package converter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"

	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
	"github.com/goccy/go-yaml"
)

const maxMappingFileBytes = 1 << 20

var mappingIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// The raw types keep scalar values untyped so wrong YAML types fail with the
// mapping id and key path instead of the decoder's field name.
type rawMapping struct {
	ID          any                    `yaml:"id"`
	Version     any                    `yaml:"version"`
	Description any                    `yaml:"description"`
	Match       []rawCondition         `yaml:"match"`
	Constants   yaml.MapSlice          `yaml:"constants"`
	Fields      []rawFieldMapping      `yaml:"fields"`
	Additional  []rawAdditionalMapping `yaml:"additional"`
}

type rawCondition struct {
	Field  any `yaml:"field"`
	Equals any `yaml:"equals"`
	In     any `yaml:"in"`
}

type rawFieldMapping struct {
	To         any           `yaml:"to"`
	From       any           `yaml:"from"`
	Transforms any           `yaml:"transforms"`
	Values     yaml.MapSlice `yaml:"values"`
	Default    any           `yaml:"default"`
}

type rawAdditionalMapping struct {
	Key        any `yaml:"key"`
	From       any `yaml:"from"`
	Transforms any `yaml:"transforms"`
}

// ParseMapping parses and validates one mapping document.
func ParseMapping(data []byte) (Mapping, error) {
	raw, err := decodeRawMapping(data)
	if err != nil {
		return Mapping{}, fmt.Errorf("mapping: %w", err)
	}
	mapping, err := raw.mapping()
	if err != nil {
		return Mapping{}, err
	}
	if err := validateMapping(mapping); err != nil {
		return Mapping{}, err
	}
	return mapping, nil
}

func decodeRawMapping(data []byte) (rawMapping, error) {
	var raw rawMapping
	decoder := yaml.NewDecoder(bytes.NewReader(data), yaml.Strict())
	if err := decoder.Decode(&raw); err != nil {
		return rawMapping{}, err
	}
	var extra rawMapping
	err := decoder.Decode(&extra)
	switch {
	case errors.Is(err, io.EOF):
		return raw, nil
	case err != nil:
		return rawMapping{}, err
	default:
		return rawMapping{}, errors.New("multiple YAML documents")
	}
}

func (raw rawMapping) mapping() (Mapping, error) {
	id, err := stringValue(raw.ID, "id")
	if err != nil {
		return Mapping{}, fmt.Errorf("mapping: %w", err)
	}
	wrap := func(err error) error {
		return fmt.Errorf("mapping %q: %w", id, err)
	}

	version, err := intValue(raw.Version, "version")
	if err != nil {
		return Mapping{}, wrap(err)
	}
	description := ""
	if raw.Description != nil {
		description, err = stringValue(raw.Description, "description")
		if err != nil {
			return Mapping{}, wrap(err)
		}
	}

	mapping := Mapping{
		ID:          id,
		Version:     version,
		Description: description,
		Match:       make([]Condition, 0, len(raw.Match)),
		Constants:   make(map[string]string, len(raw.Constants)),
		Fields:      make([]FieldMapping, 0, len(raw.Fields)),
		Additional:  make([]AdditionalMapping, 0, len(raw.Additional)),
	}
	for index, condition := range raw.Match {
		path := fmt.Sprintf("match[%d]", index)
		converted := Condition{}
		if condition.Field != nil {
			converted.Field, err = stringValue(condition.Field, path+".field")
			if err != nil {
				return Mapping{}, wrap(err)
			}
		}
		if condition.Equals != nil {
			value, err := scalarText(condition.Equals, path+".equals")
			if err != nil {
				return Mapping{}, wrap(err)
			}
			converted.Equals = &value
		}
		if condition.In != nil {
			converted.In, err = scalarList(condition.In, path+".in")
			if err != nil {
				return Mapping{}, wrap(err)
			}
		}
		mapping.Match = append(mapping.Match, converted)
	}

	for index, item := range raw.Constants {
		key, err := stringValue(item.Key, fmt.Sprintf("constants[%d].key", index))
		if err != nil {
			return Mapping{}, wrap(err)
		}
		converted, err := scalarText(item.Value, "constants."+key)
		if err != nil {
			return Mapping{}, wrap(err)
		}
		mapping.Constants[key] = converted
	}

	for index, field := range raw.Fields {
		path := fmt.Sprintf("fields[%d]", index)
		converted := FieldMapping{Values: make(map[string]string, len(field.Values))}
		converted.To, err = stringValue(field.To, path+".to")
		if err != nil {
			return Mapping{}, wrap(err)
		}
		converted.From, err = stringList(field.From, path+".from")
		if err != nil {
			return Mapping{}, wrap(err)
		}
		converted.Transforms, err = stringSlice(field.Transforms, path+".transforms")
		if err != nil {
			return Mapping{}, wrap(err)
		}
		for index, item := range field.Values {
			key, err := scalarText(item.Key, fmt.Sprintf("%s.values[%d].key", path, index))
			if err != nil {
				return Mapping{}, wrap(err)
			}
			convertedValue, err := stringValue(item.Value, fmt.Sprintf(`%s.values[%q]`, path, key))
			if err != nil {
				return Mapping{}, wrap(err)
			}
			converted.Values[key] = convertedValue
		}
		if field.Default != nil {
			value, err := stringValue(field.Default, path+".default")
			if err != nil {
				return Mapping{}, wrap(err)
			}
			converted.Default = &value
		}
		mapping.Fields = append(mapping.Fields, converted)
	}

	for index, additional := range raw.Additional {
		path := fmt.Sprintf("additional[%d]", index)
		converted := AdditionalMapping{}
		converted.Key, err = stringValue(additional.Key, path+".key")
		if err != nil {
			return Mapping{}, wrap(err)
		}
		converted.From, err = stringList(additional.From, path+".from")
		if err != nil {
			return Mapping{}, wrap(err)
		}
		converted.Transforms, err = stringSlice(additional.Transforms, path+".transforms")
		if err != nil {
			return Mapping{}, wrap(err)
		}
		mapping.Additional = append(mapping.Additional, converted)
	}
	return mapping, nil
}

func validateMapping(mapping Mapping) error {
	fail := func(path string, message string) error {
		return fmt.Errorf("mapping %q: %s: %s", mapping.ID, path, message)
	}

	if !mappingIDPattern.MatchString(mapping.ID) {
		return fail("id", "must match "+mappingIDPattern.String())
	}
	if mapping.Version < 1 {
		return fail("version", "must be at least 1")
	}
	if len(mapping.Match) == 0 {
		return fail("match", "must have at least one condition")
	}
	for index, condition := range mapping.Match {
		path := fmt.Sprintf("match[%d]", index)
		if condition.Field == "" {
			return fail(path+".field", "is required")
		}
		if (condition.Equals == nil) == (len(condition.In) == 0) {
			return fail(path, "exactly one of equals or in is required")
		}
	}

	setPaths := make(map[string]struct{}, len(mapping.Constants)+len(mapping.Fields))
	for _, key := range sortedKeys(mapping.Constants) {
		if _, ok := udm.Lookup(key); !ok {
			return fail("constants."+key, fmt.Sprintf("unknown field %q", key))
		}
		if _, duplicate := setPaths[key]; duplicate {
			return fail(key, "set more than once")
		}
		setPaths[key] = struct{}{}
	}
	for index, field := range mapping.Fields {
		path := fmt.Sprintf("fields[%d]", index)
		if _, ok := udm.Lookup(field.To); !ok {
			return fail(path+".to", fmt.Sprintf("unknown field %q", field.To))
		}
		if _, duplicate := setPaths[field.To]; duplicate {
			return fail(field.To, "set more than once")
		}
		setPaths[field.To] = struct{}{}
		if err := validateSources(field.From); err != nil {
			return fail(path+".from", err.Error())
		}
		for _, transform := range field.Transforms {
			if _, ok := transforms[transform]; !ok {
				return fail(path+".transforms", fmt.Sprintf("unknown transform %q", transform))
			}
		}
	}

	seenAdditional := make(map[string]struct{}, len(mapping.Additional))
	for index, additional := range mapping.Additional {
		path := fmt.Sprintf("additional[%d]", index)
		if _, ok := udm.Lookup("additional." + additional.Key); !ok {
			return fail(path+".key", fmt.Sprintf("invalid key %q", additional.Key))
		}
		if _, duplicate := seenAdditional[additional.Key]; duplicate {
			return fail(path+".key", fmt.Sprintf("duplicate key %q", additional.Key))
		}
		seenAdditional[additional.Key] = struct{}{}
		if err := validateSources(additional.From); err != nil {
			return fail(path+".from", err.Error())
		}
		for _, transform := range additional.Transforms {
			if _, ok := transforms[transform]; !ok {
				return fail(path+".transforms", fmt.Sprintf("unknown transform %q", transform))
			}
		}
	}

	var scratch udm.Event
	for _, key := range sortedKeys(mapping.Constants) {
		field, _ := udm.Lookup(key)
		if err := field.Set(&scratch, mapping.Constants[key]); err != nil {
			return fail("constants."+key, err.Error())
		}
	}
	for index, fieldMapping := range mapping.Fields {
		field, _ := udm.Lookup(fieldMapping.To)
		path := fmt.Sprintf("fields[%d]", index)
		for _, key := range sortedKeys(fieldMapping.Values) {
			if err := field.Set(&scratch, fieldMapping.Values[key]); err != nil {
				return fail(fmt.Sprintf("%s.values[%q]", path, key), err.Error())
			}
		}
		if fieldMapping.Default != nil {
			if err := field.Set(&scratch, *fieldMapping.Default); err != nil {
				return fail(path+".default", err.Error())
			}
		}
	}

	if _, ok := setPaths["metadata.event_type"]; !ok {
		return fail("metadata.event_type", "must be set by a constant or a field")
	}
	if _, ok := setPaths["metadata.event_timestamp"]; !ok {
		return fail("metadata.event_timestamp", "must be set by a constant or a field")
	}
	return nil
}

func validateSources(sources []string) error {
	if len(sources) == 0 {
		return errors.New("must have at least one source path")
	}
	for _, source := range sources {
		if source == "" {
			return errors.New("must have at least one source path")
		}
	}
	return nil
}

func stringValue(value any, path string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s: must be a string", path)
	}
	return text, nil
}

func intValue(value any, path string) (int, error) {
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int64:
		return int(typed), nil
	case uint64:
		if typed > math.MaxInt64 {
			return 0, fmt.Errorf("%s: must be an integer that fits in 64 bits", path)
		}
		return int(typed), nil
	default:
		return 0, fmt.Errorf("%s: must be an integer", path)
	}
}

func scalarText(value any, path string) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case int:
		return strconv.Itoa(typed), nil
	case int64:
		return strconv.FormatInt(typed, 10), nil
	case uint64:
		return strconv.FormatUint(typed, 10), nil
	case bool:
		return strconv.FormatBool(typed), nil
	default:
		return "", fmt.Errorf("%s: must be a string, integer, or boolean", path)
	}
}

func scalarList(value any, path string) ([]string, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: must be a list", path)
	}
	values := make([]string, 0, len(items))
	for index, item := range items {
		converted, err := scalarText(item, fmt.Sprintf("%s[%d]", path, index))
		if err != nil {
			return nil, err
		}
		values = append(values, converted)
	}
	return values, nil
}

func stringList(value any, path string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	if text, ok := value.(string); ok {
		return []string{text}, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: must be a string or a list of strings", path)
	}
	return stringItems(items, path)
}

func stringSlice(value any, path string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: must be a list of strings", path)
	}
	return stringItems(items, path)
}

func stringItems(items []any, path string) ([]string, error) {
	values := make([]string, 0, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: must be a string", path, index)
		}
		values = append(values, text)
	}
	return values, nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// LoadMappings reads and parses mapping files, keeping the given order.
func LoadMappings(paths []string) ([]Mapping, error) {
	mappings := make([]Mapping, 0, len(paths))
	ids := make(map[string]string, len(paths))
	for _, path := range paths {
		data, err := readMappingFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		mapping, err := ParseMapping(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if previous, duplicate := ids[mapping.ID]; duplicate {
			return nil, fmt.Errorf("duplicate mapping id %q in %s and %s", mapping.ID, previous, path)
		}
		ids[mapping.ID] = path
		mappings = append(mappings, mapping)
	}
	return mappings, nil
}

func readMappingFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(file, maxMappingFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMappingFileBytes {
		return nil, fmt.Errorf("file is larger than %d bytes", maxMappingFileBytes)
	}
	return data, nil
}
