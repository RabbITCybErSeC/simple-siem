package converter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

type compiledMapping struct {
	id         string
	version    int
	match      []compiledCondition
	constants  []compiledConstant
	fields     []compiledField
	additional []compiledAdditional
}

type compiledSource struct {
	path     string
	segments []string
}

type compiledCondition struct {
	field  compiledSource
	equals *string
	in     []string
}

type compiledConstant struct {
	path  string
	field udm.Field
	value string
}

type compiledField struct {
	to           string
	field        udm.Field
	from         []compiledSource
	transforms   []string
	values       map[string]string
	defaultValue *string
}

type compiledAdditional struct {
	path       string
	field      udm.Field
	from       []compiledSource
	transforms []string
}

// New returns a converter for one ordered mapping set and dataset retention.
// Mappings are compiled once, so Convert only reads immutable state.
func New(mappings []Mapping, retention time.Duration) (*Converter, error) {
	if retention <= 0 {
		return nil, errors.New("retention must be greater than zero")
	}
	if len(mappings) == 0 {
		return nil, errors.New("at least one mapping is required")
	}
	compiled := make([]compiledMapping, 0, len(mappings))
	for _, mapping := range mappings {
		converted, err := compileMapping(mapping)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, converted)
	}
	return &Converter{mappings: compiled, retention: retention}, nil
}

func compileMapping(mapping Mapping) (compiledMapping, error) {
	compiled := compiledMapping{
		id:         mapping.ID,
		version:    mapping.Version,
		match:      make([]compiledCondition, 0, len(mapping.Match)),
		constants:  make([]compiledConstant, 0, len(mapping.Constants)),
		fields:     make([]compiledField, 0, len(mapping.Fields)),
		additional: make([]compiledAdditional, 0, len(mapping.Additional)),
	}
	fail := func(path, message string) error {
		return fmt.Errorf("mapping %q: %s: %s", mapping.ID, path, message)
	}

	for _, condition := range mapping.Match {
		compiled.match = append(compiled.match, compiledCondition{
			field:  compileSource(condition.Field),
			equals: cloneString(condition.Equals),
			in:     slices.Clone(condition.In),
		})
	}
	for _, path := range sortedKeys(mapping.Constants) {
		field, ok := udm.Lookup(path)
		if !ok {
			return compiledMapping{}, fail("constants."+path, fmt.Sprintf("unknown field %q", path))
		}
		compiled.constants = append(compiled.constants, compiledConstant{
			path:  path,
			field: field,
			value: mapping.Constants[path],
		})
	}
	for index, fieldMapping := range mapping.Fields {
		field, ok := udm.Lookup(fieldMapping.To)
		if !ok {
			return compiledMapping{}, fail(
				fmt.Sprintf("fields[%d].to", index),
				fmt.Sprintf("unknown field %q", fieldMapping.To),
			)
		}
		compiled.fields = append(compiled.fields, compiledField{
			to:           fieldMapping.To,
			field:        field,
			from:         compileSources(fieldMapping.From),
			transforms:   slices.Clone(fieldMapping.Transforms),
			values:       maps.Clone(fieldMapping.Values),
			defaultValue: cloneString(fieldMapping.Default),
		})
	}
	for index, additional := range mapping.Additional {
		path := "additional." + additional.Key
		field, ok := udm.Lookup(path)
		if !ok {
			return compiledMapping{}, fail(
				fmt.Sprintf("additional[%d].key", index),
				fmt.Sprintf("invalid key %q", additional.Key),
			)
		}
		compiled.additional = append(compiled.additional, compiledAdditional{
			path:       path,
			field:      field,
			from:       compileSources(additional.From),
			transforms: slices.Clone(additional.Transforms),
		})
	}
	return compiled, nil
}

func compileSource(path string) compiledSource {
	return compiledSource{path: path, segments: strings.Split(path, ".")}
}

func compileSources(paths []string) []compiledSource {
	sources := make([]compiledSource, len(paths))
	for index, path := range paths {
		sources[index] = compileSource(path)
	}
	return sources
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// Convert converts one source payload into a result. It holds no mutable
// state, so one Converter is safe for concurrent use.
func (converter *Converter) Convert(payload json.RawMessage, now time.Time) Result {
	object, err := decodeObject(payload)
	if err != nil {
		return Result{
			Outcome: OutcomeQuarantined,
			Errors:  []udm.ValidationError{{Path: "payload", Message: err.Error()}},
		}
	}

	var matched *compiledMapping
	for index := range converter.mappings {
		if matches(converter.mappings[index], object) {
			matched = &converter.mappings[index]
			break
		}
	}
	if matched == nil {
		return Result{Outcome: OutcomeUnmapped}
	}

	result := Result{
		Outcome:        OutcomeConverted,
		MappingID:      matched.id,
		MappingVersion: matched.version,
	}
	event, problems := buildEvent(*matched, object)
	buildPaths := make(map[string]struct{}, len(problems))
	for _, problem := range problems {
		buildPaths[problem.Path] = struct{}{}
	}
	for _, problem := range udm.Validate(event) {
		if _, duplicate := buildPaths[problem.Path]; duplicate {
			continue
		}
		problems = append(problems, problem)
	}
	if !event.Metadata.EventTimestamp.IsZero() && event.Metadata.EventTimestamp.After(now.Add(24*time.Hour)) {
		problems = append(problems, udm.ValidationError{
			Path:    "metadata.event_timestamp",
			Message: "must not be more than 24 hours in the future",
		})
	}
	if len(problems) > 0 {
		slices.SortStableFunc(problems, func(first, second udm.ValidationError) int {
			return strings.Compare(first.Path, second.Path)
		})
		result.Outcome = OutcomeQuarantined
		result.Errors = problems
		return result
	}
	if event.Metadata.EventTimestamp.Before(now.Add(-converter.retention)) {
		result.Outcome = OutcomeLateBeyondRetention
		return result
	}

	result.Event = event
	return result
}

func decodeObject(payload json.RawMessage) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("invalid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid JSON")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("must be a JSON object")
	}
	return object, nil
}

func buildEvent(mapping compiledMapping, object map[string]any) (udm.Event, []udm.ValidationError) {
	var event udm.Event
	problems := applyConstants(&event, mapping.constants)
	problems = append(problems, applyFields(&event, mapping.fields, object)...)
	problems = append(problems, applyAdditional(&event, mapping.additional, object)...)
	return event, problems
}

func applyConstants(event *udm.Event, constants []compiledConstant) []udm.ValidationError {
	var problems []udm.ValidationError
	for _, constant := range constants {
		if err := constant.field.Set(event, constant.value); err != nil {
			problems = append(problems, udm.ValidationError{Path: constant.path, Message: err.Error()})
		}
	}
	return problems
}

func applyFields(event *udm.Event, fields []compiledField, object map[string]any) []udm.ValidationError {
	var problems []udm.ValidationError
	for _, fieldMapping := range fields {
		values, err := fieldValues(object, fieldMapping)
		if err != nil {
			problems = append(problems, udm.ValidationError{Path: fieldMapping.to, Message: err.Error()})
			continue
		}
		if len(values) == 0 {
			continue
		}
		if fieldMapping.field.Kind == udm.KindIP {
			for _, value := range values {
				if err := fieldMapping.field.Set(event, value); err != nil {
					problems = append(problems, udm.ValidationError{Path: fieldMapping.to, Message: err.Error()})
				}
			}
			continue
		}
		if err := fieldMapping.field.Set(event, values[0]); err != nil {
			problems = append(problems, udm.ValidationError{Path: fieldMapping.to, Message: err.Error()})
		}
	}
	return problems
}

func applyAdditional(event *udm.Event, additionalMappings []compiledAdditional, object map[string]any) []udm.ValidationError {
	var problems []udm.ValidationError
	for _, additional := range additionalMappings {
		values, err := sourceValues(object, additional.from, additional.transforms)
		if err != nil {
			problems = append(problems, udm.ValidationError{Path: additional.path, Message: err.Error()})
			continue
		}
		if len(values) == 0 {
			continue
		}
		if err := additional.field.Set(event, values[0]); err != nil {
			problems = append(problems, udm.ValidationError{Path: additional.path, Message: err.Error()})
		}
	}
	return problems
}

func fieldValues(object map[string]any, field compiledField) ([]string, error) {
	values, err := sourceValues(object, field.from, field.transforms)
	if err != nil {
		return nil, err
	}
	if len(field.values) > 0 {
		values = mapValues(values, field.values, field.defaultValue)
	}
	if len(values) == 0 && field.defaultValue != nil {
		values = []string{*field.defaultValue}
	}
	return values, nil
}

func sourceValues(object map[string]any, sources []compiledSource, transformNames []string) ([]string, error) {
	var firstError error
	for _, source := range sources {
		values, err := resolveSegments(object, source.segments)
		if err != nil {
			if firstError == nil {
				firstError = fmt.Errorf("from %s: %w", source.path, err)
			}
			continue
		}
		values, err = transformValues(values, transformNames)
		if err != nil {
			return nil, err
		}
		values = dropEmptyValues(values)
		if len(values) > 0 {
			return values, nil
		}
	}
	return nil, firstError
}

func transformValues(values []string, names []string) ([]string, error) {
	for _, name := range names {
		transform, ok := transforms[name]
		if !ok {
			return nil, fmt.Errorf("unknown transform %q", name)
		}
		for index := range values {
			values[index] = transform(values[index])
		}
	}
	return values, nil
}

func dropEmptyValues(values []string) []string {
	kept := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			kept = append(kept, value)
		}
	}
	return kept
}

func mapValues(values []string, mapping map[string]string, defaultValue *string) []string {
	mapped := make([]string, 0, len(values))
	for _, value := range values {
		if target, ok := mapping[value]; ok {
			mapped = append(mapped, target)
		} else if defaultValue != nil {
			mapped = append(mapped, *defaultValue)
		}
	}
	return mapped
}

var errExpectedScalar = errors.New("expected a scalar")

func resolveSegments(object map[string]any, segments []string) ([]string, error) {
	return resolveFrom(object, segments, 0)
}

// resolveFrom tries the longest literal dotted key first at each object level,
// so both {"user.name": "alice"} and {"user": {"name": "alice"}} resolve.
func resolveFrom(object map[string]any, segments []string, start int) ([]string, error) {
	key := strings.Join(segments[start:], ".")
	for end := len(segments); end > start; end-- {
		value, ok := object[key]
		if ok {
			if end == len(segments) {
				values, err := scalarStrings(value)
				if err != nil {
					return nil, err
				}
				if len(values) > 0 {
					return values, nil
				}
			} else if nested, ok := value.(map[string]any); ok {
				values, err := resolveFrom(nested, segments, end)
				if err != nil {
					return nil, err
				}
				if len(values) > 0 {
					return values, nil
				}
			}
		}
		if end > start+1 {
			key = key[:len(key)-len(segments[end-1])-1]
		}
	}
	return nil, nil
}

func scalarStrings(value any) ([]string, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{typed}, nil
	case json.Number:
		return []string{typed.String()}, nil
	case bool:
		return []string{strconv.FormatBool(typed)}, nil
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			switch element := item.(type) {
			case nil:
				continue
			case string:
				values = append(values, element)
			case json.Number:
				values = append(values, element.String())
			case bool:
				values = append(values, strconv.FormatBool(element))
			default:
				return nil, errExpectedScalar
			}
		}
		return values, nil
	default:
		return nil, errExpectedScalar
	}
}

func matches(mapping compiledMapping, object map[string]any) bool {
	for _, condition := range mapping.match {
		values, err := resolveSegments(object, condition.field.segments)
		if err != nil || len(values) == 0 {
			return false
		}
		matched := false
		if condition.equals != nil {
			matched = slices.Contains(values, *condition.equals)
		} else {
			for _, value := range values {
				if slices.Contains(condition.in, value) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// Add increments the count for one outcome.
func (counts *Counts) Add(outcome Outcome) {
	switch outcome {
	case OutcomeConverted:
		counts.Converted++
	case OutcomeQuarantined:
		counts.Quarantined++
	case OutcomeUnmapped:
		counts.Unmapped++
	case OutcomeLateBeyondRetention:
		counts.LateBeyondRetention++
	}
}

// FailsClosed reports whether a batch must stop the run: at least 100 records
// and more than maxRatio of them quarantined.
func FailsClosed(counts Counts, maxRatio float64) bool {
	total := counts.Converted + counts.Quarantined + counts.Unmapped + counts.LateBeyondRetention
	if total < 100 {
		return false
	}
	return float64(counts.Quarantined)/float64(total) > maxRatio
}
