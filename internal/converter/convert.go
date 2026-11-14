package converter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/udm"
)

// New returns a converter for one ordered mapping set and dataset retention.
func New(mappings []Mapping, retention time.Duration) *Converter {
	return &Converter{mappings: slices.Clone(mappings), retention: retention}
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

	var matched *Mapping
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
		MappingID:      matched.ID,
		MappingVersion: matched.Version,
	}
	event, problems := buildEvent(*matched, object)
	problems = append(problems, udm.Validate(event)...)
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

func buildEvent(mapping Mapping, object map[string]any) (udm.Event, []udm.ValidationError) {
	var event udm.Event
	problems := applyConstants(&event, mapping.Constants)
	problems = append(problems, applyFields(&event, mapping.Fields, object)...)
	problems = append(problems, applyAdditional(&event, mapping.Additional, object)...)
	return event, problems
}

func applyConstants(event *udm.Event, constants map[string]string) []udm.ValidationError {
	var problems []udm.ValidationError
	paths := make([]string, 0, len(constants))
	for path := range constants {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		field, ok := udm.Lookup(path)
		if !ok {
			problems = append(problems, udm.ValidationError{Path: path, Message: "field not in the v0.1 subset"})
			continue
		}
		if err := field.Set(event, constants[path]); err != nil {
			problems = append(problems, udm.ValidationError{Path: path, Message: err.Error()})
		}
	}
	return problems
}

func applyFields(event *udm.Event, fields []FieldMapping, object map[string]any) []udm.ValidationError {
	var problems []udm.ValidationError
	for _, fieldMapping := range fields {
		values, err := fieldValues(object, fieldMapping)
		if err != nil {
			problems = append(problems, udm.ValidationError{Path: fieldMapping.To, Message: err.Error()})
			continue
		}
		if len(values) == 0 {
			continue
		}
		field, ok := udm.Lookup(fieldMapping.To)
		if !ok {
			problems = append(problems, udm.ValidationError{
				Path:    fieldMapping.To,
				Message: "field not in the v0.1 subset",
			})
			continue
		}
		if field.Kind == udm.KindIP {
			for _, value := range values {
				if err := field.Set(event, value); err != nil {
					problems = append(problems, udm.ValidationError{Path: fieldMapping.To, Message: err.Error()})
				}
			}
			continue
		}
		if err := field.Set(event, values[0]); err != nil {
			problems = append(problems, udm.ValidationError{Path: fieldMapping.To, Message: err.Error()})
		}
	}
	return problems
}

func applyAdditional(event *udm.Event, additionalMappings []AdditionalMapping, object map[string]any) []udm.ValidationError {
	var problems []udm.ValidationError
	for _, additional := range additionalMappings {
		path := "additional." + additional.Key
		values, err := sourceValues(object, additional.From, additional.Transforms)
		if err != nil {
			problems = append(problems, udm.ValidationError{Path: path, Message: err.Error()})
			continue
		}
		if len(values) == 0 {
			continue
		}
		field, ok := udm.Lookup(path)
		if !ok {
			problems = append(problems, udm.ValidationError{Path: path, Message: "field not in the v0.1 subset"})
			continue
		}
		if err := field.Set(event, values[0]); err != nil {
			problems = append(problems, udm.ValidationError{Path: path, Message: err.Error()})
		}
	}
	return problems
}

func fieldValues(object map[string]any, field FieldMapping) ([]string, error) {
	values, err := sourceValues(object, field.From, field.Transforms)
	if err != nil {
		return nil, err
	}
	if len(field.Values) > 0 {
		values = mapValues(values, field.Values, field.Default)
	}
	if len(values) == 0 && field.Default != nil {
		values = []string{*field.Default}
	}
	return values, nil
}

func sourceValues(object map[string]any, paths []string, transformNames []string) ([]string, error) {
	values, err := firstSourceValues(object, paths)
	if err != nil {
		return nil, err
	}
	values, err = transformValues(values, transformNames)
	if err != nil {
		return nil, err
	}
	return dropEmptyValues(values), nil
}

func firstSourceValues(object map[string]any, paths []string) ([]string, error) {
	for _, path := range paths {
		values, err := resolve(object, path)
		if err != nil {
			return nil, fmt.Errorf("from %s: %w", path, err)
		}
		for _, value := range values {
			if value != "" {
				return values, nil
			}
		}
	}
	return nil, nil
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
		if value != "" {
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

// resolve tries the longest literal dotted key first at each object level, so
// both {"user.name": "alice"} and {"user": {"name": "alice"}} resolve.
func resolve(object map[string]any, path string) ([]string, error) {
	return resolveSegments(object, strings.Split(path, "."))
}

func resolveSegments(object map[string]any, segments []string) ([]string, error) {
	for count := len(segments); count >= 1; count-- {
		value, ok := object[strings.Join(segments[:count], ".")]
		if !ok {
			continue
		}
		if count == len(segments) {
			values, err := scalarStrings(value)
			if err != nil {
				return nil, err
			}
			if len(values) > 0 {
				return values, nil
			}
			continue
		}
		nested, ok := value.(map[string]any)
		if !ok {
			continue
		}
		values, err := resolveSegments(nested, segments[count:])
		if err != nil {
			return nil, err
		}
		if len(values) > 0 {
			return values, nil
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

func matches(mapping Mapping, object map[string]any) bool {
	for _, condition := range mapping.Match {
		values, err := resolve(object, condition.Field)
		if err != nil || len(values) == 0 {
			return false
		}
		matched := false
		if condition.Equals != nil {
			matched = slices.Contains(values, *condition.Equals)
		} else {
			for _, value := range values {
				if slices.Contains(condition.In, value) {
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
