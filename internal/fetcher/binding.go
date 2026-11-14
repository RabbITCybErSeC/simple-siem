package fetcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
)

const (
	placeholderPrefix = "${parameters."
	placeholderSuffix = "}"
	// maxValueInError bounds how much of a rejected parameter value an error
	// message may repeat.
	maxValueInError = 64
)

// unsetPlaceholder asks the nearest enclosing list to drop the element that
// contains it.
type unsetPlaceholder struct {
	parameter string
}

// Bind returns a deep copy of rawQuery with each placeholder replaced by the
// typed JSON value of its parameter. Values arrive as strings and are never
// parsed as JSON, so a hostile value stays one string. A declared parameter
// that is absent from values makes Bind remove the nearest enclosing list
// element that contains its placeholder.
func Bind(rawQuery map[string]any, parameters map[string]config.TemplateParameter, values map[string]string) (map[string]any, error) {
	for name := range values {
		if _, declared := parameters[name]; !declared {
			return nil, fmt.Errorf("unknown parameter %q", name)
		}
	}
	for name, parameter := range parameters {
		if _, supplied := values[name]; parameter.Required && !supplied {
			return nil, fmt.Errorf("parameter %q is required", name)
		}
	}

	bound, unset, err := bindMap(rawQuery, parameters, values)
	if err != nil {
		return nil, err
	}
	if unset != nil {
		return nil, fmt.Errorf("parameter %q is optional, unset, and outside a list", unset.parameter)
	}
	return bound, nil
}

func bindNode(node any, parameters map[string]config.TemplateParameter, values map[string]string) (any, *unsetPlaceholder, error) {
	switch typed := node.(type) {
	case map[string]any:
		return bindMap(typed, parameters, values)
	case []any:
		return bindList(typed, parameters, values)
	case string:
		return bindString(typed, parameters, values)
	default:
		return node, nil, nil
	}
}

func bindMap(input map[string]any, parameters map[string]config.TemplateParameter, values map[string]string) (map[string]any, *unsetPlaceholder, error) {
	bound := make(map[string]any, len(input))
	for key, child := range input {
		value, unset, err := bindNode(child, parameters, values)
		if err != nil {
			return nil, nil, err
		}
		if unset != nil {
			return nil, unset, nil
		}
		bound[key] = value
	}
	return bound, nil, nil
}

func bindList(input []any, parameters map[string]config.TemplateParameter, values map[string]string) ([]any, *unsetPlaceholder, error) {
	bound := make([]any, 0, len(input))
	for _, element := range input {
		value, unset, err := bindNode(element, parameters, values)
		if err != nil {
			return nil, nil, err
		}
		if unset != nil {
			continue
		}
		bound = append(bound, value)
	}
	return bound, nil, nil
}

func bindString(value string, parameters map[string]config.TemplateParameter, values map[string]string) (any, *unsetPlaceholder, error) {
	name, isPlaceholder := placeholderName(value)
	if !isPlaceholder {
		return value, nil, nil
	}
	parameter, declared := parameters[name]
	if !declared {
		return nil, nil, fmt.Errorf("placeholder names unknown parameter %q", name)
	}
	raw, supplied := values[name]
	if !supplied {
		return nil, &unsetPlaceholder{parameter: name}, nil
	}
	bound, err := typedValue(parameter.Type, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parameter %q: %w", name, err)
	}
	return bound, nil, nil
}

func placeholderName(value string) (string, bool) {
	if !strings.HasPrefix(value, placeholderPrefix) || !strings.HasSuffix(value, placeholderSuffix) {
		return "", false
	}
	name := value[len(placeholderPrefix) : len(value)-len(placeholderSuffix)]
	return name, name != ""
}

func typedValue(parameterType, value string) (any, error) {
	switch parameterType {
	case "string":
		return value, nil
	case "int":
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid int %s", quotedValue(value))
		}
		return parsed, nil
	case "bool":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("invalid bool %s", quotedValue(value))
		}
		return parsed, nil
	case "timestamp":
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return nil, fmt.Errorf("invalid timestamp %s", quotedValue(value))
		}
		return parsed.UTC().Format(time.RFC3339Nano), nil
	default:
		return nil, fmt.Errorf("unsupported type %q", parameterType)
	}
}

// quotedValue renders at most maxValueInError bytes of value.
func quotedValue(value string) string {
	if len(value) <= maxValueInError {
		return strconv.Quote(value)
	}
	return strconv.Quote(value[:maxValueInError]) + "..."
}

// RenderedHash is the hex SHA-256 of the canonical JSON of body
// (json.Marshal sorts map keys).
func RenderedHash(body map[string]any) string {
	encoded, err := json.Marshal(body)
	if err != nil {
		// A body built by Bind holds only the template's YAML scalars, maps,
		// and lists, which always marshal.
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
