package elasticsearch

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
)

// queryNodes are the only Elasticsearch query nodes a template may use.
var queryNodes = map[string]bool{
	"bool":         true,
	"term":         true,
	"terms":        true,
	"range":        true,
	"match":        true,
	"match_phrase": true,
	"exists":       true,
	"prefix":       true,
	"ids":          true,
}

// fieldQueryNodes take one field name and a scalar, a placeholder, or an
// options object.
var fieldQueryNodes = map[string]bool{
	"term":         true,
	"match":        true,
	"match_phrase": true,
	"prefix":       true,
}

var fieldQueryOptions = map[string]bool{
	"value": true, "query": true, "boost": true,
	"case_insensitive": true, "operator": true,
}

// ValidateQuery checks that a template's raw query holds only the allowed
// Elasticsearch DSL nodes. Errors name the JSON path of the offending node.
func ValidateQuery(rawQuery map[string]any) error {
	if rawQuery == nil {
		return fmt.Errorf("query: required")
	}
	for _, key := range slices.Sorted(maps.Keys(rawQuery)) {
		switch key {
		case "query", "_source":
		default:
			return fmt.Errorf("%s: unknown top-level key", key)
		}
	}
	query, exists := rawQuery["query"]
	if !exists {
		return fmt.Errorf("query: required")
	}
	if err := validateNode(query, "query"); err != nil {
		return err
	}
	if source, exists := rawQuery["_source"]; exists {
		return validateSource(source)
	}
	return nil
}

func validateNode(node any, path string) error {
	object, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: must be an object", path)
	}
	keys := slices.Sorted(maps.Keys(object))
	switch len(keys) {
	case 0:
		return fmt.Errorf("%s: must be a query node", path)
	case 1:
	default:
		for _, key := range keys {
			if !queryNodes[key] {
				return fmt.Errorf("%s.%s: unknown query node", path, key)
			}
		}
		return fmt.Errorf("%s.%s: only one query node is allowed", path, keys[1])
	}

	key, value := keys[0], object[keys[0]]
	nodePath := path + "." + key
	switch {
	case key == "bool":
		return validateBool(value, nodePath)
	case fieldQueryNodes[key]:
		return validateFieldQuery(value, nodePath)
	case key == "terms":
		return validateTerms(value, nodePath)
	case key == "range":
		return validateRange(value, nodePath)
	case key == "exists":
		return validateExists(value, nodePath)
	case key == "ids":
		return validateIDs(value, nodePath)
	default:
		return fmt.Errorf("%s: unknown query node", nodePath)
	}
}

func validateNodeOrList(node any, path string) error {
	list, isList := node.([]any)
	if !isList {
		return validateNode(node, path)
	}
	for index, child := range list {
		if err := validateNode(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
			return err
		}
	}
	return nil
}

func validateBool(node any, path string) error {
	object, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: must be an object", path)
	}
	for _, key := range slices.Sorted(maps.Keys(object)) {
		switch key {
		case "must", "filter", "should", "must_not":
			if err := validateNodeOrList(object[key], path+"."+key); err != nil {
				return err
			}
		case "minimum_should_match":
			if !isInteger(object[key]) && !isString(object[key]) {
				return fmt.Errorf("%s.%s: must be an integer or string", path, key)
			}
		default:
			return fmt.Errorf("%s.%s: unknown bool key", path, key)
		}
	}
	return nil
}

func validateFieldQuery(node any, path string) error {
	object, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: must be an object", path)
	}
	keys := slices.Sorted(maps.Keys(object))
	if len(keys) == 0 {
		return fmt.Errorf("%s: must name one field", path)
	}
	if len(keys) > 1 {
		return fmt.Errorf("%s.%s: only one field is allowed", path, keys[1])
	}

	field, value := keys[0], object[keys[0]]
	fieldPath := path + "." + field
	if err := validateFieldName(field, fieldPath); err != nil {
		return err
	}
	if options, isOptions := value.(map[string]any); isOptions {
		for _, option := range slices.Sorted(maps.Keys(options)) {
			if !fieldQueryOptions[option] {
				return fmt.Errorf("%s.%s: unknown option", fieldPath, option)
			}
		}
		return nil
	}
	if !isScalar(value) {
		return fmt.Errorf("%s: must be a scalar or an options object", fieldPath)
	}
	return nil
}

func validateTerms(node any, path string) error {
	object, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: must be an object", path)
	}
	var field string
	for _, key := range slices.Sorted(maps.Keys(object)) {
		if key == "boost" {
			if !isNumber(object[key]) {
				return fmt.Errorf("%s.boost: must be a number", path)
			}
			continue
		}
		if field != "" {
			return fmt.Errorf("%s.%s: only one field is allowed", path, key)
		}
		field = key
	}
	if field == "" {
		return fmt.Errorf("%s: must name one field", path)
	}

	fieldPath := path + "." + field
	if err := validateFieldName(field, fieldPath); err != nil {
		return err
	}
	values, isList := object[field].([]any)
	if !isList {
		return fmt.Errorf("%s: must be a list of scalars", fieldPath)
	}
	for index, value := range values {
		if !isScalar(value) {
			return fmt.Errorf("%s[%d]: must be a scalar", fieldPath, index)
		}
	}
	return nil
}

func validateRange(node any, path string) error {
	object, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: must be an object", path)
	}
	keys := slices.Sorted(maps.Keys(object))
	if len(keys) == 0 {
		return fmt.Errorf("%s: must name one field", path)
	}
	if len(keys) > 1 {
		return fmt.Errorf("%s.%s: only one field is allowed", path, keys[1])
	}

	field, value := keys[0], object[keys[0]]
	fieldPath := path + "." + field
	if err := validateFieldName(field, fieldPath); err != nil {
		return err
	}
	bounds, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: must be an object", fieldPath)
	}
	for _, option := range slices.Sorted(maps.Keys(bounds)) {
		switch option {
		case "gte", "gt", "lte", "lt", "format", "time_zone":
			if !isScalar(bounds[option]) {
				return fmt.Errorf("%s.%s: must be a scalar", fieldPath, option)
			}
		default:
			return fmt.Errorf("%s.%s: unknown range option", fieldPath, option)
		}
	}
	return nil
}

func validateExists(node any, path string) error {
	object, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: must be an object", path)
	}
	for _, key := range slices.Sorted(maps.Keys(object)) {
		if key != "field" {
			return fmt.Errorf("%s.%s: unknown exists key", path, key)
		}
	}
	value, exists := object["field"]
	if !exists {
		return fmt.Errorf("%s.field: required", path)
	}
	field, ok := value.(string)
	if !ok {
		return fmt.Errorf("%s.field: must be a field name", path)
	}
	return validateFieldName(field, path+".field")
}

func validateIDs(node any, path string) error {
	object, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: must be an object", path)
	}
	for _, key := range slices.Sorted(maps.Keys(object)) {
		if key != "values" {
			return fmt.Errorf("%s.%s: unknown ids key", path, key)
		}
	}
	value, exists := object["values"]
	if !exists {
		return fmt.Errorf("%s.values: required", path)
	}
	values, isList := value.([]any)
	if !isList {
		return fmt.Errorf("%s.values: must be a list", path)
	}
	for index, item := range values {
		if !isScalar(item) {
			return fmt.Errorf("%s.values[%d]: must be a scalar", path, index)
		}
	}
	return nil
}

func validateSource(node any) error {
	if fields, isList := node.([]any); isList {
		return validateStringList(fields, "_source")
	}
	object, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("_source: must be a list or an includes/excludes object")
	}
	for _, key := range slices.Sorted(maps.Keys(object)) {
		if key != "includes" && key != "excludes" {
			return fmt.Errorf("_source.%s: unknown source key", key)
		}
		fields, isList := object[key].([]any)
		if !isList {
			return fmt.Errorf("_source.%s: must be a list of field names", key)
		}
		if err := validateStringList(fields, "_source."+key); err != nil {
			return err
		}
	}
	return nil
}

func validateStringList(values []any, path string) error {
	for index, value := range values {
		if !isString(value) {
			return fmt.Errorf("%s[%d]: must be a field name", path, index)
		}
	}
	return nil
}

func validateFieldName(field, path string) error {
	if field == "" {
		return fmt.Errorf("%s: field name must not be empty", path)
	}
	if strings.HasPrefix(field, "_") && field != "_id" {
		return fmt.Errorf("%s: field name must not start with \"_\"", path)
	}
	return nil
}

func isScalar(value any) bool {
	switch value.(type) {
	case nil, string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, json.Number:
		return true
	default:
		return false
	}
}

func isString(value any) bool {
	_, ok := value.(string)
	return ok
}

func isNumber(value any) bool {
	switch value.(type) {
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, json.Number:
		return true
	default:
		return false
	}
}

func isInteger(value any) bool {
	switch typed := value.(type) {
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	case float32:
		return math.Trunc(float64(typed)) == float64(typed)
	case float64:
		return math.Trunc(typed) == typed
	case json.Number:
		_, err := typed.Int64()
		return err == nil
	default:
		return false
	}
}
