package audit

import (
	"fmt"
	"sort"
	"strings"

	"gorm.io/gorm"
)

const redactedValue = "[REDACTED]"

var sensitiveKeyParts = []string{
	"password",
	"token",
	"secret",
	"apikey",
	"api_key",
	"authorization",
}

var validOutcomes = map[string]struct{}{
	"SUCCESS":           {},
	"DENIED":            {},
	"VALIDATION_FAILED": {},
	"FAILED":            {},
	"PARTIAL":           {},
	"CANCELED":          {},
	"SKIPPED":           {},
}

// Record validates event, redacts sensitive values in a copy of its changes,
// and inserts it through the caller's transaction.
func Record(tx *gorm.DB, event Event) error {
	if err := validate(event); err != nil {
		return err
	}
	event.Changes, event.Redactions = redact(event.Changes)
	if err := tx.Create(&event).Error; err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

func validate(event Event) error {
	requiredFields := []struct {
		name  string
		value string
	}{
		{"eventName", event.EventName},
		{"eventCategory", event.EventCategory},
		{"eventOutcome", event.EventOutcome},
		{"actorType", event.ActorType},
		{"targetType", event.TargetType},
		{"targetId", event.TargetID},
		{"action", event.Action},
	}
	for _, field := range requiredFields {
		if field.value == "" {
			return fmt.Errorf("audit event: %s is required", field.name)
		}
	}
	if _, ok := validOutcomes[event.EventOutcome]; !ok {
		return fmt.Errorf("audit event: eventOutcome %q is not one of the allowed values", event.EventOutcome)
	}
	return nil
}

func redact(changes map[string]any) (map[string]any, []string) {
	paths := []string{}
	redacted := redactMap(changes, "changes", &paths)
	sort.Strings(paths)
	return redacted, paths
}

func redactMap(values map[string]any, path string, paths *[]string) map[string]any {
	if values == nil {
		return nil
	}
	redacted := make(map[string]any, len(values))
	for key, value := range values {
		keyPath := path + "." + key
		if isSensitiveKey(key) {
			redacted[key] = redactedValue
			*paths = append(*paths, keyPath)
			continue
		}
		redacted[key] = redactValue(value, keyPath, paths)
	}
	return redacted
}

func redactValue(value any, path string, paths *[]string) any {
	switch typed := value.(type) {
	case map[string]any:
		return redactMap(typed, path, paths)
	case []any:
		if typed == nil {
			return typed
		}
		redacted := make([]any, len(typed))
		for index, element := range typed {
			redacted[index] = redactValue(element, fmt.Sprintf("%s[%d]", path, index), paths)
		}
		return redacted
	default:
		return value
	}
}

func isSensitiveKey(key string) bool {
	lowered := strings.ToLower(key)
	for _, part := range sensitiveKeyParts {
		if strings.Contains(lowered, part) {
			return true
		}
	}
	return false
}
