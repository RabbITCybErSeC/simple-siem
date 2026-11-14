package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	redactedValue = "[REDACTED]"
	// MaxPage is the highest page number the list endpoints accept.
	MaxPage = 100000
)

// ErrInvalidPage is returned when a list request asks for a page outside
// 1 to MaxPage.
var ErrInvalidPage = errors.New("page is out of range")

var sensitiveKeyParts = []string{
	"api_key",
	"apikey",
	"authorization",
	"bearer",
	"cookie",
	"credential",
	"passwd",
	"password",
	"private_key",
	"privatekey",
	"secret",
	"session",
	"token",
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

// ValidOutcome reports whether outcome is one of the values the audit_events
// table accepts.
func ValidOutcome(outcome string) bool {
	_, ok := validOutcomes[outcome]
	return ok
}

// Record validates event, redacts sensitive values in a copy of its changes,
// and inserts it through the caller's transaction.
func Record(tx *gorm.DB, event Event) error {
	if err := validate(event); err != nil {
		return err
	}
	changes, err := normalizeChanges(event.Changes)
	if err != nil {
		return err
	}
	event.Changes, event.Redactions = redact(changes, "changes")
	if err := tx.Create(&event).Error; err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

// storedEvent is the read-side row. PostgreSQL returns inet as text, which
// database/sql cannot scan into net.IP, so host(source_ip) lands in a string
// and event() converts it back.
type storedEvent struct {
	ID             string         `gorm:"column:id"`
	EventName      string         `gorm:"column:event_name"`
	EventCategory  string         `gorm:"column:event_category"`
	EventOutcome   string         `gorm:"column:event_outcome"`
	ActorType      string         `gorm:"column:actor_type"`
	ActorID        *string        `gorm:"column:actor_id"`
	ActorSessionID *string        `gorm:"column:actor_session_id"`
	RequestID      string         `gorm:"column:request_id"`
	TraceID        string         `gorm:"column:trace_id"`
	SourceIP       *string        `gorm:"column:source_ip"`
	TargetType     string         `gorm:"column:target_type"`
	TargetID       string         `gorm:"column:target_id"`
	Action         string         `gorm:"column:action"`
	Changes        map[string]any `gorm:"column:changes;serializer:json"`
	Redactions     []string       `gorm:"column:redactions;serializer:json"`
	CreatedAt      time.Time      `gorm:"column:created_at"`
}

const selectEventColumns = `
	id, event_name, event_category, event_outcome, actor_type, actor_id,
	actor_session_id, request_id, trace_id, host(source_ip) AS source_ip,
	target_type, target_id, action, changes, redactions, created_at`

func (stored storedEvent) event() Event {
	event := Event{
		ID:             stored.ID,
		EventName:      stored.EventName,
		EventCategory:  stored.EventCategory,
		EventOutcome:   stored.EventOutcome,
		ActorType:      stored.ActorType,
		ActorID:        stored.ActorID,
		ActorSessionID: stored.ActorSessionID,
		RequestID:      stored.RequestID,
		TraceID:        stored.TraceID,
		TargetType:     stored.TargetType,
		TargetID:       stored.TargetID,
		Action:         stored.Action,
		Changes:        stored.Changes,
		Redactions:     stored.Redactions,
		CreatedAt:      stored.CreatedAt,
	}
	if stored.SourceIP != nil {
		event.SourceIP = net.ParseIP(*stored.SourceIP)
	}
	return event
}

// List returns one page of events, newest first, and the total that match.
// shortcut: page-based with count(*); switch to keyset pagination when audit_events passes a few million rows (Phase 7 measurement).
func List(ctx context.Context, db *gorm.DB, filter Filter, page, pageSize int) ([]Event, int64, error) {
	if page < 1 || page > MaxPage {
		return nil, 0, ErrInvalidPage
	}
	if pageSize < 1 {
		return nil, 0, errors.New("list audit events: pageSize must be at least 1")
	}

	query := db.WithContext(ctx).Model(&Event{})
	if filter.EventName != "" {
		query = query.Where("event_name = ?", filter.EventName)
	}
	if filter.EventCategory != "" {
		query = query.Where("event_category = ?", filter.EventCategory)
	}
	if filter.EventOutcome != "" {
		query = query.Where("event_outcome = ?", filter.EventOutcome)
	}
	if filter.ActorID != "" {
		query = query.Where("actor_id = ?", filter.ActorID)
	}
	if filter.Action != "" {
		query = query.Where("action = ?", filter.Action)
	}
	if filter.TargetType != "" {
		query = query.Where("target_type = ?", filter.TargetType)
	}
	if filter.TargetID != "" {
		query = query.Where("target_id = ?", filter.TargetID)
	}
	if filter.RequestID != "" {
		query = query.Where("request_id = ?", filter.RequestID)
	}
	if filter.TraceID != "" {
		query = query.Where("trace_id = ?", filter.TraceID)
	}
	if filter.CreatedAfter != nil {
		query = query.Where("created_at >= ?", *filter.CreatedAfter)
	}
	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", *filter.CreatedBefore)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count audit events: %w", err)
	}

	var rows []storedEvent
	err := query.
		Select(selectEventColumns).
		Order("created_at DESC, id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("list audit events: %w", err)
	}
	events := make([]Event, 0, len(rows))
	for _, row := range rows {
		events = append(events, row.event())
	}
	return events, total, nil
}

// Get returns one audit event by id.
func Get(ctx context.Context, db *gorm.DB, id string) (Event, error) {
	if !ValidID(id) {
		return Event{}, ErrNotFound
	}
	var row storedEvent
	err := db.WithContext(ctx).Model(&Event{}).
		Select(selectEventColumns).
		Where("id = ?", id).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Event{}, ErrNotFound
	}
	if err != nil {
		return Event{}, fmt.Errorf("get audit event: %w", err)
	}
	return row.event(), nil
}

// ValidID reports whether id is in canonical UUID form. The database rejects
// every other form for a uuid column, so the check keeps malformed ids out of
// queries.
func ValidID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	return err == nil
}

// normalizeChanges round-trips changes through JSON, so redaction walks nested
// maps, slices, and structs uniformly and never mutates the caller's values.
func normalizeChanges(changes map[string]any) (map[string]any, error) {
	if changes == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(changes)
	if err != nil {
		return nil, fmt.Errorf("encode values: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var normalized map[string]any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, fmt.Errorf("decode values: %w", err)
	}
	return normalized, nil
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
	if !ValidOutcome(event.EventOutcome) {
		return fmt.Errorf("audit event: eventOutcome %q is not one of the allowed values", event.EventOutcome)
	}
	return nil
}

// SensitivePaths returns the sorted paths of values' keys, at any depth, that
// IsSensitiveKey matches; root prefixes every path.
func SensitivePaths(values map[string]any, root string) ([]string, error) {
	normalized, err := normalizeChanges(values)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	redactMap(normalized, root, &paths)
	sort.Strings(paths)
	return paths, nil
}

func redact(changes map[string]any, root string) (map[string]any, []string) {
	paths := []string{}
	redacted := redactMap(changes, root, &paths)
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
		if IsSensitiveKey(key) {
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

// IsSensitiveKey reports whether a map key names a secret; audit redacts such
// values and the outbox rejects them.
func IsSensitiveKey(key string) bool {
	lowered := strings.ToLower(key)
	identifier := strings.ReplaceAll(strings.ReplaceAll(lowered, "_", ""), "-", "")
	// A key ending in href is a link, not a reference to a stored secret.
	reference := strings.HasSuffix(identifier, "ref") || strings.HasSuffix(identifier, "refid")
	if reference && !strings.HasSuffix(identifier, "href") {
		return false
	}
	for _, part := range sensitiveKeyParts {
		if strings.Contains(lowered, part) {
			return true
		}
	}
	return false
}
