package cases

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/RabbITCybErSeC/simple-siem/internal/alerts"
	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/outbox"
	"gorm.io/gorm"
)

var _ alerts.CaseHooks = (*Service)(nil)

// AlertCreated opens the case for a new alert, links the alert, assigns the
// case when someone is on call, and records the audit and outbox events, all
// in the caller's transaction.
func (service *Service) AlertCreated(ctx context.Context, tx *gorm.DB, alert alerts.NewAlert) (alerts.CaseOutcome, error) {
	if !validSeverity(alert.Severity) {
		return alerts.CaseOutcome{}, fmt.Errorf("%w: %q", ErrInvalidSeverity, alert.Severity)
	}

	database := tx.WithContext(ctx)

	guardrailTripped, err := service.recordCaseOpened(database, alert.DetectionID)
	if err != nil {
		return alerts.CaseOutcome{}, err
	}

	assigneeID, err := service.assignOnCall(database)
	if err != nil {
		return alerts.CaseOutcome{}, err
	}
	var assignee *string
	if assigneeID != "" {
		assignee = &assigneeID
	}

	title := normalizeTitle(alert.Title, alert.DetectionID)
	var created caseRow
	err = database.Raw(`
		INSERT INTO cases (title, severity, detection_id, first_event_at, last_event_at, assignee_user_id)
		VALUES (?, ?, ?, ?, ?, ?)
		RETURNING id::text AS id, case_number`,
		title, string(alert.Severity), alert.DetectionID, alert.FirstEventAt, alert.LastEventAt, assignee,
	).Scan(&created).Error
	if err != nil {
		return alerts.CaseOutcome{}, fmt.Errorf("open case: %w", err)
	}

	if assigneeID != "" {
		if err := database.Exec(
			"UPDATE on_call_rotation SET last_user_id = ? WHERE id = 1", assigneeID,
		).Error; err != nil {
			return alerts.CaseOutcome{}, fmt.Errorf("advance on-call rotation: %w", err)
		}
	}

	if err := database.Create(&caseAlertRow{CaseID: created.ID, AlertID: alert.ID}).Error; err != nil {
		return alerts.CaseOutcome{}, fmt.Errorf("link alert %s to case %s: %w", alert.ID, created.ID, err)
	}

	link := service.caseLink(created.CaseNumber)

	createdEvent := systemCaseAuditEvent(created.ID, eventCaseCreated, "create")
	if err := audit.Record(database, createdEvent); err != nil {
		return alerts.CaseOutcome{}, err
	}
	addedEvent := systemCaseAuditEvent(created.ID, eventCaseAlertAdded, "add_alert")
	addedEvent.Changes = map[string]any{"alertId": alert.ID}
	if err := audit.Record(database, addedEvent); err != nil {
		return alerts.CaseOutcome{}, err
	}
	if assigneeID != "" {
		assignedEvent := systemCaseAuditEvent(created.ID, eventCaseAssigned, "assign")
		assignedEvent.Changes = map[string]any{"assigneeId": assigneeID, "onCall": true}
		if err := audit.Record(database, assignedEvent); err != nil {
			return alerts.CaseOutcome{}, err
		}
	}

	createdPayload := map[string]any{
		"caseId":      created.ID,
		"caseNumber":  created.CaseNumber,
		"title":       title,
		"severity":    string(alert.Severity),
		"detectionId": alert.DetectionID,
		"alertId":     alert.ID,
		"link":        link,
	}
	if err := outbox.Record(database, detectionEvent(outbox.TypeCaseCreated, created.ID, createdPayload)); err != nil {
		return alerts.CaseOutcome{}, err
	}
	if assigneeID != "" {
		assignedPayload := map[string]any{
			"caseId":     created.ID,
			"caseNumber": created.CaseNumber,
			"assigneeId": assigneeID,
			"onCall":     true,
			"link":       link,
		}
		if err := outbox.Record(database, detectionEvent(outbox.TypeCaseAssigned, created.ID, assignedPayload)); err != nil {
			return alerts.CaseOutcome{}, err
		}
	}

	return alerts.CaseOutcome{GuardrailTripped: guardrailTripped}, nil
}

// EvidenceAdded moves the case of a retriggered alert forward. It changes
// nothing for a closed case.
func (service *Service) EvidenceAdded(ctx context.Context, tx *gorm.DB, alertID string, lastEventAt time.Time, added int) error {
	database := tx.WithContext(ctx)

	var updated caseRow
	err := database.Raw(`
		UPDATE cases
		SET last_event_at = greatest(cases.last_event_at, ?),
		    last_activity_at = now(), updated_at = now(), version = cases.version + 1
		FROM case_alerts
		WHERE case_alerts.case_id = cases.id AND case_alerts.alert_id = ?
		  AND cases.status <> 'CLOSED'
		RETURNING cases.id::text AS id, cases.case_number`, lastEventAt, alertID).Scan(&updated).Error
	if err != nil {
		return fmt.Errorf("update case evidence: %w", err)
	}
	// No row means the alert has no case or a closed case; neither may fail the run.
	if updated.ID == "" {
		return nil
	}

	return outbox.Record(database, detectionEvent(outbox.TypeCaseEvidenceAdded, updated.ID, map[string]any{
		"caseId":     updated.ID,
		"caseNumber": updated.CaseNumber,
		"alertId":    alertID,
		"added":      added,
		"link":       service.caseLink(updated.CaseNumber),
	}))
}

// recordCaseOpened counts this detection's cases in the current hour and
// reports every case past the limit. Pipeline switches only an ENABLED
// detection, so a repeat report is harmless and re-shadows one an operator
// re-enabled within the hour.
func (service *Service) recordCaseOpened(database *gorm.DB, detectionID string) (bool, error) {
	var casesOpened int
	err := database.Raw(`
		INSERT INTO detection_guardrails (detection_id, hour_bucket, cases_opened)
		VALUES (?, date_trunc('hour', ?::timestamptz), 1)
		ON CONFLICT (detection_id, hour_bucket)
		DO UPDATE SET cases_opened = detection_guardrails.cases_opened + 1
		RETURNING cases_opened`, detectionID, service.now()).Scan(&casesOpened).Error
	if err != nil {
		return false, fmt.Errorf("count detection cases: %w", err)
	}
	return casesOpened > service.maxCasesPerHour, nil
}

// assignOnCall picks the next on-call user, or "" when nobody can take the
// case. The rotation row is locked only when there is someone to assign, so an
// alert with nobody on call does not serialize case creation.
func (service *Service) assignOnCall(database *gorm.DB) (string, error) {
	candidates, err := onCallCandidates(database)
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", nil
	}

	var lastUserID *string
	err = database.Raw(
		"SELECT last_user_id::text AS last_user_id FROM on_call_rotation WHERE id = 1 FOR UPDATE",
	).Scan(&lastUserID).Error
	if err != nil {
		return "", fmt.Errorf("lock on-call rotation: %w", err)
	}

	candidates, err = onCallCandidates(database)
	if err != nil {
		return "", err
	}
	return pickOnCallUser(candidates, lastUserID), nil
}

// onCallCandidates lists the active on-call users who can take a case,
// ordered by id.
func onCallCandidates(database *gorm.DB) ([]string, error) {
	var candidates []string
	err := database.Raw(`
		SELECT users.id::text AS id
		FROM users
		JOIN user_roles ON user_roles.user_id = users.id
		JOIN role_permissions ON role_permissions.role_name = user_roles.role_name
		WHERE users.status = 'ACTIVE' AND users.on_call
		  AND role_permissions.permission = 'case:write'
		GROUP BY users.id
		ORDER BY users.id`).Scan(&candidates).Error
	if err != nil {
		return nil, fmt.Errorf("read on-call users: %w", err)
	}
	return candidates, nil
}

// pickOnCallUser picks the first candidate after lastUserID, or the first
// candidate when the rotation has reached its end.
func pickOnCallUser(candidates []string, lastUserID *string) string {
	for _, candidate := range candidates {
		if lastUserID == nil || candidate > *lastUserID {
			return candidate
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// normalizeTitle trims the alert summary and cuts it to the column's 500 runes
// on a rune boundary. An empty title falls back to the detection, so a bad
// summary never rolls an alert back.
func normalizeTitle(title, detectionID string) string {
	title = strings.TrimSpace(title)
	if runes := []rune(title); len(runes) > maxTitleRunes {
		title = string(runes[:maxTitleRunes])
	}
	if title == "" {
		return "Alert from " + detectionID
	}
	return title
}

// caseLink is the console URL of a case.
func (service *Service) caseLink(caseNumber int64) string {
	return service.publicURL + "/cases/" + strconv.FormatInt(caseNumber, 10)
}

// systemCaseAuditEvent fills the fields every alert-driven case audit event
// shares.
func systemCaseAuditEvent(caseID, name, action string) audit.Event {
	return audit.Event{
		EventName:     name,
		EventCategory: "CASE",
		EventOutcome:  "SUCCESS",
		ActorType:     "SYSTEM",
		TargetType:    "CASE",
		TargetID:      caseID,
		Action:        action,
	}
}

// detectionEvent builds the event every alert-driven case write records.
func detectionEvent(eventType, caseID string, payload map[string]any) outbox.Event {
	return outbox.Event{
		Type:      eventType,
		Version:   1,
		Actor:     outbox.Actor{Type: outbox.ActorSystem, ID: detectionEngineActorID},
		SubjectID: caseID,
		Payload:   payload,
	}
}

// validStatuses, validSeverities, and validOutcomes are the enum allowlists
// of every case read.
var (
	validStatuses = map[string]struct{}{
		StatusOpen: {}, StatusInProgress: {}, StatusClosed: {},
	}
	validSeverities = map[string]struct{}{
		string(alerts.SeverityLow): {}, string(alerts.SeverityMedium): {}, string(alerts.SeverityHigh): {},
	}
	validOutcomes = map[string]struct{}{"MALICIOUS": {}, "ACCEPTED": {}}
)

// detectionPattern is the manifest id pattern, declared here because
// internal/config keeps its copy unexported.
var detectionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// offsetPattern matches the relative-time grammar of the console.
var offsetPattern = regexp.MustCompile(`^now-([1-9]\d*)([mhdw])$`)

var offsetUnits = map[string]time.Duration{
	"m": time.Minute,
	"h": time.Hour,
	"d": 24 * time.Hour,
	"w": 7 * 24 * time.Hour,
}

// timeFieldColumns maps the contract's time field names to columns. Only a
// value found here may reach a query.
var timeFieldColumns = map[string]string{
	TimeFieldLastEventAt:  "cases.last_event_at",
	TimeFieldFirstEventAt: "cases.first_event_at",
	TimeFieldCreatedAt:    "cases.created_at",
	TimeFieldClosedAt:     "cases.closed_at",
}

// sortOrders and sortKeysets are the only ORDER BY fragments the list uses.
var (
	sortOrders = map[string]string{
		SortLastEventAtDesc: "cases.last_event_at DESC, cases.id DESC",
		SortCreatedAtAsc:    "cases.created_at ASC, cases.id ASC",
	}
	sortKeysets = map[string]string{
		SortLastEventAtDesc: "(cases.last_event_at, cases.id) < (?, ?)",
		SortCreatedAtAsc:    "(cases.created_at, cases.id) > (?, ?)",
	}
)

// caseSummaryColumns are the columns of one case list item.
const caseSummaryColumns = `
	cases.id::text AS id,
	cases.case_number,
	cases.title,
	cases.status,
	cases.severity,
	cases.outcome,
	cases.closure_reason,
	cases.assignee_user_id::text AS assignee_user_id,
	assignee.display_name AS assignee_display_name,
	cases.first_event_at,
	cases.last_event_at,
	cases.created_at,
	cases.closed_at,
	cases.version`

// selectCaseSummary is the read of one case list item with its assignee.
const selectCaseSummary = `
	SELECT ` + caseSummaryColumns + `
	FROM cases
	LEFT JOIN users AS assignee ON assignee.id = cases.assignee_user_id`

// ParseTime resolves a contract time expression against now. Accepted forms
// are now, now-<n><m|h|d|w> with a positive count, now/d, now/w, and an RFC
// 3339 UTC time. Anything else is an error.
func ParseTime(value string, now time.Time) (time.Time, error) {
	now = now.UTC()
	switch value {
	case "now":
		return now, nil
	case "now/d":
		return startOfUTCDay(now), nil
	case "now/w":
		daysSinceMonday := (int(now.Weekday()) + 6) % 7
		return startOfUTCDay(now).AddDate(0, 0, -daysSinceMonday), nil
	}

	if match := offsetPattern.FindStringSubmatch(value); match != nil {
		count, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("time %q is out of range", value)
		}
		unit := offsetUnits[match[2]]
		// A count whose duration would overflow must be rejected, never
		// wrapped into a time near now.
		if count > math.MaxInt64/int64(unit) {
			return time.Time{}, fmt.Errorf("time %q is out of range", value)
		}
		return now.Add(-time.Duration(count) * unit), nil
	}

	if strings.HasSuffix(value, "Z") {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("time %q is not RFC 3339 UTC", value)
		}
		return parsed.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("time %q is not a supported expression", value)
}

// startOfUTCDay is midnight of now's UTC day.
func startOfUTCDay(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

// invalid builds a ValidationError for a request parameter.
func invalid(parameter, format string, args ...any) ValidationError {
	return ValidationError{Parameter: parameter, Message: fmt.Sprintf(format, args...)}
}

// ValidateListFilter rejects filter values outside the list contract's bounds.
// The service normalizes a filter before validating it; a nil limit is absent
// and takes the default.
func ValidateListFilter(filter ListFilter) error {
	if err := validateFilterValues(filter); err != nil {
		return err
	}
	if filter.Limit != nil && (*filter.Limit < 1 || *filter.Limit > MaxListLimit) {
		return invalid("limit", "limit must be 1 to %d", MaxListLimit)
	}
	return nil
}

// validateFilterValues checks every filter value every case read accepts.
func validateFilterValues(filter ListFilter) error {
	for _, status := range filter.Statuses {
		if _, ok := validStatuses[status]; !ok {
			return invalid("status", "status %q is not OPEN, IN_PROGRESS, or CLOSED", status)
		}
	}
	switch filter.Scope {
	case "", ScopeMine, ScopeUnassigned, ScopeAll:
	default:
		return invalid("scope", "scope %q is not mine, unassigned, or all", filter.Scope)
	}
	if len(filter.AssigneeIDs) > MaxFilterAssignees {
		return invalid("assignee", "assignee accepts at most %d ids", MaxFilterAssignees)
	}
	for _, assigneeID := range filter.AssigneeIDs {
		if !audit.ValidID(assigneeID) {
			return invalid("assignee", "assignee ids must be UUIDs")
		}
	}
	for _, severity := range filter.Severities {
		if _, ok := validSeverities[severity]; !ok {
			return invalid("severity", "severity %q is not LOW, MEDIUM, or HIGH", severity)
		}
	}
	for _, detectionID := range filter.DetectionIDs {
		if !detectionPattern.MatchString(detectionID) {
			return invalid("detection", "detection %q is not a detection id", detectionID)
		}
	}
	for _, outcome := range filter.Outcomes {
		if _, ok := validOutcomes[outcome]; !ok {
			return invalid("outcome", "outcome %q is not MALICIOUS or ACCEPTED", outcome)
		}
	}

	query := strings.TrimSpace(filter.Query)
	if filter.Query != "" && query == "" {
		return invalid("q", "q must be 1 to %d characters after trimming", MaxQueryRunes)
	}
	if utf8.RuneCountInString(query) > MaxQueryRunes {
		return invalid("q", "q must be 1 to %d characters after trimming", MaxQueryRunes)
	}
	if allDigits(query) {
		if _, err := strconv.ParseInt(query, 10, 64); err != nil {
			return invalid("q", "the case number is too large")
		}
	}

	if filter.TimeField != "" {
		if _, ok := timeFieldColumns[filter.TimeField]; !ok {
			return invalid("timeField", "timeField %q is not supported", filter.TimeField)
		}
	}
	if filter.Sort != "" {
		if _, ok := sortOrders[filter.Sort]; !ok {
			return invalid("sort", "sort %q is not supported", filter.Sort)
		}
	}
	if filter.From != nil && filter.To != nil && !filter.From.Before(*filter.To) {
		return invalid("from", "from must be before to")
	}
	return nil
}

// normalizeFilter applies the contract's defaults and trims the query. Every
// read entry point normalizes before validating, so the cursor hash and the
// counts cache key see the same values.
func normalizeFilter(filter ListFilter) ListFilter {
	filter.Query = strings.TrimSpace(filter.Query)
	if filter.Scope == "" {
		filter.Scope = ScopeAll
	}
	if filter.TimeField == "" {
		filter.TimeField = TimeFieldLastEventAt
	}
	if filter.Sort == "" {
		filter.Sort = SortLastEventAtDesc
	}
	if filter.Limit == nil {
		limit := DefaultListLimit
		filter.Limit = &limit
	}
	return filter
}

// List returns one page of cases matching filter, newest last event first by
// default.
func (service *Service) List(ctx context.Context, actorUserID string, filter ListFilter) (CasePage, error) {
	filter = normalizeFilter(filter)
	if err := ValidateListFilter(filter); err != nil {
		return CasePage{}, err
	}
	filterHash := listFilterHash(filter, actorUserID)
	limit := *filter.Limit

	var key *cursorKey
	if filter.Cursor != "" {
		decoded, err := parseCursor(filter.Cursor, filterHash, audit.ValidID)
		if err != nil {
			return CasePage{}, err
		}
		key = &decoded
	}

	conditions, arguments, err := caseConditions(filter, actorUserID)
	if err != nil {
		return CasePage{}, err
	}
	if key != nil {
		conditions = append(conditions, sortKeysets[filter.Sort])
		arguments = append(arguments, key.SortValue, key.ID)
	}
	arguments = append(arguments, limit+1)

	var rows []summaryRow
	query := selectCaseSummary + where(conditions) + " ORDER BY " + sortOrders[filter.Sort] + " LIMIT ?"
	if err := service.database.WithContext(ctx).Raw(query, arguments...).Scan(&rows).Error; err != nil {
		return CasePage{}, fmt.Errorf("list cases: %w", err)
	}

	rows, nextCursor := trimPage(rows, limit, filterHash, func(row summaryRow) (time.Time, string) {
		return row.sortValue(filter.Sort), row.ID
	})
	page := CasePage{Items: make([]CaseSummary, 0, len(rows)), NextCursor: nextCursor, Limit: limit}
	for _, row := range rows {
		page.Items = append(page.Items, row.summary())
	}
	return page, nil
}

// caseConditions builds the WHERE conditions every case read shares. All
// values are bound parameters; only allowlisted columns reach the SQL.
func caseConditions(filter ListFilter, actorUserID string) ([]string, []any, error) {
	conditions := make([]string, 0, 8)
	arguments := make([]any, 0, 8)

	if len(filter.Statuses) > 0 {
		conditions = append(conditions, "cases.status IN ?")
		arguments = append(arguments, filter.Statuses)
	}
	switch filter.Scope {
	case ScopeMine:
		if actorUserID == "" {
			return nil, nil, invalid("scope", "mine needs an authenticated user")
		}
		conditions = append(conditions, "cases.assignee_user_id = ?")
		arguments = append(arguments, actorUserID)
	case ScopeUnassigned:
		conditions = append(conditions, "cases.assignee_user_id IS NULL")
	}
	if len(filter.AssigneeIDs) > 0 {
		conditions = append(conditions, "cases.assignee_user_id IN ?")
		arguments = append(arguments, filter.AssigneeIDs)
	}
	if len(filter.Severities) > 0 {
		conditions = append(conditions, "cases.severity IN ?")
		arguments = append(arguments, filter.Severities)
	}
	if len(filter.DetectionIDs) > 0 {
		conditions = append(conditions, "cases.detection_id IN ?")
		arguments = append(arguments, filter.DetectionIDs)
	}
	if len(filter.Outcomes) > 0 {
		conditions = append(conditions, "cases.outcome IN ?")
		arguments = append(arguments, filter.Outcomes)
	}
	if filter.Query != "" {
		if allDigits(filter.Query) {
			number, _ := strconv.ParseInt(filter.Query, 10, 64)
			conditions = append(conditions, "cases.case_number = ?")
			arguments = append(arguments, number)
		} else {
			pattern := strings.ToLower(escapeLike(filter.Query)) + "%"
			conditions = append(conditions, `lower(cases.title) LIKE ? ESCAPE '\'`)
			arguments = append(arguments, pattern)
		}
	}
	if filter.From != nil {
		column := timeFieldColumns[filter.TimeField]
		conditions = append(conditions, column+" >= ?")
		arguments = append(arguments, filter.From.UTC())
		if filter.To != nil {
			conditions = append(conditions, column+" < ?")
			arguments = append(arguments, filter.To.UTC())
		}
	}
	return conditions, arguments, nil
}

// where joins conditions into a WHERE clause, or "" when empty.
func where(conditions []string) string {
	if len(conditions) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(conditions, " AND ")
}

// escapeLike makes the three LIKE metacharacters match literally under
// ESCAPE '\', as the user directory does.
func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}

// allDigits reports whether value is a non-empty run of ASCII digits.
func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// encodeCursor builds a keyset cursor of sortValue, id, and filterHash.
func encodeCursor(sortValue time.Time, id, filterHash string) string {
	encoded, _ := json.Marshal(cursorPayload{
		SortValue: sortValue.UTC().Format(time.RFC3339Nano),
		ID:        id,
		Filter:    filterHash,
	})
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// parseCursor decodes the shared cursor envelope, checks its filter hash, and
// applies the reader's id rule.
func parseCursor(cursor, filterHash string, validID func(string) bool) (cursorKey, error) {
	if len(cursor) > MaxCursorBytes {
		return cursorKey{}, ErrInvalidCursor
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return cursorKey{}, ErrInvalidCursor
	}
	var payload cursorPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return cursorKey{}, ErrInvalidCursor
	}
	sortValue, err := time.Parse(time.RFC3339Nano, payload.SortValue)
	if err != nil || !validID(payload.ID) || payload.Filter != filterHash {
		return cursorKey{}, ErrInvalidCursor
	}
	return cursorKey{SortValue: sortValue.UTC(), ID: payload.ID}, nil
}

// validTimelineCursorID accepts the opaque ids the timeline issues.
func validTimelineCursorID(id string) bool {
	return len(id) <= maxCursorIDBytes &&
		(strings.HasPrefix(id, "ev_") || strings.HasPrefix(id, "ac_"))
}

// trimPage returns at most limit rows and the cursor that continues after the
// last kept row. rows holds limit + 1 fetched rows.
func trimPage[Row any](rows []Row, limit int, filterHash string, key func(Row) (time.Time, string)) ([]Row, *string) {
	if len(rows) <= limit {
		return rows, nil
	}
	rows = rows[:limit]
	sortValue, id := key(rows[limit-1])
	cursor := encodeCursor(sortValue, id, filterHash)
	return rows, &cursor
}

// listFilterHash is the hex SHA-256 of the canonical filter, so a cursor only
// continues the filters it was built for.
func listFilterHash(filter ListFilter, actorUserID string) string {
	input := filterHashInput{
		Statuses:       sortedValues(filter.Statuses),
		Scope:          filter.Scope,
		AssigneeIDs:    sortedValues(filter.AssigneeIDs),
		Severities:     sortedValues(filter.Severities),
		DetectionIDs:   sortedValues(filter.DetectionIDs),
		Outcomes:       sortedValues(filter.Outcomes),
		Query:          filter.Query,
		FromExpression: filter.FromExpression,
		ToExpression:   filter.ToExpression,
		TimeField:      filter.TimeField,
		Sort:           filter.Sort,
	}
	if filter.Scope == ScopeMine {
		input.ActorUserID = actorUserID
	}
	encoded, _ := json.Marshal(input)
	return hashParts(string(encoded))
}

// hashParts hashes length-prefixed parts, so no two part lists encode alike.
func hashParts(parts ...string) string {
	var builder strings.Builder
	for _, part := range parts {
		builder.WriteString(strconv.Itoa(len(part)))
		builder.WriteByte(':')
		builder.WriteString(part)
	}
	digest := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(digest[:])
}

// sortedValues returns a sorted copy, so equivalent filters hash alike.
func sortedValues(values []string) []string {
	sorted := append([]string{}, values...)
	slices.Sort(sorted)
	return sorted
}

// utcTime returns a UTC copy of value, or nil.
func utcTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	utc := value.UTC()
	return &utc
}

// summary converts a row to the list item shape.
func (row summaryRow) summary() CaseSummary {
	summary := CaseSummary{
		ID:            row.ID,
		CaseNumber:    row.CaseNumber,
		Title:         row.Title,
		Status:        row.Status,
		Severity:      row.Severity,
		Outcome:       row.Outcome,
		ClosureReason: row.ClosureReason,
		FirstEventAt:  row.FirstEventAt.UTC(),
		LastEventAt:   row.LastEventAt.UTC(),
		CreatedAt:     row.CreatedAt.UTC(),
		ClosedAt:      utcTime(row.ClosedAt),
		Version:       row.Version,
	}
	if row.AssigneeUserID != nil && row.AssigneeDisplayName != nil {
		summary.Assignee = &CaseAssignee{ID: *row.AssigneeUserID, DisplayName: *row.AssigneeDisplayName}
	}
	return summary
}

// sortValue is the column value the active sort orders by.
func (row summaryRow) sortValue(sort string) time.Time {
	if sort == SortCreatedAtAsc {
		return row.CreatedAt.UTC()
	}
	return row.LastEventAt.UTC()
}

// selectCaseDetail reads one case with its assignee and closer.
const selectCaseDetail = `
	SELECT ` + caseSummaryColumns + `,
	       cases.previous_case_id::text AS previous_case_id,
	       cases.last_activity_at,
	       cases.conclusion,
	       cases.closed_by::text AS closed_by_id,
	       closer.display_name AS closed_by_display_name
	FROM cases
	LEFT JOIN users AS assignee ON assignee.id = cases.assignee_user_id
	LEFT JOIN users AS closer ON closer.id = cases.closed_by`

// selectAlerts reads a case's alerts with their dispositions.
const selectAlerts = `
	SELECT alerts.id::text AS id,
	       alerts.summary AS title,
	       alerts.severity,
	       alerts.status,
	       alerts.detection_id,
	       alerts.detection_version,
	       alerts.evidence_count,
	       alerts.occurrence_count,
	       alerts.first_event_at,
	       alerts.last_event_at,
	       case_alerts.outcome,
	       case_alerts.closure_reason
	FROM case_alerts
	JOIN alerts ON alerts.id = case_alerts.alert_id
	WHERE case_alerts.case_id = ?`

// selectEvidenceTimeline reads the evidence rows of a case's alerts. The UDM
// lookup runs only for the final page, after the merged rows are limited.
const selectEvidenceTimeline = `
	SELECT 'ev_' || alert_evidence.alert_id::text || '_' || encode(alert_evidence.source_key_hash, 'hex') AS id,
	       'EVIDENCE' AS kind,
	       alert_evidence.event_time AS at,
	       alert_evidence.alert_id::text AS alert_id,
	       alert_evidence.document_id AS source_id,
	       alert_evidence.source_key_hash,
	       NULL::text AS actor_id,
	       NULL::text AS actor_display_name,
	       NULL::text AS action,
	       NULL::jsonb AS details
	FROM case_alerts
	JOIN alert_evidence ON alert_evidence.alert_id = case_alerts.alert_id
	WHERE case_alerts.case_id = ?`

// selectActivityTimeline reads the allowlisted case audit rows and builds the
// contract's details from named keys only.
const selectActivityTimeline = `
	SELECT 'ac_' || audit_events.id::text AS id,
	       'ACTIVITY' AS kind,
	       audit_events.created_at AS at,
	       NULL::text AS alert_id,
	       NULL::text AS source_id,
	       NULL::bytea AS source_key_hash,
	       CASE WHEN audit_events.actor_type = 'SYSTEM' THEN NULL
	            ELSE audit_events.actor_id::text END AS actor_id,
	       CASE WHEN audit_events.actor_type = 'SYSTEM' THEN NULL
	            ELSE actor.display_name END AS actor_display_name,
	       CASE audit_events.event_name
	           WHEN 'simple_siem.case.created' THEN 'CASE_CREATED'
	           WHEN 'simple_siem.case.alert_added' THEN 'ALERT_ADDED'
	           WHEN 'simple_siem.case.assigned' THEN 'ASSIGNED'
	           WHEN 'simple_siem.case.unassigned' THEN 'UNASSIGNED'
	           WHEN 'simple_siem.case.status_changed' THEN 'STATUS_CHANGED'
	       END AS action,
	       CASE audit_events.event_name
	           WHEN 'simple_siem.case.created' THEN '{}'::jsonb
	           WHEN 'simple_siem.case.alert_added' THEN jsonb_build_object('alertId', audit_events.changes->>'alertId')
	           WHEN 'simple_siem.case.assigned' THEN jsonb_build_object('assignee',
	               jsonb_build_object('id', audit_events.changes->>'assigneeId',
	                                  'displayName', assignee.display_name))
	           WHEN 'simple_siem.case.unassigned' THEN '{}'::jsonb
	           WHEN 'simple_siem.case.status_changed' THEN jsonb_build_object(
	               'from', audit_events.changes->>'from',
	               'to', audit_events.changes->>'to')
	       END AS details
	FROM audit_events
	LEFT JOIN users AS actor
	       ON audit_events.actor_type = 'USER'
	      AND actor.id = audit_events.actor_id::uuid
	LEFT JOIN users AS assignee
	       ON assignee.id = (audit_events.changes->>'assigneeId')::uuid
	WHERE audit_events.target_type = 'CASE'
	  AND audit_events.target_id = ?
	  AND audit_events.event_name IN ('simple_siem.case.created', 'simple_siem.case.alert_added',
	      'simple_siem.case.assigned', 'simple_siem.case.unassigned',
	      'simple_siem.case.status_changed')`

// timelineSelect, timelinePage, and timelineTail put the keyset and limit
// before the UDM lookup, so only the paged evidence rows read the dataset
// cache. The inner UNION ALL shares one column set across both kinds.
const (
	timelineSelect = `SELECT entries.id, entries.kind, entries.at, entries.alert_id,
	       entries.source_id, cached.event AS udm, entries.actor_id,
	       entries.actor_display_name, entries.action, entries.details
	FROM (
	    SELECT * FROM (`
	timelinePage = `) AS merged`
	timelineTail = `) AS entries
	LEFT JOIN LATERAL (
	    SELECT dataset_events.event
	    FROM dataset_events
	    WHERE dataset_events.event_time = entries.at
	      AND dataset_events.source_key_hash = entries.source_key_hash
	    ORDER BY dataset_events.dataset
	    LIMIT 1
	) AS cached ON true
	ORDER BY entries.at, entries.id`
)

// Get returns one case by its id or its case number.
func (service *Service) Get(ctx context.Context, ref string) (CaseDetail, error) {
	database := service.database.WithContext(ctx)
	if allDigits(ref) {
		number, err := strconv.ParseInt(ref, 10, 64)
		if err != nil {
			return CaseDetail{}, ErrCaseNotFound
		}
		return loadCaseDetail(database, "cases.case_number = ?", number)
	}
	if !audit.ValidID(ref) {
		return CaseDetail{}, ErrCaseNotFound
	}
	return loadCaseDetail(database, "cases.id = ?", ref)
}

// loadCaseDetail reads one detail inside database.
func loadCaseDetail(database *gorm.DB, condition string, argument any) (CaseDetail, error) {
	var row detailRow
	if err := database.Raw(selectCaseDetail+" WHERE "+condition, argument).Scan(&row).Error; err != nil {
		return CaseDetail{}, fmt.Errorf("get case: %w", err)
	}
	if row.Summary.ID == "" {
		return CaseDetail{}, ErrCaseNotFound
	}

	detail := row.detail()
	if err := database.Raw(
		"SELECT count(*) FROM case_alerts WHERE case_id = ?", row.Summary.ID,
	).Scan(&detail.AlertCount).Error; err != nil {
		return CaseDetail{}, fmt.Errorf("count case alerts: %w", err)
	}

	linked := make([]LinkedCase, 0, 3)
	if row.PreviousCaseID != nil {
		var previous LinkedCase
		if err := database.Raw(`
			SELECT id::text AS id, case_number, title, status
			FROM cases WHERE id = ?`, *row.PreviousCaseID).Scan(&previous).Error; err != nil {
			return CaseDetail{}, fmt.Errorf("read previous case: %w", err)
		}
		if previous.ID != "" {
			linked = append(linked, previous)
		}
	}
	var children []LinkedCase
	if err := database.Raw(`
		SELECT id::text AS id, case_number, title, status
		FROM cases WHERE previous_case_id = ? ORDER BY case_number`, row.Summary.ID).Scan(&children).Error; err != nil {
		return CaseDetail{}, fmt.Errorf("read linked cases: %w", err)
	}
	linked = append(linked, children...)
	slices.SortFunc(linked, func(left, right LinkedCase) int {
		return cmp.Compare(left.CaseNumber, right.CaseNumber)
	})
	detail.LinkedCases = linked
	return detail, nil
}

// detail converts a row to the detail shape.
func (row detailRow) detail() CaseDetail {
	detail := CaseDetail{
		CaseSummary:    row.Summary.summary(),
		LastActivityAt: row.LastActivityAt.UTC(),
		Conclusion:     row.Conclusion,
	}
	if row.ClosedByID != nil && row.ClosedByDisplayName != nil {
		detail.ClosedBy = &CaseAssignee{ID: *row.ClosedByID, DisplayName: *row.ClosedByDisplayName}
	}
	return detail
}

// ListAlerts returns one page of a case's alerts, oldest first event first.
func (service *Service) ListAlerts(ctx context.Context, caseID string, limit *int, cursor string) (AlertPage, error) {
	pageLimit, err := normalizePageLimit(limit)
	if err != nil {
		return AlertPage{}, err
	}
	exists, err := service.caseExists(ctx, caseID)
	if err != nil {
		return AlertPage{}, err
	}
	if !exists {
		return AlertPage{}, ErrCaseNotFound
	}

	filterHash := hashParts("case-alerts", caseID)
	var key *cursorKey
	if cursor != "" {
		decoded, err := parseCursor(cursor, filterHash, audit.ValidID)
		if err != nil {
			return AlertPage{}, err
		}
		key = &decoded
	}

	condition := ""
	arguments := []any{caseID}
	if key != nil {
		condition = " AND (alerts.first_event_at, alerts.id) > (?, ?)"
		arguments = append(arguments, key.SortValue, key.ID)
	}
	arguments = append(arguments, pageLimit+1)

	var rows []alertSummaryRow
	query := selectAlerts + condition + " ORDER BY alerts.first_event_at, alerts.id LIMIT ?"
	if err := service.database.WithContext(ctx).Raw(query, arguments...).Scan(&rows).Error; err != nil {
		return AlertPage{}, fmt.Errorf("list case alerts: %w", err)
	}

	rows, nextCursor := trimPage(rows, pageLimit, filterHash, func(row alertSummaryRow) (time.Time, string) {
		return row.FirstEventAt, row.ID
	})
	page := AlertPage{Items: make([]AlertSummary, 0, len(rows)), NextCursor: nextCursor, Limit: pageLimit}
	for _, row := range rows {
		page.Items = append(page.Items, row.summary())
	}
	return page, nil
}

// summary converts a row to the alert shape.
func (row alertSummaryRow) summary() AlertSummary {
	return AlertSummary{
		ID:               row.ID,
		Title:            row.Title,
		Severity:         row.Severity,
		Status:           row.Status,
		DetectionID:      row.DetectionID,
		DetectionVersion: row.DetectionVersion,
		EvidenceCount:    row.EvidenceCount,
		OccurrenceCount:  row.OccurrenceCount,
		FirstEventAt:     row.FirstEventAt.UTC(),
		LastEventAt:      row.LastEventAt.UTC(),
		Outcome:          row.Outcome,
		ClosureReason:    row.ClosureReason,
	}
}

// Timeline returns one page of a case's evidence and activity entries.
func (service *Service) Timeline(ctx context.Context, caseID string, kind string, limit *int, cursor string) (TimelinePage, error) {
	switch kind {
	case "", KindEvidence, KindActivity:
	default:
		return TimelinePage{}, invalid("kind", "kind %q is not EVIDENCE or ACTIVITY", kind)
	}
	pageLimit, err := normalizePageLimit(limit)
	if err != nil {
		return TimelinePage{}, err
	}
	exists, err := service.caseExists(ctx, caseID)
	if err != nil {
		return TimelinePage{}, err
	}
	if !exists {
		return TimelinePage{}, ErrCaseNotFound
	}

	filterHash := hashParts("case-timeline", caseID, kind)
	var key *cursorKey
	if cursor != "" {
		decoded, err := parseCursor(cursor, filterHash, validTimelineCursorID)
		if err != nil {
			return TimelinePage{}, err
		}
		key = &decoded
	}

	branches := make([]string, 0, 2)
	arguments := make([]any, 0, 5)
	if kind == "" || kind == KindEvidence {
		branches = append(branches, selectEvidenceTimeline)
		arguments = append(arguments, caseID)
	}
	if kind == "" || kind == KindActivity {
		branches = append(branches, selectActivityTimeline)
		arguments = append(arguments, caseID)
	}
	query := timelineSelect + strings.Join(branches, " UNION ALL ") + timelinePage
	if key != nil {
		query += " WHERE (merged.at, merged.id) > (?, ?)"
		arguments = append(arguments, key.SortValue, key.ID)
	}
	query += " ORDER BY merged.at, merged.id LIMIT ?" + timelineTail
	arguments = append(arguments, pageLimit+1)

	var rows []timelineRow
	if err := service.database.WithContext(ctx).Raw(query, arguments...).Scan(&rows).Error; err != nil {
		return TimelinePage{}, fmt.Errorf("read case timeline: %w", err)
	}

	rows, nextCursor := trimPage(rows, pageLimit, filterHash, func(row timelineRow) (time.Time, string) {
		return row.At, row.ID
	})
	page := TimelinePage{Items: make([]TimelineEntry, 0, len(rows)), NextCursor: nextCursor, Limit: pageLimit}
	for _, row := range rows {
		entry, err := row.entry()
		if err != nil {
			return TimelinePage{}, err
		}
		page.Items = append(page.Items, entry)
	}
	return page, nil
}

// entry converts a row to the timeline entry of its kind.
func (row timelineRow) entry() (TimelineEntry, error) {
	entry := TimelineEntry{ID: row.ID, Kind: row.Kind, At: row.At.UTC()}
	switch row.Kind {
	case KindEvidence:
		if row.AlertID != nil {
			entry.AlertID = *row.AlertID
		}
		if row.SourceID != nil {
			entry.SourceID = *row.SourceID
		}
		entry.UDM = json.RawMessage(row.UDM)
		if len(entry.UDM) == 0 {
			entry.UDM = json.RawMessage("null")
		}
	case KindActivity:
		if row.ActorID != nil && row.ActorDisplayName != nil {
			actor, err := json.Marshal(CaseAssignee{ID: *row.ActorID, DisplayName: *row.ActorDisplayName})
			if err != nil {
				return TimelineEntry{}, fmt.Errorf("encode timeline actor: %w", err)
			}
			entry.Actor = actor
		} else {
			entry.Actor = json.RawMessage("null")
		}
		if row.Action != nil {
			entry.Action = *row.Action
		}
		details := map[string]any{}
		if len(row.Details) > 0 {
			if err := json.Unmarshal(row.Details, &details); err != nil {
				return TimelineEntry{}, fmt.Errorf("decode timeline details: %w", err)
			}
		}
		encoded, err := json.Marshal(details)
		if err != nil {
			return TimelineEntry{}, fmt.Errorf("encode timeline details: %w", err)
		}
		entry.Details = encoded
	}
	return entry, nil
}

// caseExists reports whether a case id names a case.
func (service *Service) caseExists(ctx context.Context, caseID string) (bool, error) {
	if !audit.ValidID(caseID) {
		return false, nil
	}
	var exists bool
	if err := service.database.WithContext(ctx).Raw(
		"SELECT EXISTS (SELECT 1 FROM cases WHERE id = ?)", caseID,
	).Scan(&exists).Error; err != nil {
		return false, fmt.Errorf("check case: %w", err)
	}
	return exists, nil
}

// Assign sets or clears a case's assignee and returns the fresh detail.
func (service *Service) Assign(ctx context.Context, actor Actor, caseID string, assigneeID *string, version int) (CaseDetail, error) {
	if !audit.ValidID(caseID) {
		return CaseDetail{}, ErrCaseNotFound
	}
	if assigneeID != nil && !audit.ValidID(*assigneeID) {
		return CaseDetail{}, ErrInvalidAssignee
	}

	var detail CaseDetail
	err := service.database.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current caseRow
		err := tx.Raw(`
			SELECT id::text AS id, case_number, status,
			       assignee_user_id::text AS assignee_user_id, version
			FROM cases
			WHERE id = ?
			FOR UPDATE`, caseID).Scan(&current).Error
		if err != nil {
			return fmt.Errorf("lock case: %w", err)
		}
		if current.ID == "" {
			return ErrCaseNotFound
		}
		if current.Status == StatusClosed {
			return ErrCaseClosed
		}
		if current.Version != version {
			return ErrVersionConflict
		}

		if assigneeID != nil {
			if err := lockValidAssignee(tx, *assigneeID); err != nil {
				return err
			}
		}

		sameAssignee := (current.AssigneeUserID == nil && assigneeID == nil) ||
			(current.AssigneeUserID != nil && assigneeID != nil && *current.AssigneeUserID == *assigneeID)
		if sameAssignee {
			detail, err = loadCaseDetail(tx, "cases.id = ?", caseID)
			return err
		}

		statusMoved := current.Status == StatusOpen && assigneeID != nil
		update := "UPDATE cases SET assignee_user_id = ?, last_activity_at = now(), updated_at = now(), version = version + 1"
		if statusMoved {
			update += ", status = 'IN_PROGRESS'"
		}
		if err := tx.Exec(update+" WHERE id = ?", assigneeID, caseID).Error; err != nil {
			return fmt.Errorf("assign case: %w", err)
		}

		eventName, action := eventCaseUnassigned, "unassign"
		changes := map[string]any{}
		if assigneeID != nil {
			eventName, action = eventCaseAssigned, "assign"
			changes = map[string]any{"assigneeId": *assigneeID}
		}
		if err := audit.Record(tx, userCaseAuditEvent(actor, caseID, eventName, action, changes)); err != nil {
			return err
		}
		if statusMoved {
			if err := audit.Record(tx, userCaseAuditEvent(actor, caseID, eventCaseStatusChanged, "change_status",
				map[string]any{"from": StatusOpen, "to": StatusInProgress})); err != nil {
				return err
			}
		}

		link := service.caseLink(current.CaseNumber)
		var assignedID any
		if assigneeID != nil {
			assignedID = *assigneeID
		}
		if err := outbox.Record(tx, userCaseEvent(outbox.TypeCaseAssigned, caseID, actor.UserID, map[string]any{
			"caseId":     caseID,
			"caseNumber": current.CaseNumber,
			"assigneeId": assignedID,
			"onCall":     false,
			"link":       link,
		})); err != nil {
			return err
		}
		if statusMoved {
			if err := outbox.Record(tx, userCaseEvent(outbox.TypeCaseStatusChanged, caseID, actor.UserID, map[string]any{
				"caseId":     caseID,
				"caseNumber": current.CaseNumber,
				"from":       StatusOpen,
				"to":         StatusInProgress,
				"link":       link,
			})); err != nil {
				return err
			}
		}

		detail, err = loadCaseDetail(tx, "cases.id = ?", caseID)
		return err
	})
	if err != nil {
		return CaseDetail{}, err
	}
	return detail, nil
}

// Counts returns the capped status and scope counts of the case queue. status
// selects the tab whose scope counts follow, or "" for every status.
func (service *Service) Counts(ctx context.Context, actorUserID string, filter ListFilter, status string) (Counts, error) {
	filter = normalizeFilter(filter)
	if err := ValidateListFilter(filter); err != nil {
		return Counts{}, err
	}
	tabStatus, err := countsStatus(status)
	if err != nil {
		return Counts{}, err
	}

	base := countsBase(filter)
	cacheKey := countsCacheKey(actorUserID, base, status)
	if cached, ok := service.cachedCounts(cacheKey); ok {
		return cached, nil
	}

	rangeFree := base
	rangeFree.From, rangeFree.To = nil, nil
	counts := Counts{Cap: CountsCap}
	statusQueries := []countQuery{
		{&counts.Status.Open, withStatus(rangeFree, StatusOpen)},
		{&counts.Status.InProgress, withStatus(rangeFree, StatusInProgress)},
		{&counts.Status.Closed, withStatus(base, StatusClosed)},
		{&counts.Status.All, withStatus(base, "")},
	}
	for _, query := range statusQueries {
		if err := service.countInto(ctx, actorUserID, query); err != nil {
			return Counts{}, err
		}
	}

	scopeBase := withStatus(base, tabStatus)
	if tabStatus != StatusClosed && tabStatus != "" {
		scopeBase.From, scopeBase.To = nil, nil
	}
	scopeMine := scopeBase
	scopeMine.Scope = ScopeMine
	scopeUnassigned := scopeBase
	scopeUnassigned.Scope = ScopeUnassigned
	scopeQueries := []countQuery{
		{&counts.Scope.Mine, scopeMine},
		{&counts.Scope.Unassigned, scopeUnassigned},
	}
	for _, query := range scopeQueries {
		if err := service.countInto(ctx, actorUserID, query); err != nil {
			return Counts{}, err
		}
	}
	counts.Scope.All = tabStatusCount(counts.Status, tabStatus)

	service.storeCounts(cacheKey, counts)
	return counts, nil
}

// countInto runs one capped count into its target.
func (service *Service) countInto(ctx context.Context, actorUserID string, query countQuery) error {
	count, err := service.countCases(ctx, actorUserID, query.filter)
	if err != nil {
		return err
	}
	*query.target = count
	return nil
}

// tabStatusCount is the scope-all value already computed for the tab.
func tabStatusCount(status StatusCounts, tabStatus string) int64 {
	switch tabStatus {
	case StatusOpen:
		return status.Open
	case StatusInProgress:
		return status.InProgress
	case StatusClosed:
		return status.Closed
	default:
		return status.All
	}
}

// countCases counts the filtered cases without scanning past the cap.
func (service *Service) countCases(ctx context.Context, actorUserID string, filter ListFilter) (int64, error) {
	conditions, arguments, err := caseConditions(filter, actorUserID)
	if err != nil {
		return 0, err
	}
	arguments = append(arguments, CountsCap)
	var count int64
	query := "SELECT count(*) FROM (SELECT 1 FROM cases" + where(conditions) + " LIMIT ?) AS capped"
	if err := service.database.WithContext(ctx).Raw(query, arguments...).Scan(&count).Error; err != nil {
		return 0, fmt.Errorf("count cases: %w", err)
	}
	return count, nil
}

// countsBase clears the list fields the counts ignore.
func countsBase(filter ListFilter) ListFilter {
	filter.Statuses = nil
	filter.Scope = ScopeAll
	filter.Cursor = ""
	filter.Limit = nil
	filter.Sort = ""
	return filter
}

// withStatus returns a copy of filter for one status, or for all when status is
// empty.
func withStatus(filter ListFilter, status string) ListFilter {
	if status == "" {
		filter.Statuses = nil
	} else {
		filter.Statuses = []string{status}
	}
	return filter
}

// countsStatus checks the counts tab: a case status, or "" for every status.
func countsStatus(status string) (string, error) {
	switch status {
	case "", StatusOpen, StatusInProgress, StatusClosed:
		return status, nil
	default:
		return "", invalid("status", "status %q is not OPEN, IN_PROGRESS, or CLOSED", status)
	}
}

// countsCacheKey holds the user and the base filter the counts depend on.
func countsCacheKey(actorUserID string, base ListFilter, status string) string {
	return hashParts("counts", actorUserID, listFilterHash(base, actorUserID), status)
}

// cachedCounts returns a live cache entry.
func (service *Service) cachedCounts(key string) (Counts, bool) {
	service.countsLock.Lock()
	defer service.countsLock.Unlock()
	entry, ok := service.countsCache[key]
	if !ok || !service.now().Before(entry.expiresAt) {
		return Counts{}, false
	}
	return entry.value, true
}

// storeCounts adds an entry, dropping expired entries and clearing the cache
// when it is still full.
func (service *Service) storeCounts(key string, value Counts) {
	service.countsLock.Lock()
	defer service.countsLock.Unlock()
	now := service.now()
	if service.countsCache == nil {
		service.countsCache = make(map[string]countsCacheEntry)
	}
	for existingKey, entry := range service.countsCache {
		if !now.Before(entry.expiresAt) {
			delete(service.countsCache, existingKey)
		}
	}
	if len(service.countsCache) >= maxCountsCacheEntries {
		clear(service.countsCache)
	}
	service.countsCache[key] = countsCacheEntry{value: value, expiresAt: now.Add(countsCacheTTL)}
}

var histogramIntervals = []histogramInterval{
	{"1m", time.Minute, "1 minute"},
	{"5m", 5 * time.Minute, "5 minutes"},
	{"15m", 15 * time.Minute, "15 minutes"},
	{"30m", 30 * time.Minute, "30 minutes"},
	{"1h", time.Hour, "1 hour"},
	{"3h", 3 * time.Hour, "3 hours"},
	{"6h", 6 * time.Hour, "6 hours"},
	{"12h", 12 * time.Hour, "12 hours"},
	{"1d", 24 * time.Hour, "1 day"},
}

// Histogram returns the severity counts per bucket over a required range.
func (service *Service) Histogram(ctx context.Context, actorUserID string, filter ListFilter) (Histogram, error) {
	filter = normalizeFilter(filter)
	if err := ValidateListFilter(filter); err != nil {
		return Histogram{}, err
	}
	if filter.From == nil {
		return Histogram{}, invalid("from", "from is required")
	}
	if filter.To == nil {
		return Histogram{}, invalid("to", "to is required")
	}
	span := filter.To.Sub(*filter.From)
	if span > maxHistogramRangeDays*24*time.Hour {
		return Histogram{}, invalid("from", "the range must be at most %d days", maxHistogramRangeDays)
	}

	interval := chooseHistogramInterval(span)
	alignedFrom := filter.From.Truncate(interval.duration).UTC()
	conditions, arguments, err := caseConditions(filter, actorUserID)
	if err != nil {
		return Histogram{}, err
	}
	column := timeFieldColumns[filter.TimeField]
	query := "SELECT date_bin(?::interval, " + column + ", ?) AS bucket_start, " +
		"cases.severity, count(*) AS count FROM cases" + where(conditions) +
		" GROUP BY bucket_start, cases.severity"
	queryArguments := append([]any{interval.value, alignedFrom}, arguments...)

	var rows []histogramCountRow
	if err := service.database.WithContext(ctx).Raw(query, queryArguments...).Scan(&rows).Error; err != nil {
		return Histogram{}, fmt.Errorf("read case histogram: %w", err)
	}

	countsByStart := make(map[int64]SeverityCounts, len(rows))
	for _, row := range rows {
		start := row.BucketStart.UTC().UnixNano()
		counts := countsByStart[start]
		switch row.Severity {
		case string(alerts.SeverityHigh):
			counts.High += row.Count
		case string(alerts.SeverityMedium):
			counts.Medium += row.Count
		case string(alerts.SeverityLow):
			counts.Low += row.Count
		}
		countsByStart[start] = counts
	}

	buckets := make([]HistogramBucket, 0, int(span/interval.duration)+1)
	for start := alignedFrom; start.Before(*filter.To); start = start.Add(interval.duration) {
		buckets = append(buckets, HistogramBucket{
			Start:  start,
			Counts: countsByStart[start.UnixNano()],
		})
	}
	return Histogram{Interval: interval.label, Buckets: buckets}, nil
}

// chooseHistogramInterval picks the smallest interval that gives at most
// maxHistogramBuckets buckets, falling back to a day.
func chooseHistogramInterval(span time.Duration) histogramInterval {
	for _, interval := range histogramIntervals {
		if span <= maxHistogramBuckets*interval.duration {
			return interval
		}
	}
	return histogramIntervals[len(histogramIntervals)-1]
}

// lockValidAssignee locks the user and checks the assign contract: the user
// must exist, be ACTIVE, and hold case:read through a role.
func lockValidAssignee(database *gorm.DB, userID string) error {
	var row struct {
		ID      string `gorm:"column:id"`
		Status  string `gorm:"column:status"`
		CanRead bool   `gorm:"column:can_read"`
	}
	err := database.Raw(`
		SELECT users.id::text AS id, users.status,
		       EXISTS (
		           SELECT 1
		           FROM user_roles
		           JOIN role_permissions ON role_permissions.role_name = user_roles.role_name
		           WHERE user_roles.user_id = users.id
		             AND role_permissions.permission = 'case:read'
		       ) AS can_read
		FROM users
		WHERE users.id = ?
		FOR SHARE`, userID).Scan(&row).Error
	if err != nil {
		return fmt.Errorf("lock assignee: %w", err)
	}
	if row.ID == "" || row.Status != userStatusActive || !row.CanRead {
		return ErrInvalidAssignee
	}
	return nil
}

// userCaseAuditEvent fills the fields of an analyst-driven case audit event.
func userCaseAuditEvent(actor Actor, caseID, name, action string, changes map[string]any) audit.Event {
	actorID := actor.UserID
	sessionID := actor.SessionID
	return audit.Event{
		EventName:      name,
		EventCategory:  "CASE",
		EventOutcome:   "SUCCESS",
		ActorType:      "USER",
		ActorID:        &actorID,
		ActorSessionID: &sessionID,
		RequestID:      actor.RequestID,
		SourceIP:       actor.IP,
		TargetType:     "CASE",
		TargetID:       caseID,
		Action:         action,
		Changes:        changes,
	}
}

// userCaseEvent builds an outbox event caused by an analyst.
func userCaseEvent(eventType, caseID, userID string, payload map[string]any) outbox.Event {
	return outbox.Event{
		Type:      eventType,
		Version:   1,
		Actor:     outbox.Actor{Type: outbox.ActorUser, ID: userID},
		SubjectID: caseID,
		Payload:   payload,
	}
}

// normalizePageLimit applies the default and bounds of the cursor pages. A nil
// limit is absent and takes the default.
func normalizePageLimit(limit *int) (int, error) {
	if limit == nil {
		return DefaultListLimit, nil
	}
	if *limit < 1 || *limit > MaxListLimit {
		return 0, invalid("limit", "limit must be 1 to %d", MaxListLimit)
	}
	return *limit, nil
}
