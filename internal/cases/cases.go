package cases

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

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
// reports the first case past the limit. A repeat crossing stays silent,
// because pipeline only needs to shadow a detection once.
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
	return casesOpened == service.maxCasesPerHour+1, nil
}

// assignOnCall locks the on-call rotation and picks the next user, or "" when
// nobody can take the case. The lock serializes concurrent case creation.
func (service *Service) assignOnCall(database *gorm.DB) (string, error) {
	var lastUserID *string
	err := database.Raw(
		"SELECT last_user_id::text AS last_user_id FROM on_call_rotation WHERE id = 1 FOR UPDATE",
	).Scan(&lastUserID).Error
	if err != nil {
		return "", fmt.Errorf("lock on-call rotation: %w", err)
	}
	return nextOnCallUser(database, lastUserID)
}

// nextOnCallUser picks the first candidate after lastUserID, or the first
// candidate when the rotation has reached its end.
func nextOnCallUser(database *gorm.DB, lastUserID *string) (string, error) {
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
		return "", fmt.Errorf("read on-call users: %w", err)
	}
	for _, candidate := range candidates {
		if lastUserID == nil || candidate > *lastUserID {
			return candidate, nil
		}
	}
	if len(candidates) > 0 {
		return candidates[0], nil
	}
	return "", nil
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
