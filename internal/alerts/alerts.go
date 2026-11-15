package alerts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/audit"
	"github.com/RabbITCybErSeC/simple-siem/internal/outbox"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrInvalidProposal is returned when a proposal is missing required values or
// names an unknown mode or severity. Nothing is written.
var ErrInvalidProposal = errors.New("invalid proposal")

// shadowReason is recorded when the case-rate guardrail switches a detection.
const shadowReason = "case_rate_exceeded"

// evidenceHashRow reads one source_key_hash from alert_evidence.
type evidenceHashRow struct {
	SourceKeyHash []byte `gorm:"column:source_key_hash"`
}

// hashedEvidence is one evidence item with its source key hash, so the hash
// runs once per item.
type hashedEvidence struct {
	Evidence
	hash []byte
}

// Apply applies one proposal inside the caller's transaction.
func (service *Service) Apply(ctx context.Context, tx *gorm.DB, policy Policy, proposal Proposal) (Outcome, error) {
	if err := validateProposal(policy, proposal); err != nil {
		return Outcome{}, err
	}
	if err := lockIdentity(tx, proposal); err != nil {
		return Outcome{}, err
	}

	evidence := uniqueEvidence(proposal.Evidence)
	earliest, _ := eventRange(evidence)
	newEvidence, err := unseenEvidence(tx, proposal, policy, evidence, earliest)
	if err != nil {
		return Outcome{}, err
	}
	if len(newEvidence) == 0 {
		return Outcome{Action: ActionNoop}, nil
	}

	open, err := openCoalescingAlert(tx, proposal, policy.Mode)
	if err != nil {
		return Outcome{}, err
	}
	first, last := eventRange(newEvidence)
	if open != nil && shouldMerge(policy, *open, first, last) {
		return service.merge(ctx, tx, proposal, *open, newEvidence, first, last)
	}
	if open != nil {
		if err := splitAlert(tx, open.ID); err != nil {
			return Outcome{}, err
		}
	}
	previousAlertID, err := previousAlertOfIdentity(tx, proposal, first, policy.MaxAlertSpan)
	if err != nil {
		return Outcome{}, err
	}
	return service.create(ctx, tx, proposal, policy, newEvidence, first, last, previousAlertID)
}

// shouldMerge reports whether new evidence belongs in the open alert.
func shouldMerge(policy Policy, open alertRow, first, last time.Time) bool {
	switch policy.Mode {
	case ModeUnique:
		return true
	case ModeMerge:
		var gap time.Duration
		switch {
		case first.After(open.LastEventAt):
			gap = first.Sub(open.LastEventAt)
		case last.Before(open.FirstEventAt):
			gap = open.FirstEventAt.Sub(last)
		}
		spanStart := first
		if open.FirstEventAt.Before(spanStart) {
			spanStart = open.FirstEventAt
		}
		spanEnd := last
		if open.LastEventAt.After(spanEnd) {
			spanEnd = open.LastEventAt
		}
		return gap <= policy.CoalesceWindow && spanEnd.Sub(spanStart) <= policy.MaxAlertSpan
	default:
		return false
	}
}

// previousAlertOfIdentity returns the most recent alert of the identity that
// is recent enough to link, or nil.
func previousAlertOfIdentity(tx *gorm.DB, proposal Proposal, first time.Time, maxAlertSpan time.Duration) (*string, error) {
	var ids []string
	err := tx.Model(&alertRow{}).
		Where("detection_id = ? AND identity_hash = ? AND last_event_at >= ?",
			proposal.DetectionID, proposal.IdentityHash, first.Add(-maxAlertSpan)).
		Order("last_event_at DESC").
		Limit(1).
		Pluck("id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("load the previous alert: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return &ids[0], nil
}

// splitAlert stops the old alert from coalescing; it stays OPEN and linked
// from the new alert.
func splitAlert(tx *gorm.DB, alertID string) error {
	err := tx.Exec("UPDATE alerts SET coalescing = false, updated_at = now(), version = version + 1 WHERE id = ?", alertID).Error
	if err != nil {
		return fmt.Errorf("split alert %q: %w", alertID, err)
	}
	return nil
}

func validateProposal(policy Policy, proposal Proposal) error {
	switch {
	case len(proposal.Evidence) == 0:
		return fmt.Errorf("%w: no evidence", ErrInvalidProposal)
	case proposal.DetectionID == "":
		return fmt.Errorf("%w: detection id is empty", ErrInvalidProposal)
	case proposal.IdentityHash == "":
		return fmt.Errorf("%w: identity hash is empty", ErrInvalidProposal)
	case proposal.DetectionRunID == "":
		return fmt.Errorf("%w: detection run id is empty", ErrInvalidProposal)
	case policy.Mode != ModeMerge && policy.Mode != ModeUnique && policy.Mode != ModeAlwaysNew:
		return fmt.Errorf("%w: unknown mode %q", ErrInvalidProposal, policy.Mode)
	case proposal.Severity != SeverityLow && proposal.Severity != SeverityMedium && proposal.Severity != SeverityHigh:
		return fmt.Errorf("%w: unknown severity %q", ErrInvalidProposal, proposal.Severity)
	}
	return nil
}

// lockIdentity serializes every proposal of one detection identity across
// transactions and processes. The lock ends with the transaction.
func lockIdentity(tx *gorm.DB, proposal Proposal) error {
	key := "alert:" + proposal.DetectionID + ":" + proposal.IdentityHash
	err := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", key).Error
	if err != nil {
		return fmt.Errorf("lock alert identity %q: %w", proposal.IdentityHash, err)
	}
	return nil
}

// openCoalescingAlert loads the identity's open coalescing alert and locks it
// for the rest of the transaction. ALWAYS_NEW never uses one.
func openCoalescingAlert(tx *gorm.DB, proposal Proposal, mode Mode) (*alertRow, error) {
	if mode == ModeAlwaysNew {
		return nil, nil
	}
	var open alertRow
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("detection_id = ? AND identity_hash = ? AND status = 'OPEN' AND coalescing",
			proposal.DetectionID, proposal.IdentityHash).
		First(&open).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load the open alert: %w", err)
	}
	return &open, nil
}

// unseenEvidence drops evidence already attached to an alert of this identity
// that is recent enough to cover the proposal.
func unseenEvidence(tx *gorm.DB, proposal Proposal, policy Policy, evidence []hashedEvidence, earliest time.Time) ([]hashedEvidence, error) {
	hashes := make([][]byte, len(evidence))
	for index, item := range evidence {
		hashes[index] = item.hash
	}

	var existing []evidenceHashRow
	err := tx.Table("alert_evidence").
		Select("alert_evidence.source_key_hash").
		Joins("JOIN alerts ON alerts.id = alert_evidence.alert_id").
		Where("alerts.detection_id = ? AND alerts.identity_hash = ?", proposal.DetectionID, proposal.IdentityHash).
		Where("alerts.last_event_at >= ?", earliest.Add(-policy.MaxAlertSpan)).
		Where("alert_evidence.source_key_hash IN ?", hashes).
		Find(&existing).Error
	if err != nil {
		return nil, fmt.Errorf("load seen alert evidence: %w", err)
	}

	seen := make(map[string]struct{}, len(existing))
	for _, row := range existing {
		seen[string(row.SourceKeyHash)] = struct{}{}
	}
	newEvidence := make([]hashedEvidence, 0, len(evidence))
	for _, item := range evidence {
		if _, ok := seen[string(item.hash)]; ok {
			continue
		}
		newEvidence = append(newEvidence, item)
	}
	return newEvidence, nil
}

// uniqueEvidence drops repeated source keys inside one proposal, keeping the
// first occurrence.
func uniqueEvidence(evidence []Evidence) []hashedEvidence {
	unique := make([]hashedEvidence, 0, len(evidence))
	seen := make(map[string]struct{}, len(evidence))
	for _, item := range evidence {
		hash := item.SourceKey.Hash()
		key := string(hash)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, hashedEvidence{Evidence: item, hash: hash})
	}
	return unique
}

func eventRange(evidence []hashedEvidence) (time.Time, time.Time) {
	earliest := evidence[0].EventTime
	latest := evidence[0].EventTime
	for _, item := range evidence[1:] {
		if item.EventTime.Before(earliest) {
			earliest = item.EventTime
		}
		if item.EventTime.After(latest) {
			latest = item.EventTime
		}
	}
	return earliest, latest
}

// create writes one new alert with its evidence, first occurrence, and audit
// event.
func (service *Service) create(ctx context.Context, tx *gorm.DB, proposal Proposal, policy Policy, newEvidence []hashedEvidence, first, last time.Time, previousAlertID *string) (Outcome, error) {
	details := proposal.Details
	if details == nil {
		details = map[string]string{}
	}
	alert := alertRow{
		DetectionID:           proposal.DetectionID,
		DetectionVersion:      proposal.DetectionVersion,
		IdentityHash:          proposal.IdentityHash,
		IdentitySchemaVersion: proposal.IdentitySchemaVersion,
		Identity:              proposal.Identity,
		Subject:               proposal.Subject,
		Summary:               proposal.Summary,
		Details:               details,
		Severity:              string(proposal.Severity),
		Coalescing:            policy.Mode != ModeAlwaysNew,
		FirstEventAt:          first,
		LastEventAt:           last,
		EvidenceCount:         len(newEvidence),
		PreviousAlertID:       previousAlertID,
	}
	if err := tx.Create(&alert).Error; err != nil {
		return Outcome{}, fmt.Errorf("insert alert: %w", err)
	}
	if err := tx.Create(evidenceRows(alert.ID, newEvidence)).Error; err != nil {
		return Outcome{}, fmt.Errorf("insert alert evidence: %w", err)
	}
	if err := insertOccurrence(tx, alert.ID, proposal.DetectionRunID, len(newEvidence), first, last); err != nil {
		return Outcome{}, err
	}
	if err := writeCreatedAudit(tx, alert); err != nil {
		return Outcome{}, err
	}
	guardrailTripped := false
	if service.Hooks != nil {
		outcome, err := service.Hooks.AlertCreated(ctx, tx, NewAlert{
			ID:               alert.ID,
			DetectionID:      alert.DetectionID,
			DetectionVersion: alert.DetectionVersion,
			Title:            alert.Summary,
			Severity:         proposal.Severity,
			IdentityHash:     alert.IdentityHash,
			FirstEventAt:     alert.FirstEventAt,
			LastEventAt:      alert.LastEventAt,
			PreviousAlertID:  alert.PreviousAlertID,
		})
		if err != nil {
			return Outcome{}, fmt.Errorf("case hook: %w", err)
		}
		guardrailTripped = outcome.GuardrailTripped
		if guardrailTripped {
			if err := switchDetectionToShadow(tx, proposal.DetectionID); err != nil {
				return Outcome{}, err
			}
		}
	}
	return Outcome{
		Action:           ActionCreated,
		AlertID:          alert.ID,
		NewEvidence:      len(newEvidence),
		GuardrailTripped: guardrailTripped,
	}, nil
}

// merge adds evidence to an open alert, records one occurrence, and widens
// the alert's range and counts.
func (service *Service) merge(ctx context.Context, tx *gorm.DB, proposal Proposal, open alertRow, newEvidence []hashedEvidence, first, last time.Time) (Outcome, error) {
	result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(evidenceRows(open.ID, newEvidence))
	if result.Error != nil {
		return Outcome{}, fmt.Errorf("insert alert evidence: %w", result.Error)
	}
	inserted := int(result.RowsAffected)
	if inserted == 0 {
		return Outcome{Action: ActionNoop}, nil
	}
	if err := insertOccurrence(tx, open.ID, proposal.DetectionRunID, inserted, first, last); err != nil {
		return Outcome{}, err
	}
	row := tx.Raw(`
		UPDATE alerts
		SET first_event_at = LEAST(first_event_at, ?),
		    last_event_at = GREATEST(last_event_at, ?),
		    occurrence_count = occurrence_count + 1,
		    evidence_count = evidence_count + ?,
		    updated_at = now(),
		    version = version + 1
		WHERE id = ?
		RETURNING last_event_at`,
		first, last, inserted, open.ID).Row()
	var mergedLastEventAt time.Time
	if err := row.Scan(&mergedLastEventAt); err != nil {
		return Outcome{}, fmt.Errorf("merge alert %q: %w", open.ID, err)
	}
	if service.Hooks != nil {
		if err := service.Hooks.EvidenceAdded(ctx, tx, open.ID, mergedLastEventAt, inserted); err != nil {
			return Outcome{}, fmt.Errorf("case hook: %w", err)
		}
	}
	return Outcome{Action: ActionMerged, AlertID: open.ID, NewEvidence: inserted}, nil
}

// insertOccurrence records one run's evidence contribution to an alert.
func insertOccurrence(tx *gorm.DB, alertID, runID string, count int, first, last time.Time) error {
	occurrence := occurrenceRow{
		AlertID:          alertID,
		DetectionRunID:   runID,
		NewEvidenceCount: count,
		FirstEventAt:     first,
		LastEventAt:      last,
	}
	if err := tx.Create(&occurrence).Error; err != nil {
		return fmt.Errorf("insert alert occurrence: %w", err)
	}
	return nil
}

func evidenceRows(alertID string, evidence []hashedEvidence) []evidenceRow {
	rows := make([]evidenceRow, len(evidence))
	for index, item := range evidence {
		rows[index] = evidenceRow{
			AlertID:           alertID,
			SourceKeyHash:     item.hash,
			FetcherInstanceID: item.SourceKey.FetcherInstanceID,
			SourceIndex:       item.SourceKey.Index,
			DocumentID:        item.SourceKey.DocumentID,
			EventTime:         item.EventTime,
		}
	}
	return rows
}

func writeCreatedAudit(tx *gorm.DB, alert alertRow) error {
	err := audit.Record(tx, audit.Event{
		EventName:     "simple_siem.alert.created",
		EventCategory: "ALERT",
		EventOutcome:  "SUCCESS",
		ActorType:     "SYSTEM",
		TargetType:    "ALERT",
		TargetID:      alert.ID,
		Action:        "create",
		Changes: map[string]any{
			"detectionId":      alert.DetectionID,
			"detectionVersion": alert.DetectionVersion,
			"identityHash":     alert.IdentityHash,
			"severity":         alert.Severity,
			"previousAlertId":  alert.PreviousAlertID,
			"evidenceCount":    alert.EvidenceCount,
		},
	})
	if err != nil {
		return fmt.Errorf("record alert.created audit event: %w", err)
	}
	return nil
}

// switchDetectionToShadow applies the case-rate guardrail. Only an ENABLED
// detection changes, and the switch carries its audit and outbox events.
func switchDetectionToShadow(tx *gorm.DB, detectionID string) error {
	from := string(RuntimeStatusEnabled)
	to := string(RuntimeStatusShadow)
	reason := shadowReason
	result := tx.Exec(`
		UPDATE detection_runtime
		SET status = ?, reason = ?, changed_at = now(), version = version + 1
		WHERE detection_id = ? AND status = ?`, to, reason, detectionID, from)
	if result.Error != nil {
		return fmt.Errorf("switch detection %q to shadow: %w", detectionID, result.Error)
	}
	if result.RowsAffected == 0 {
		return nil
	}
	err := audit.Record(tx, audit.Event{
		EventName:     "simple_siem.detection.status_changed",
		EventCategory: "DETECTION",
		EventOutcome:  "SUCCESS",
		ActorType:     "SYSTEM",
		TargetType:    "DETECTION",
		TargetID:      detectionID,
		Action:        "update",
		Changes: map[string]any{
			"from":   from,
			"to":     to,
			"reason": reason,
		},
	})
	if err != nil {
		return fmt.Errorf("record detection status audit event: %w", err)
	}
	err = outbox.Record(tx, outbox.Event{
		Type:      outbox.TypeDetectionStatusChanged,
		Version:   1,
		Actor:     outbox.Actor{Type: outbox.ActorSystem, ID: "detection-engine"},
		SubjectID: detectionID,
		Payload: map[string]any{
			"detectionId": detectionID,
			"from":        from,
			"to":          to,
			"reason":      reason,
		},
	})
	if err != nil {
		return fmt.Errorf("record detection status event: %w", err)
	}
	return nil
}

// EnsureRuntime creates the detection's runtime row on its first run.
func EnsureRuntime(tx *gorm.DB, detectionID, initialStatus string) error {
	err := tx.Exec(`
		INSERT INTO detection_runtime (detection_id, status)
		VALUES (?, ?)
		ON CONFLICT (detection_id) DO NOTHING`, detectionID, initialStatus).Error
	if err != nil {
		return fmt.Errorf("ensure detection runtime for %q: %w", detectionID, err)
	}
	return nil
}

// Status reads the detection's runtime status.
func Status(tx *gorm.DB, detectionID string) (RuntimeStatus, error) {
	var runtime runtimeRow
	err := tx.Where("detection_id = ?", detectionID).First(&runtime).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("detection %q has no runtime row", detectionID)
	}
	if err != nil {
		return "", fmt.Errorf("read detection runtime for %q: %w", detectionID, err)
	}
	return RuntimeStatus(runtime.Status), nil
}
