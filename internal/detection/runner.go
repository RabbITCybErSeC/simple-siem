package detection

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/alerts"
	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"gorm.io/gorm"
)

// Errors the caller distinguishes: an inactive detection never runs, and an
// unknown or unready window records no run.
var (
	ErrDetectionInactive = errors.New("detection is inactive")
	ErrUnknownDetection  = errors.New("unknown detection")
	ErrInputNotReady     = errors.New("input is not ready")
	ErrInvalidWindow     = errors.New("invalid window")
)

// errApplyAlerts marks an alert application failure, so the run records a
// FAILED row instead of returning with no row.
var errApplyAlerts = errors.New("apply alerts")

// persistenceTimeout is the write allowance added to a run's evaluation budget.
// The run transaction runs without the caller's cancellation, so a canceled
// run still leaves its row.
const persistenceTimeout = 5 * time.Second

// inactiveError prints exactly the registry warning while still matching
// ErrDetectionInactive.
type inactiveError struct {
	warning string
}

func (failure inactiveError) Error() string {
	return failure.warning
}

func (failure inactiveError) Is(target error) bool {
	return target == ErrDetectionInactive
}

// appliedProposals is the outcome of applying one run's proposals.
type appliedProposals struct {
	stored       []Proposal
	created      int
	merged       int
	deduplicated int
}

// Runner evaluates one detection window and records the run and its
// proposals.
type Runner struct {
	Database *gorm.DB
	Store    dataset.Store
	Registry Registry
	Logger   *slog.Logger
	Alerts   *alerts.Service
}

// RunWindow evaluates and records one window ending at windowEnd. The
// returned error is non-nil only when no run row was written: an inactive or
// unknown detection, a window the database rejects, an input that is not
// ready, or the database itself. A failure to apply alerts still records a
// FAILED run row and returns that result.
func (runner *Runner) RunWindow(ctx context.Context, registration Registration, windowEnd time.Time, options RunOptions) (RunResult, error) {
	manifest, err := config.ParseDetectionManifest(registration.Manifest)
	if err != nil {
		return RunResult{}, fmt.Errorf("detection manifest: %w", err)
	}
	if warning, inactive := runner.Registry.Inactive[manifest.ID]; inactive {
		return RunResult{}, inactiveError{warning: warning}
	}
	if _, known := runner.Registry.Manifests[manifest.ID]; !known {
		return RunResult{}, fmt.Errorf("%w: %s", ErrUnknownDetection, manifest.ID)
	}

	if windowEnd.Nanosecond() != 0 {
		return RunResult{}, fmt.Errorf("%w: window end %s is not a whole second",
			ErrInvalidWindow, windowEnd.Format(time.RFC3339Nano))
	}
	var databaseNow time.Time
	if err := runner.Database.WithContext(ctx).Raw("SELECT now()").Scan(&databaseNow).Error; err != nil {
		return RunResult{}, fmt.Errorf("read the database clock: %w", err)
	}
	if windowEnd.After(databaseNow) {
		return RunResult{}, fmt.Errorf("%w: window end %s is in the future (database time %s)",
			ErrInvalidWindow, formatInstant(windowEnd), formatInstant(databaseNow))
	}

	windowStart := windowEnd.Add(-time.Duration(manifest.Window.Size))
	if err := runner.checkInputsReady(ctx, manifest, windowEnd); err != nil {
		return RunResult{}, err
	}

	// The run transaction takes the window's advisory lock before reading the
	// revision and holds it through the insert, so concurrent runs of one
	// detection window are serialised and each gets the next revision. The
	// evaluation runs inside it so the window and the row share one revision.
	// The deadline covers waiting behind one run plus a full evaluation and the
	// writes, and survives the caller's cancellation so a canceled run still
	// leaves its row. lock_timeout caps the wait at one run, so a waiter that
	// does acquire the lock still has its whole budget to evaluate.
	runAllowance := time.Duration(manifest.Budgets.Timeout) + persistenceTimeout
	transactionContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*runAllowance)
	defer cancel()

	var result RunResult
	var startedAt time.Time
	// shortcut: evaluation holds the window-lock transaction (one pooled connection per run for up to the evaluation budget); reserve the revision in a short transaction and evaluate outside it when the Phase 3 scheduler runs detections concurrently (bead simple-siem-tc3).
	err = runner.Database.WithContext(transactionContext).Transaction(func(transaction *gorm.DB) error {
		if err := setLockTimeout(transaction, runAllowance); err != nil {
			return err
		}
		if err := lockWindow(transaction, manifest.ID, windowStart, windowEnd); err != nil {
			return err
		}
		revision, err := nextRevision(transaction, manifest.ID, windowStart, windowEnd)
		if err != nil {
			return err
		}

		window := Window{
			Start:    windowStart,
			End:      windowEnd,
			Revision: revision,
			reader:   runner.Store,
			inputs:   declaredInputs(manifest),
			budget:   newRowBudget(manifest.Budgets.MaxRows),
		}
		startedAt = time.Now().UTC()
		outcome := evaluate(ctx, manifest, registration.Logic, window)

		result = RunResult{
			Status:      outcome.status,
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
			Revision:    revision,
			RowsRead:    window.budget.count(),
			Mode:        RunModeShadow,
		}
		if outcome.status == RunStatusOK {
			result.Proposals = len(outcome.proposals)
		}
		if outcome.err != nil {
			result.Error = outcome.err.Error()
		}

		run := runRow{
			DetectionID:      manifest.ID,
			DetectionVersion: manifest.Version,
			Status:           string(result.Status),
			WindowStart:      windowStart,
			WindowEnd:        windowEnd,
			Revision:         revision,
			RowsRead:         result.RowsRead,
			Proposals:        result.Proposals,
			Mode:             string(RunModeShadow),
			Error:            dataset.OptionalText(result.Error),
			StartedAt:        startedAt,
		}
		if err := transaction.Create(&run).Error; err != nil {
			return fmt.Errorf("insert the run record: %w", err)
		}
		result.RunID = run.ID
		if outcome.status != RunStatusOK {
			return nil
		}

		if err := alerts.EnsureRuntime(transaction, manifest.ID, manifest.InitialStatus); err != nil {
			return fmt.Errorf("register the detection runtime: %w", err)
		}
		status, err := alerts.Status(transaction, manifest.ID)
		if err != nil {
			return fmt.Errorf("read the detection status: %w", err)
		}
		mode := RunModeShadow
		if status == "ENABLED" && !options.Shadow && runner.Alerts != nil {
			mode = RunModeEnabled
		}

		storedProposals := outcome.proposals
		var alertsCreated, alertsMerged, proposalsDeduplicated int
		if mode == RunModeEnabled {
			applied, err := runner.applyEnabledProposals(transactionContext, transaction, manifest, run.ID, outcome.proposals)
			if err != nil {
				return err
			}
			storedProposals = applied.stored
			alertsCreated = applied.created
			alertsMerged = applied.merged
			proposalsDeduplicated = applied.deduplicated
		}

		if len(storedProposals) > 0 {
			rows, err := proposalRows(storedProposals, run.ID, manifest)
			if err != nil {
				return err
			}
			if err := transaction.Create(&rows).Error; err != nil {
				return fmt.Errorf("insert detection proposals: %w", err)
			}
		}

		result.Mode = mode
		result.AlertsCreated = alertsCreated
		result.AlertsMerged = alertsMerged
		result.ProposalsDeduplicated = proposalsDeduplicated
		err = transaction.Model(&runRow{}).Where("id = ?", run.ID).Updates(map[string]any{
			"mode":                   string(mode),
			"alerts_created":         alertsCreated,
			"alerts_merged":          alertsMerged,
			"proposals_deduplicated": proposalsDeduplicated,
		}).Error
		if err != nil {
			return fmt.Errorf("update the run counters: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errApplyAlerts) {
			runner.Logger.Error("apply alerts", "detection", manifest.ID, "error", err)
			return runner.recordApplyFailure(transactionContext, manifest, windowStart, windowEnd, startedAt, result.RowsRead)
		}
		return RunResult{}, fmt.Errorf("detection %q: %w", manifest.ID, err)
	}

	return result, nil
}

// applyEnabledProposals applies proposals in order. After a guardrail trip it
// returns the proposals that still need to be stored; without one it returns
// none.
func (runner *Runner) applyEnabledProposals(ctx context.Context, transaction *gorm.DB,
	manifest config.DetectionManifest, runID string, proposals []Proposal) (appliedProposals, error) {
	policy := alerts.Policy{
		Mode:           alerts.Mode(manifest.Alerting.Mode),
		CoalesceWindow: time.Duration(manifest.Alerting.CoalesceWindow),
		MaxAlertSpan:   time.Duration(manifest.Alerting.MaxAlertSpan),
	}
	var applied appliedProposals
	for index, proposal := range proposals {
		identity, err := ComputeIdentity(manifest.ID, manifest.Alerting, proposal.Subject)
		if err != nil {
			return appliedProposals{}, err
		}
		outcome, err := runner.Alerts.Apply(
			ctx, transaction, policy, alertProposal(manifest, runID, identity, proposal))
		if err != nil {
			return appliedProposals{}, fmt.Errorf("%w: %w", errApplyAlerts, err)
		}
		switch outcome.Action {
		case alerts.ActionCreated:
			applied.created++
		case alerts.ActionMerged:
			applied.merged++
		case alerts.ActionNoop:
			applied.deduplicated++
		}
		if outcome.GuardrailTripped {
			applied.stored = proposals[index+1:]
			break
		}
	}
	return applied, nil
}

// recordApplyFailure writes the FAILED row for a window whose alert
// application failed. Its own transaction takes the window lock, so the
// rolled-back attempt left no row and this one gets the next revision.
func (runner *Runner) recordApplyFailure(ctx context.Context, manifest config.DetectionManifest,
	windowStart, windowEnd time.Time, startedAt time.Time, rowsRead int) (RunResult, error) {
	runAllowance := time.Duration(manifest.Budgets.Timeout) + persistenceTimeout
	var failure runRow
	err := runner.Database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := setLockTimeout(transaction, runAllowance); err != nil {
			return err
		}
		if err := lockWindow(transaction, manifest.ID, windowStart, windowEnd); err != nil {
			return err
		}
		revision, err := nextRevision(transaction, manifest.ID, windowStart, windowEnd)
		if err != nil {
			return err
		}
		failure = runRow{
			DetectionID:      manifest.ID,
			DetectionVersion: manifest.Version,
			Status:           string(RunStatusFailed),
			WindowStart:      windowStart,
			WindowEnd:        windowEnd,
			Revision:         revision,
			RowsRead:         rowsRead,
			Mode:             string(RunModeShadow),
			Error:            dataset.OptionalText("apply alerts failed"),
			StartedAt:        startedAt,
		}
		if err := transaction.Create(&failure).Error; err != nil {
			return fmt.Errorf("insert the failed run record: %w", err)
		}
		return nil
	})
	if err != nil {
		return RunResult{}, fmt.Errorf("detection %q: record the apply failure: %w", manifest.ID, err)
	}
	return RunResult{
		RunID:       failure.ID,
		Status:      RunStatusFailed,
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
		Revision:    failure.Revision,
		RowsRead:    rowsRead,
		Mode:        RunModeShadow,
		Error:       "apply alerts failed",
	}, nil
}

// proposalRows builds the stored proposal rows shared by the shadow path and
// the proposals left after a guardrail switch.
func proposalRows(proposals []Proposal, runID string, manifest config.DetectionManifest) ([]proposalRow, error) {
	rows := make([]proposalRow, len(proposals))
	for index, proposal := range proposals {
		identity, err := ComputeIdentity(manifest.ID, manifest.Alerting, proposal.Subject)
		if err != nil {
			return nil, err
		}
		details := proposal.Details
		if details == nil {
			details = map[string]string{}
		}
		evidence := make([]proposalEvidence, len(proposal.Evidence))
		for evidenceIndex, item := range proposal.Evidence {
			evidence[evidenceIndex] = proposalEvidence(item)
		}
		rows[index] = proposalRow{
			DetectionRunID: runID,
			IdentityHash:   identity.Hash,
			Identity:       identity.Values,
			Subject:        proposal.Subject,
			Summary:        proposal.Summary,
			Details:        details,
			Severity:       string(proposal.Severity),
			Evidence:       evidence,
		}
	}
	return rows, nil
}

// alertProposal converts one evaluated proposal to the alerts package.
func alertProposal(manifest config.DetectionManifest, runID string, identity Identity, proposal Proposal) alerts.Proposal {
	evidence := make([]alerts.Evidence, len(proposal.Evidence))
	for index, item := range proposal.Evidence {
		evidence[index] = alerts.Evidence{SourceKey: item.SourceKey, EventTime: item.EventTime}
	}
	return alerts.Proposal{
		DetectionID:           manifest.ID,
		DetectionVersion:      manifest.Version,
		DetectionRunID:        runID,
		IdentityHash:          identity.Hash,
		IdentitySchemaVersion: manifest.Alerting.IdentitySchemaVersion,
		Identity:              identity.Values,
		Subject:               proposal.Subject,
		Summary:               proposal.Summary,
		Details:               proposal.Details,
		Severity:              alerts.Severity(proposal.Severity),
		Evidence:              evidence,
	}
}

// checkInputsReady requires every input's dataset watermark to be at or after
// the window end, so a run never evaluates an incomplete dataset.
func (runner *Runner) checkInputsReady(ctx context.Context, manifest config.DetectionManifest, windowEnd time.Time) error {
	var behind []string
	for _, input := range manifest.Inputs {
		watermark, err := runner.Store.Watermark(ctx, input.Dataset)
		if errors.Is(err, dataset.ErrUnknownDataset) {
			behind = append(behind, fmt.Sprintf("%s watermark unset", input.Dataset))
			continue
		}
		if err != nil {
			return fmt.Errorf("read the watermark of input dataset %q: %w", input.Dataset, err)
		}
		if watermark.DatasetWatermark.Before(windowEnd) {
			behind = append(behind, fmt.Sprintf("%s watermark %s",
				input.Dataset, formatWatermark(watermark.DatasetWatermark)))
		}
	}
	if len(behind) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s is before window end %s",
		ErrInputNotReady, strings.Join(behind, ", "), formatInstant(windowEnd))
}

// setLockTimeout caps a run's wait for the window lock at one run's allowance.
func setLockTimeout(transaction *gorm.DB, allowance time.Duration) error {
	err := transaction.Exec(fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", allowance.Milliseconds())).Error
	if err != nil {
		return fmt.Errorf("set the run lock wait: %w", err)
	}
	return nil
}

// lockWindow serialises concurrent runs of one detection window. The lock
// lasts for the run's transaction, so the next run waits and then reads the
// revision this one committed.
func lockWindow(transaction *gorm.DB, detectionID string, windowStart, windowEnd time.Time) error {
	key := detectionID + "|" + windowStart.UTC().Format(time.RFC3339Nano) + "|" + windowEnd.UTC().Format(time.RFC3339Nano)
	err := transaction.Exec("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", key).Error
	if err != nil {
		return fmt.Errorf("lock detection %q window [%s, %s): %w",
			detectionID, formatInstant(windowStart), formatInstant(windowEnd), err)
	}
	return nil
}

// nextRevision is one more than the last revision of this detection window.
// It runs in the run's transaction, under the window lock.
func nextRevision(transaction *gorm.DB, detectionID string, windowStart, windowEnd time.Time) (int, error) {
	var current int
	row := transaction.
		Model(&runRow{}).
		Select("COALESCE(MAX(revision), 0)").
		Where("detection_id = ? AND window_start = ? AND window_end = ?", detectionID, windowStart, windowEnd).
		Row()
	if err := row.Scan(&current); err != nil {
		return 0, fmt.Errorf("read the revision of detection %q window [%s, %s): %w",
			detectionID, formatInstant(windowStart), formatInstant(windowEnd), err)
	}
	return current + 1, nil
}

func formatInstant(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

func formatWatermark(value time.Time) string {
	if value.IsZero() {
		return "unset"
	}
	return formatInstant(value)
}
