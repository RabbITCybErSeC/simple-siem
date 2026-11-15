package detection

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

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

// Runner evaluates one detection window and records the run and its
// proposals.
type Runner struct {
	Database *gorm.DB
	Store    dataset.Store
	Registry Registry
	Logger   *slog.Logger
}

// RunWindow evaluates and records one window ending at windowEnd. The
// returned error is non-nil only when no run row was written: an inactive or
// unknown detection, a window the database rejects, an input that is not
// ready, or the database itself.
func (runner *Runner) RunWindow(ctx context.Context, registration Registration, windowEnd time.Time) (RunResult, error) {
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
	// evaluation runs inside it so the window and the row share one revision;
	// the deadline covers a whole evaluation plus the writes, and survives the
	// caller's cancellation so a canceled run still leaves its row.
	runDeadline := time.Duration(manifest.Budgets.Timeout) + persistenceTimeout
	transactionContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), runDeadline)
	defer cancel()

	var result RunResult
	var run runRow
	err = runner.Database.WithContext(transactionContext).Transaction(func(transaction *gorm.DB) error {
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
		startedAt := time.Now().UTC()
		outcome := evaluate(ctx, manifest, registration.Logic, window)

		result = RunResult{
			Status:      outcome.status,
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
			Revision:    revision,
			RowsRead:    window.budget.count(),
		}
		if outcome.status == RunStatusOK {
			result.Proposals = len(outcome.proposals)
		}
		if outcome.err != nil {
			result.Error = outcome.err.Error()
		}

		run = runRow{
			DetectionID:      manifest.ID,
			DetectionVersion: manifest.Version,
			Status:           string(result.Status),
			WindowStart:      windowStart,
			WindowEnd:        windowEnd,
			Revision:         revision,
			RowsRead:         result.RowsRead,
			Proposals:        result.Proposals,
			Error:            dataset.OptionalText(result.Error),
			StartedAt:        startedAt,
		}
		if err := transaction.Create(&run).Error; err != nil {
			return fmt.Errorf("insert the run record: %w", err)
		}
		if outcome.status != RunStatusOK {
			return nil
		}

		rows := make([]proposalRow, len(outcome.proposals))
		for index, proposal := range outcome.proposals {
			identity, err := ComputeIdentity(manifest.ID, manifest.Alerting, proposal.Subject)
			if err != nil {
				return err
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
				DetectionRunID: run.ID,
				IdentityHash:   identity.Hash,
				Identity:       identity.Values,
				Subject:        proposal.Subject,
				Summary:        proposal.Summary,
				Details:        details,
				Severity:       string(proposal.Severity),
				Evidence:       evidence,
			}
		}
		if len(rows) > 0 {
			if err := transaction.Create(&rows).Error; err != nil {
				return fmt.Errorf("insert detection proposals: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return RunResult{}, fmt.Errorf("detection %q: %w", manifest.ID, err)
	}

	result.RunID = run.ID
	return result, nil
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
