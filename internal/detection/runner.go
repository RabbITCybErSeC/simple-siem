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
	revision, err := runner.nextRevision(ctx, manifest.ID, windowStart, windowEnd)
	if err != nil {
		return RunResult{}, err
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

	result := RunResult{
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

	run := runRow{
		DetectionID:      manifest.ID,
		DetectionVersion: manifest.Version,
		Status:           string(result.Status),
		WindowStart:      windowStart,
		WindowEnd:        windowEnd,
		Revision:         revision,
		RowsRead:         result.RowsRead,
		Proposals:        result.Proposals,
		Error:            optionalText(result.Error),
		StartedAt:        startedAt,
	}
	err = runner.Database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
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

// nextRevision is one more than the last revision of this detection window.
func (runner *Runner) nextRevision(ctx context.Context, detectionID string, windowStart, windowEnd time.Time) (int, error) {
	var current int
	row := runner.Database.WithContext(ctx).
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

func optionalText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
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
