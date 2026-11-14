package pipeline

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/RabbITCybErSeC/simple-siem/internal/config"
	"github.com/RabbITCybErSeC/simple-siem/internal/converter"
	"github.com/RabbITCybErSeC/simple-siem/internal/dataset"
	"github.com/RabbITCybErSeC/simple-siem/internal/fetcher"
	"gorm.io/gorm"
)

const (
	phaseOneShapeMessage = "Phase 1 runs one fetcher step, one converter, one output"

	defaultRunnerBatchSize          = 5000
	defaultRunnerMaxQuarantineRatio = 0.10
	finishTimeout                   = 5 * time.Second

	advisoryLockStatement   = "SELECT pg_try_advisory_lock(hashtextextended('pipeline:' || $1, 0))"
	advisoryUnlockStatement = "SELECT pg_advisory_unlock(hashtextextended('pipeline:' || $1, 0))"
)

// ValidateFiles checks the Phase 1 pipeline shape and loads every mapping so
// catalog errors surface at configuration validation.
func ValidateFiles(files config.Files) error {
	var problems []error
	for _, pipeline := range files.Pipelines {
		shape, ok := phaseOneShape(pipeline)
		if !ok {
			problems = append(problems, fmt.Errorf("pipeline %q: %s", pipeline.ID, phaseOneShapeMessage))
			continue
		}

		instance, known := files.Fetchers[shape.Step.Ref]
		switch {
		case !known:
			problems = append(problems, fmt.Errorf("pipeline %q: fetcher step %q: unknown fetcher instance %q",
				pipeline.ID, shape.Step.ID, shape.Step.Ref))
		case instance.Type != "elasticsearch":
			problems = append(problems, fmt.Errorf("pipeline %q: fetcher step %q: fetcher type %q is not implemented",
				pipeline.ID, shape.Step.ID, instance.Type))
		}

		if _, err := converter.LoadMappings(mappingPaths(files.Directory, shape.Processor.Mappings)); err != nil {
			problems = append(problems, fmt.Errorf("pipeline %q: %w", pipeline.ID, err))
		}
	}
	return errors.Join(problems...)
}

// phaseOneShape resolves a pipeline to the one fetcher step, converter and
// output that Phase 1 runs, or reports that it is not a Phase 1 pipeline.
func phaseOneShape(pipeline config.Pipeline) (phaseOnePipeline, bool) {
	if len(pipeline.Fetchers) != 1 || len(pipeline.Processors) != 1 || len(pipeline.Outputs) != 1 {
		return phaseOnePipeline{}, false
	}
	step := pipeline.Fetchers[0]
	processor := pipeline.Processors[0]
	if processor.Type != "converter" || processor.From != step.ID+".records" {
		return phaseOnePipeline{}, false
	}
	for name, output := range pipeline.Outputs {
		if output.From != processor.Output {
			return phaseOnePipeline{}, false
		}
		return phaseOnePipeline{Step: step, Processor: processor, Output: output, Dataset: name}, true
	}
	return phaseOnePipeline{}, false
}

// Run executes one pipeline once and leaves one run record behind. The
// returned error is non-nil only when no run record could be written.
func (runner *Runner) Run(ctx context.Context, pipelineID string) (RunResult, error) {
	pipeline, found := runner.pipeline(pipelineID)
	if !found {
		return RunResult{}, fmt.Errorf("unknown pipeline %q", pipelineID)
	}
	shape, ok := phaseOneShape(pipeline)
	if !ok {
		return RunResult{}, fmt.Errorf("pipeline %q: %s", pipeline.ID, phaseOneShapeMessage)
	}

	connection, acquired, err := runner.acquireLock(ctx, pipeline.ID)
	if err != nil {
		return RunResult{}, fmt.Errorf("pipeline %q: %w", pipeline.ID, err)
	}
	defer func() {
		_ = connection.Close()
	}()
	if !acquired {
		return runner.recordSkipped(ctx, pipeline, shape)
	}
	defer runner.releaseLock(connection, pipeline.ID)

	variables, err := pipeline.ResolveVariables(nil)
	if err != nil {
		return RunResult{}, fmt.Errorf("pipeline %q: %w", pipeline.ID, err)
	}
	instance, known := runner.Files.Fetchers[shape.Step.Ref]
	if !known {
		return RunResult{}, fmt.Errorf("pipeline %q: unknown fetcher instance %q", pipeline.ID, shape.Step.Ref)
	}
	retention, lateness := outputDurations(runner.Files, shape.Output)
	eventTimeSource := instance.Defaults.FetchTimeField == instance.Defaults.TimeField

	start, err := runner.startRun(ctx, pipeline, shape, retention, lateness, eventTimeSource)
	if err != nil {
		return RunResult{}, fmt.Errorf("pipeline %q: %w", pipeline.ID, err)
	}
	result, window, now := start.result, start.window, start.now
	timeout := time.Duration(pipeline.Schedule.Timeout)
	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	failRun := func(cause error) (RunResult, error) {
		result.Status, result.Error = failureStatus(ctx, runContext, timeout)
		if result.Status == StatusFailed {
			result.Error = sanitizedError(cause)
		}
		if err := runner.finishRun(ctx, result, nil, ""); err != nil {
			return result, err
		}
		return result, nil
	}

	if !window.Start.Before(window.End) {
		result.Status, result.Error = failureStatus(ctx, runContext, timeout)
		if result.Status == StatusFailed {
			result.Status = StatusOK
			result.Error = ""
		}
		if err := runner.finishRun(ctx, result, nil, ""); err != nil {
			return result, err
		}
		return result, nil
	}

	converterMappings, err := converter.LoadMappings(mappingPaths(runner.Files.Directory, shape.Processor.Mappings))
	if err != nil {
		return failRun(err)
	}
	converterInstance, err := converter.New(converterMappings, retention)
	if err != nil {
		return failRun(err)
	}
	if runner.NewFetcher == nil {
		return failRun(errors.New("no fetcher constructor is configured"))
	}
	fetcherInstance, err := runner.NewFetcher(instance)
	if err != nil {
		return failRun(err)
	}
	template, found := runner.Files.QueryTemplates[shape.Step.Inputs["query_template"].Literal]
	if !found {
		return failRun(fmt.Errorf("unknown query template %q", shape.Step.Inputs["query_template"].Literal))
	}
	index := shape.Step.Inputs["index"].Literal
	if index == "" {
		index = instance.Defaults.Index
	}
	request := fetcher.FetchRequest{
		PipelineRunID: result.RunID,
		Index:         index,
		Template:      template,
		Values:        templateValues(shape.Step, variables),
		Window:        fetcher.Window{Start: window.Start, End: window.End},
	}

	batchSize := runner.Files.System.Runner.BatchSize
	if batchSize <= 0 {
		batchSize = defaultRunnerBatchSize
	}
	maxQuarantineRatio := runner.Files.System.Runner.MaxQuarantineRatio
	if maxQuarantineRatio <= 0 {
		maxQuarantineRatio = defaultRunnerMaxQuarantineRatio
	}

	var batch runBatch
	var failedClosed *quarantineError
	commitPending := func() error {
		if batch.read() == 0 {
			return nil
		}
		if converter.FailsClosed(batch.counts, maxQuarantineRatio) {
			failedClosed = &quarantineError{quarantined: batch.counts.Quarantined, total: batch.read()}
			return failedClosed
		}
		if err := runner.commitBatch(runContext, shape.Dataset, result.RunID, batch); err != nil {
			return err
		}
		result.RecordsRead += batch.read()
		result.RecordsWritten += batch.counts.Converted
		result.RecordsQuarantined += batch.counts.Quarantined
		result.RecordsUnmapped += batch.counts.Unmapped
		result.RecordsLate += batch.counts.LateBeyondRetention
		batch = runBatch{}
		return nil
	}
	emit := func(page []fetcher.SourceRecord) error {
		for _, record := range page {
			converted := converterInstance.Convert(record.Payload, now)
			batch.counts.Add(converted.Outcome)
			batch.lastFetchTime = record.FetchTime
			switch converted.Outcome {
			case converter.OutcomeConverted:
				batch.records = append(batch.records, dataset.Record{
					Key:       record.Key,
					EventTime: converted.Event.Metadata.EventTimestamp,
					Event:     converted.Event,
					RunID:     result.RunID,
				})
			case converter.OutcomeQuarantined:
				batch.quarantined = append(batch.quarantined, dataset.QuarantinedRecord{
					Key:            record.Key,
					Payload:        record.Payload,
					MappingID:      converted.MappingID,
					MappingVersion: converted.MappingVersion,
					Errors:         converted.Errors,
				})
			}
			if batch.read() >= batchSize {
				if err := commitPending(); err != nil {
					return err
				}
			}
		}
		return nil
	}

	var fetchStatus fetcher.FetchStatus
	var fetchErr error
	if runContext.Err() == nil {
		fetchStatus, fetchErr = fetcherInstance.Fetch(runContext, request, emit)
	}
	var remainderErr error
	if failedClosed == nil && runContext.Err() == nil && ctx.Err() == nil {
		remainderErr = commitPending()
	}

	result.Truncated = fetchStatus.Truncated
	fetchFailures := fetchErrorRows(fetchStatus.Errors)
	contextStatus, contextMessage := failureStatus(ctx, runContext, timeout)
	switch {
	case contextStatus != StatusFailed:
		result.Status, result.Error = contextStatus, contextMessage
	case failedClosed != nil:
		result.Status = StatusFailed
		result.Error = failedClosed.Error()
	case remainderErr != nil:
		result.Status = StatusFailed
		result.Error = sanitizedError(remainderErr)
	case fetchStatus.Status == fetcher.StatusOK:
		result.Status = StatusOK
	case fetchStatus.Status == fetcher.StatusPartial:
		result.Status = StatusPartial
	default:
		result.Status = StatusFailed
		result.Error = fetchFailureMessage(fetchStatus, fetchErr)
	}

	if result.Status == StatusOK {
		if err := runner.commitWatermark(runContext, shape.Dataset, result.RunID, window.End); err != nil {
			result.Status, result.Error = failureStatus(ctx, runContext, timeout)
			if result.Status == StatusFailed {
				result.Error = sanitizedError(err)
			}
		}
	}

	if result.Status == StatusPartial {
		watermark, err := runner.fetchWatermark(ctx, shape.Dataset)
		if err != nil {
			runner.logger().Warn("pipeline run: read the fetch watermark", "dataset", shape.Dataset, "error", err)
		} else if !watermark.After(start.watermark) {
			result.Warnings = append(result.Warnings, "NO_PROGRESS")
		}
	}

	if result.RecordsRead >= 100 && result.RecordsUnmapped == result.RecordsRead {
		result.Warnings = append(result.Warnings, "ALL_UNMAPPED")
	}
	if result.Status != StatusCanceled && result.Status != StatusTimedOut {
		runner.expireDataset(ctx, shape.Dataset, now, &result)
	}

	if err := runner.finishRun(ctx, result, fetchFailures, fetchStatus.RenderedQueryHash); err != nil {
		return result, err
	}
	return result, nil
}

// startRun registers the dataset, computes the window from its watermark, and
// inserts the RUNNING run record against one database clock reading. Its writes
// survive the run's cancellation: the lock is already held.
func (runner *Runner) startRun(ctx context.Context, pipeline config.Pipeline, shape phaseOnePipeline,
	retention, lateness time.Duration, eventTimeSource bool) (runStart, error) {
	var start runStart

	// The store's watermark read uses its own connection, so registration has
	// to commit before the run transaction starts.
	registerContext, cancelRegistration := detach(ctx)
	err := runner.Database.WithContext(registerContext).Transaction(func(transaction *gorm.DB) error {
		return runner.registerDataset(registerContext, transaction, pipeline, shape, retention, lateness)
	})
	cancelRegistration()
	if err != nil {
		return runStart{}, err
	}

	startContext, cancel := detach(ctx)
	defer cancel()

	err = runner.Database.WithContext(startContext).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.Raw("SELECT now()").Scan(&start.now).Error; err != nil {
			return fmt.Errorf("read the database clock: %w", err)
		}
		watermark, err := runner.Store.Watermark(startContext, shape.Dataset)
		if err != nil {
			return err
		}
		start.watermark = watermark.FetchWatermark
		start.window = computeWindow(start.now, watermark, pipeline.Schedule, retention, lateness, eventTimeSource)

		// The lock proves no other run of this pipeline is alive, so every
		// earlier RUNNING row belongs to a process that ended mid-run.
		if err := markAbandonedRuns(transaction, pipeline.ID); err != nil {
			return err
		}

		row := runRow{
			PipelineID:  pipeline.ID,
			Dataset:     shape.Dataset,
			Status:      string(StatusRunning),
			WindowStart: &start.window.Start,
			WindowEnd:   &start.window.End,
			FetchErrors: []fetchErrorRow{},
			Warnings:    []string{},
		}
		if start.window.Gap != nil {
			row.GapStart = &start.window.Gap.Start
			row.GapEnd = &start.window.Gap.End
		}
		if err := transaction.Create(&row).Error; err != nil {
			return fmt.Errorf("insert the run record: %w", err)
		}
		start.result = RunResult{
			RunID:       row.ID,
			Status:      StatusRunning,
			WindowStart: start.window.Start,
			WindowEnd:   start.window.End,
			Warnings:    []string{},
		}
		return nil
	})
	if err != nil {
		return runStart{}, err
	}
	return start, nil
}

// markAbandonedRuns fails every earlier RUNNING row of the pipeline in the
// transaction that inserts the new one.
func markAbandonedRuns(transaction *gorm.DB, pipelineID string) error {
	err := transaction.Model(&runRow{}).
		Where("pipeline_id = ? AND status = ?", pipelineID, string(StatusRunning)).
		Updates(map[string]any{
			"status":      string(StatusFailed),
			"error":       "abandoned: the process ended during the run",
			"finished_at": gorm.Expr("now()"),
			"version":     gorm.Expr("version + 1"),
		}).Error
	if err != nil {
		return fmt.Errorf("mark abandoned runs: %w", err)
	}
	return nil
}

// recordSkipped writes the run record of a pipeline whose lock is held. It
// registers the dataset first so the record's foreign key always holds.
func (runner *Runner) recordSkipped(ctx context.Context, pipeline config.Pipeline, shape phaseOnePipeline) (RunResult, error) {
	const message = "another run of this pipeline is in progress"
	retention, lateness := outputDurations(runner.Files, shape.Output)
	result := RunResult{Status: StatusSkipped, Error: message, Warnings: []string{}}
	finishedAt := time.Now().UTC()

	var row runRow
	err := runner.Database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := runner.registerDataset(ctx, transaction, pipeline, shape, retention, lateness); err != nil {
			return err
		}
		row = runRow{
			PipelineID:  pipeline.ID,
			Dataset:     shape.Dataset,
			Status:      string(StatusSkipped),
			Error:       optionalText(message),
			FetchErrors: []fetchErrorRow{},
			Warnings:    []string{},
			FinishedAt:  &finishedAt,
		}
		return transaction.Create(&row).Error
	})
	if err != nil {
		return RunResult{}, fmt.Errorf("pipeline %q: record the skipped run: %w", pipeline.ID, err)
	}
	result.RunID = row.ID
	return result, nil
}

// acquireLock reserves one pooled connection and tries the pipeline's advisory
// lock on it. The caller holds the lock until it releases the connection.
func (runner *Runner) acquireLock(ctx context.Context, pipelineID string) (*sql.Conn, bool, error) {
	sqlDatabase, err := runner.Database.DB()
	if err != nil {
		return nil, false, fmt.Errorf("read the connection pool: %w", err)
	}
	connection, err := sqlDatabase.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("reserve a connection: %w", err)
	}
	var acquired bool
	if err := connection.QueryRowContext(ctx, advisoryLockStatement, pipelineID).Scan(&acquired); err != nil {
		_ = connection.Close()
		return nil, false, fmt.Errorf("take the run lock: %w", err)
	}
	return connection, acquired, nil
}

// releaseLock unlocks the advisory lock. A connection that cannot be unlocked
// is closed instead of returning to the pool still holding the lock.
func (runner *Runner) releaseLock(connection *sql.Conn, pipelineID string) {
	ctx, cancel := context.WithTimeout(context.Background(), finishTimeout)
	defer cancel()

	if _, err := connection.ExecContext(ctx, advisoryUnlockStatement, pipelineID); err == nil {
		return
	}
	runner.logger().Warn("pipeline run lock release failed; closing the connection",
		"pipeline", pipelineID)
	_ = connection.Raw(func(any) error { return driver.ErrBadConn })
}

// commitBatch writes the pending records, quarantine, run progress and fetch
// watermark in one transaction.
func (runner *Runner) commitBatch(ctx context.Context, datasetName, runID string, batch runBatch) error {
	err := runner.Database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := runner.Store.WriteBatch(ctx, transaction, datasetName, dataset.Batch{
			RunID:          runID,
			Records:        batch.records,
			Quarantined:    batch.quarantined,
			FetchWatermark: batch.lastFetchTime,
		}); err != nil {
			return fmt.Errorf("write batch: %w", err)
		}
		updates := map[string]any{
			"records_read":                  gorm.Expr("records_read + ?", batch.read()),
			"records_written":               gorm.Expr("records_written + ?", batch.counts.Converted),
			"records_quarantined":           gorm.Expr("records_quarantined + ?", batch.counts.Quarantined),
			"records_unmapped":              gorm.Expr("records_unmapped + ?", batch.counts.Unmapped),
			"records_late_beyond_retention": gorm.Expr("records_late_beyond_retention + ?", batch.counts.LateBeyondRetention),
			"batches_committed":             gorm.Expr("batches_committed + 1"),
		}
		if err := transaction.Model(&runRow{}).Where("id = ?", runID).Updates(updates).Error; err != nil {
			return fmt.Errorf("record batch progress: %w", err)
		}
		return nil
	})
	return err
}

// commitWatermark advances the dataset watermark through an empty batch.
func (runner *Runner) commitWatermark(ctx context.Context, datasetName, runID string, watermark time.Time) error {
	err := runner.Database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		return runner.Store.WriteBatch(ctx, transaction, datasetName, dataset.Batch{
			RunID:          runID,
			FetchWatermark: watermark,
		})
	})
	if err != nil {
		return fmt.Errorf("advance the fetch watermark: %w", err)
	}
	return nil
}

// fetchWatermark reads the dataset's fetch watermark after the run, on a
// context that survives the run ending.
func (runner *Runner) fetchWatermark(ctx context.Context, datasetName string) (time.Time, error) {
	readContext, cancel := detach(ctx)
	defer cancel()
	watermark, err := runner.Store.Watermark(readContext, datasetName)
	return watermark.FetchWatermark, err
}

// expireDataset drops data beyond retention. A failure is a warning, not a run
// failure: the batch commits stand.
func (runner *Runner) expireDataset(ctx context.Context, datasetName string, now time.Time, result *RunResult) {
	expireContext, cancel := detach(ctx)
	defer cancel()

	err := runner.Database.WithContext(expireContext).Transaction(func(transaction *gorm.DB) error {
		return runner.Store.Expire(expireContext, transaction, datasetName, now)
	})
	if err != nil {
		runner.logger().Error("pipeline run: expire dataset", "dataset", datasetName, "error", err)
		result.Warnings = append(result.Warnings, "EXPIRE_FAILED: "+sanitizedError(err))
	}
}

// finishRun records the final status, counters, errors and finish time on a
// fresh context so a canceled or timed-out run still lands.
func (runner *Runner) finishRun(ctx context.Context, result RunResult, fetchFailures []fetchErrorRow, renderedQueryHash string) error {
	finishContext, cancel := detach(ctx)
	defer cancel()

	warnings, err := json.Marshal(result.Warnings)
	if err != nil {
		return fmt.Errorf("encode run warnings: %w", err)
	}
	if fetchFailures == nil {
		fetchFailures = []fetchErrorRow{}
	}
	failures, err := json.Marshal(fetchFailures)
	if err != nil {
		return fmt.Errorf("encode fetch errors: %w", err)
	}

	updates := map[string]any{
		"status":                        string(result.Status),
		"records_read":                  result.RecordsRead,
		"records_written":               result.RecordsWritten,
		"records_quarantined":           result.RecordsQuarantined,
		"records_unmapped":              result.RecordsUnmapped,
		"records_late_beyond_retention": result.RecordsLate,
		"truncated":                     result.Truncated,
		"fetch_errors":                  gorm.Expr("?::jsonb", string(failures)),
		"warnings":                      gorm.Expr("?::jsonb", string(warnings)),
		"error":                         optionalText(result.Error),
		"finished_at":                   gorm.Expr("now()"),
	}
	if renderedQueryHash != "" {
		updates["rendered_query_hash"] = renderedQueryHash
	}
	err = runner.Database.WithContext(finishContext).Model(&runRow{}).
		Where("id = ?", result.RunID).Updates(updates).Error
	if err != nil {
		return fmt.Errorf("finish run %s: %w", result.RunID, err)
	}
	return nil
}

// computeWindow returns the fetch-time window for one run and the backlog
// beyond max_catch_up that the run skips.
func computeWindow(now time.Time, watermark dataset.Watermark, schedule config.Schedule,
	retention time.Duration, lateness time.Duration, eventTimeSource bool) runWindow {
	window := runWindow{End: now.Add(-time.Duration(schedule.IngestDelay))}

	overlap := time.Duration(schedule.Overlap)
	if eventTimeSource && lateness > overlap {
		overlap = lateness
	}

	if watermark.FetchWatermark.IsZero() {
		lookback := time.Duration(schedule.MaxCatchUp)
		if retention < lookback {
			lookback = retention
		}
		window.Start = window.End.Add(-lookback)
		return window
	}

	maxCatchUp := time.Duration(schedule.MaxCatchUp)
	if window.End.Sub(watermark.FetchWatermark) > maxCatchUp {
		gapEnd := window.End.Add(-maxCatchUp)
		window.Gap = &fetchGap{Start: watermark.FetchWatermark, End: gapEnd}
		window.Start = gapEnd
		return window
	}
	window.Start = watermark.FetchWatermark.Add(-overlap)
	return window
}

func (runner *Runner) pipeline(pipelineID string) (config.Pipeline, bool) {
	for _, pipeline := range runner.Files.Pipelines {
		if pipeline.ID == pipelineID {
			return pipeline, true
		}
	}
	return config.Pipeline{}, false
}

func (runner *Runner) logger() *slog.Logger {
	if runner.Logger != nil {
		return runner.Logger
	}
	return slog.Default()
}

func (runner *Runner) registerDataset(ctx context.Context, transaction *gorm.DB,
	pipeline config.Pipeline, shape phaseOnePipeline, retention, lateness time.Duration) error {
	return runner.Store.RegisterDataset(ctx, transaction, dataset.Dataset{
		Name:            shape.Dataset,
		PipelineID:      pipeline.ID,
		Retention:       retention,
		AllowedLateness: lateness,
	})
}

func mappingPaths(directory string, mappings []string) []string {
	paths := make([]string, len(mappings))
	for index, mapping := range mappings {
		paths[index] = filepath.Join(directory, filepath.FromSlash(mapping))
	}
	return paths
}

func outputDurations(files config.Files, output config.Output) (time.Duration, time.Duration) {
	retention := time.Duration(files.System.Stores.DatasetCache.DefaultRetention)
	if output.Retention != nil {
		retention = time.Duration(*output.Retention)
	}
	lateness := time.Duration(files.System.Stores.DatasetCache.DefaultAllowedLateness)
	if output.AllowedLateness != nil {
		lateness = time.Duration(*output.AllowedLateness)
	}
	return retention, lateness
}

// templateValues turns the step's non-reserved inputs into template values; an
// unresolved variable input stays absent so an optional parameter can unset.
func templateValues(step config.FetcherStep, variables map[string]string) map[string]string {
	values := make(map[string]string, len(step.Inputs))
	for name, input := range step.Inputs {
		if name == "index" || name == "query_template" {
			continue
		}
		if input.Variable != "" {
			value, resolved := variables[input.Variable]
			if resolved {
				values[name] = value
			}
			continue
		}
		values[name] = input.Literal
	}
	return values
}

func fetchErrorRows(failures []fetcher.FetchError) []fetchErrorRow {
	rows := make([]fetchErrorRow, len(failures))
	for index, failure := range failures {
		rows[index] = fetchErrorRow{
			Code:      string(failure.Code),
			Message:   failure.Message,
			Retryable: failure.Retryable,
		}
	}
	return rows
}

func fetchFailureMessage(status fetcher.FetchStatus, fetchErr error) string {
	if fetchErr != nil {
		return sanitizedError(fetchErr)
	}
	if len(status.Errors) > 0 {
		return status.Errors[0].Message
	}
	return "the fetch failed"
}

func sanitizedError(err error) string {
	return strings.ReplaceAll(err.Error(), "\n", " ")
}

func optionalText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// detach returns a context that survives the run ending, bounded by
// finishTimeout. Every run-row write after the lock uses it.
func detach(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
}

// failureStatus is the one place a run's contexts decide its failed outcome: a
// canceled parent is CANCELED, the run deadline is TIMED_OUT, and anything else
// is a plain FAILED the caller fills in with its cause.
func failureStatus(ctx, runContext context.Context, timeout time.Duration) (RunStatus, string) {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return StatusCanceled, "run canceled"
	case errors.Is(runContext.Err(), context.DeadlineExceeded):
		return StatusTimedOut, fmt.Sprintf("run timed out after %s", timeout)
	default:
		return StatusFailed, ""
	}
}
