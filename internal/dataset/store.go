package dataset

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const maxQuarantinePayload = 65536

// datasetNamePattern matches the names the datasets table accepts. The store
// checks it again even though config validated the name, immediately before
// any DDL is formatted.
var datasetNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

func validateDatasetName(name string) error {
	if !datasetNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidDatasetName, name)
	}
	return nil
}

// PostgresStore implements Store on PostgreSQL. Reads use the store's own
// connection; writes take the caller's transaction.
type PostgresStore struct {
	database *gorm.DB
}

// NewPostgresStore returns a store whose reads use database.
func NewPostgresStore(database *gorm.DB) *PostgresStore {
	return &PostgresStore{database: database}
}

// RegisterDataset records the dataset's writing pipeline, retention, and
// allowed lateness, and creates its list partition.
func (store *PostgresStore) RegisterDataset(ctx context.Context, transaction *gorm.DB, dataset Dataset) error {
	if err := validateDatasetName(dataset.Name); err != nil {
		return err
	}
	database := transaction.WithContext(ctx)

	var existing datasetRow
	err := database.Where("name = ?", dataset.Name).Take(&existing).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		row := datasetRow{
			Name:            dataset.Name,
			PipelineID:      dataset.PipelineID,
			Retention:       intervalFromDuration(dataset.Retention),
			AllowedLateness: intervalFromDuration(dataset.AllowedLateness),
			Version:         1,
		}
		if err := database.Create(&row).Error; err != nil {
			return fmt.Errorf("register dataset %q: %w", dataset.Name, err)
		}
	case err != nil:
		return fmt.Errorf("read dataset %q: %w", dataset.Name, err)
	case existing.PipelineID != dataset.PipelineID:
		return fmt.Errorf("%w: dataset %q is written by pipeline %q, not %q",
			ErrDatasetOwned, dataset.Name, existing.PipelineID, dataset.PipelineID)
	default:
		updates := map[string]any{
			"retention":        intervalFromDuration(dataset.Retention),
			"allowed_lateness": intervalFromDuration(dataset.AllowedLateness),
			"updated_at":       gorm.Expr("now()"),
			"version":          gorm.Expr("version + 1"),
		}
		if err := database.Model(&datasetRow{}).
			Where("name = ?", dataset.Name).
			Updates(updates).Error; err != nil {
			return fmt.Errorf("update dataset %q: %w", dataset.Name, err)
		}
	}

	if err := createListPartition(database, dataset.Name); err != nil {
		return err
	}
	return nil
}

// WriteBatch upserts the records by source key, stores the quarantined
// records, and advances the watermarks, all in the caller's transaction.
func (store *PostgresStore) WriteBatch(ctx context.Context, transaction *gorm.DB, datasetName string, batch Batch) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	database := transaction.WithContext(ctx)
	if err := lockDataset(database, datasetName); err != nil {
		return err
	}
	dataset, err := loadDataset(database, datasetName)
	if err != nil {
		return err
	}

	var now time.Time
	if err := database.Raw("SELECT now()").Scan(&now).Error; err != nil {
		return fmt.Errorf("read database clock: %w", err)
	}
	if err := checkRetention(batch.Records, now, durationFromInterval(dataset.Retention)); err != nil {
		return err
	}

	if err := createDayPartitions(database, datasetName, batch.Records); err != nil {
		return err
	}
	if len(batch.Records) > 0 {
		rows := make([]eventRow, len(batch.Records))
		for index, record := range batch.Records {
			rows[index] = eventRowFromRecord(datasetName, record, now)
		}
		err := database.Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "dataset"}, {Name: "event_time"}, {Name: "source_key_hash"},
			},
			DoUpdates: clause.AssignmentColumns([]string{
				"event", "event_type", "target_user", "target_host",
				"principal_ip", "pipeline_run_id", "written_at",
			}),
		}).CreateInBatches(&rows, 1000).Error
		if err != nil {
			return fmt.Errorf("write dataset %q records: %w", datasetName, err)
		}
	}

	if len(batch.Quarantined) > 0 {
		rows := make([]quarantineRow, len(batch.Quarantined))
		for index, record := range batch.Quarantined {
			rows[index] = quarantineRowFromRecord(datasetName, batch.RunID, record)
		}
		if err := database.CreateInBatches(&rows, 1000).Error; err != nil {
			return fmt.Errorf("write dataset %q quarantine: %w", datasetName, err)
		}
	}

	if err := advanceWatermark(database, datasetName, batch); err != nil {
		return err
	}
	return nil
}

// lockDataset serializes partition DDL and watermark updates for one dataset
// without blocking other datasets.
func lockDataset(database *gorm.DB, datasetName string) error {
	err := database.Exec(
		"SELECT pg_advisory_xact_lock(hashtextextended('dataset:' || ?, 0))",
		datasetName,
	).Error
	if err != nil {
		return fmt.Errorf("lock dataset %q: %w", datasetName, err)
	}
	return nil
}

func loadDataset(database *gorm.DB, datasetName string) (datasetRow, error) {
	var row datasetRow
	err := database.Where("name = ?", datasetName).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return datasetRow{}, fmt.Errorf("%w: %q", ErrUnknownDataset, datasetName)
	}
	if err != nil {
		return datasetRow{}, fmt.Errorf("read dataset %q: %w", datasetName, err)
	}
	return row, nil
}

func intervalFromDuration(duration time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: duration.Microseconds(), Valid: true}
}

func durationFromInterval(interval pgtype.Interval) time.Duration {
	return time.Duration(interval.Microseconds)*time.Microsecond +
		time.Duration(interval.Days)*24*time.Hour
}

func checkRetention(records []Record, now time.Time, retention time.Duration) error {
	earliest := now.Add(-retention - 24*time.Hour)
	latest := now.Add(24 * time.Hour)
	for _, record := range records {
		if record.EventTime.After(latest) || record.EventTime.Before(earliest) {
			return fmt.Errorf("%w: record %q at %s", ErrOutsideRetention, record.Key.DocumentID, record.EventTime)
		}
	}
	return nil
}

func eventRowFromRecord(datasetName string, record Record, writtenAt time.Time) eventRow {
	row := eventRow{
		Dataset:           datasetName,
		EventTime:         record.EventTime,
		SourceKeyHash:     record.Key.Hash(),
		FetcherInstanceID: record.Key.FetcherInstanceID,
		SourceIndex:       record.Key.Index,
		DocumentID:        record.Key.DocumentID,
		EventType:         string(record.Event.Metadata.EventType),
		TargetUser:        nullableString(record.Event.Target.User.UserID),
		TargetHost:        nullableString(record.Event.Target.Hostname),
		Event:             record.Event,
		PipelineRunID:     record.RunID,
		WrittenAt:         writtenAt,
	}
	if len(record.Event.Principal.IP) > 0 {
		row.PrincipalIP = nullableString(record.Event.Principal.IP[0])
	}
	return row
}

func quarantineRowFromRecord(datasetName, runID string, record QuarantinedRecord) quarantineRow {
	payload := record.Payload
	truncated := false
	if len(payload) > maxQuarantinePayload {
		payload = payload[:maxQuarantinePayload]
		truncated = true
	}
	problems := make([]validationErrorRow, len(record.Errors))
	for index, problem := range record.Errors {
		problems[index] = validationErrorRow{Path: problem.Path, Message: problem.Message}
	}
	return quarantineRow{
		Dataset:           datasetName,
		FetcherInstanceID: record.Key.FetcherInstanceID,
		SourceIndex:       record.Key.Index,
		DocumentID:        record.Key.DocumentID,
		Payload:           payload,
		PayloadTruncated:  truncated,
		MappingID:         nullableString(record.MappingID),
		MappingVersion:    nullableInt(record.MappingVersion),
		Errors:            problems,
		PipelineRunID:     runID,
	}
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func nullableInt(value int) *int {
	if value == 0 {
		return nil
	}
	return &value
}

// createDayPartitions creates the UTC day partitions the batch needs. The
// name is checked again right before the DDL is formatted.
func createDayPartitions(transaction *gorm.DB, datasetName string, records []Record) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	days := make(map[time.Time]struct{}, len(records))
	for _, record := range records {
		days[utcDay(record.EventTime)] = struct{}{}
	}
	ordered := make([]time.Time, 0, len(days))
	for day := range days {
		ordered = append(ordered, day)
	}
	slices.SortFunc(ordered, func(left, right time.Time) int { return left.Compare(right) })

	listPartition := "ds_" + datasetName
	for _, day := range ordered {
		partitionName := listPartition + "_" + day.Format("20060102")
		exists, err := partitionExists(transaction, partitionName, listPartition)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		statement := fmt.Sprintf(
			`CREATE TABLE "%s" PARTITION OF "%s" FOR VALUES FROM ('%s') TO ('%s')`,
			partitionName,
			listPartition,
			day.Format("2006-01-02"),
			day.Add(24*time.Hour).Format("2006-01-02"),
		)
		if err := transaction.Exec(statement).Error; err != nil {
			return fmt.Errorf("create partition %q: %w", partitionName, err)
		}
	}
	return nil
}

func utcDay(value time.Time) time.Time {
	utc := value.UTC()
	return time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
}

// advanceWatermark moves the fetch watermark forward, never backwards, and
// keeps the dataset watermark at the fetch watermark minus allowed lateness.
func advanceWatermark(database *gorm.DB, datasetName string, batch Batch) error {
	if batch.FetchWatermark.IsZero() {
		err := database.Model(&datasetRow{}).
			Where("name = ?", datasetName).
			Updates(map[string]any{
				"last_run_id": batch.RunID,
				"updated_at":  gorm.Expr("now()"),
				"version":     gorm.Expr("version + 1"),
			}).Error
		if err != nil {
			return fmt.Errorf("record dataset %q run: %w", datasetName, err)
		}
		return nil
	}
	err := database.Exec(`
		UPDATE datasets
		SET fetch_watermark = GREATEST(fetch_watermark, ?),
		    dataset_watermark = GREATEST(fetch_watermark, ?) - allowed_lateness,
		    last_run_id = ?, updated_at = now(), version = version + 1
		WHERE name = ?`,
		batch.FetchWatermark, batch.FetchWatermark, batch.RunID, datasetName).Error
	if err != nil {
		return fmt.Errorf("advance watermarks of dataset %q: %w", datasetName, err)
	}
	return nil
}

// ReadWindow streams records in [start, end) ordered by (event time, source
// key hash), one page query at a time.
func (store *PostgresStore) ReadWindow(ctx context.Context, datasetName string, start, end time.Time, filter Filter) iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		if err := validateDatasetName(datasetName); err != nil {
			yield(Record{}, err)
			return
		}
		if !start.Before(end) {
			return
		}
		database := store.database.WithContext(ctx)
		if _, err := loadDataset(database, datasetName); err != nil {
			yield(Record{}, err)
			return
		}

		eventTypes := make([]string, len(filter.EventTypes))
		for index, eventType := range filter.EventTypes {
			eventTypes[index] = string(eventType)
		}

		var cursorTime time.Time
		var cursorHash []byte
		firstPage := true
		for {
			if err := ctx.Err(); err != nil {
				yield(Record{}, err)
				return
			}
			query := database.Model(&eventRow{}).
				Where("dataset = ? AND event_time >= ? AND event_time < ?", datasetName, start, end)
			if len(eventTypes) > 0 {
				query = query.Where("event_type IN ?", eventTypes)
			}
			if !firstPage {
				query = query.Where("(event_time, source_key_hash) > (?, ?)", cursorTime, cursorHash)
			}
			var rows []eventRow
			err := query.Order("event_time, source_key_hash").Limit(1000).Find(&rows).Error
			if err != nil {
				if contextError := ctx.Err(); contextError != nil {
					yield(Record{}, contextError)
				} else {
					yield(Record{}, err)
				}
				return
			}
			for _, row := range rows {
				if !yield(row.record(), nil) {
					return
				}
			}
			if len(rows) < 1000 {
				return
			}
			last := rows[len(rows)-1]
			cursorTime = last.EventTime
			cursorHash = last.SourceKeyHash
			firstPage = false
		}
	}
}

func (row eventRow) record() Record {
	return Record{
		Key: SourceKey{
			FetcherInstanceID: row.FetcherInstanceID,
			Index:             row.SourceIndex,
			DocumentID:        row.DocumentID,
		},
		EventTime: row.EventTime,
		Event:     row.Event,
		RunID:     row.PipelineRunID,
	}
}

// Watermark returns the dataset's watermarks; zero times before the first
// batch.
func (store *PostgresStore) Watermark(ctx context.Context, datasetName string) (Watermark, error) {
	row, err := loadDataset(store.database.WithContext(ctx), datasetName)
	if err != nil {
		return Watermark{}, err
	}
	watermark := Watermark{UpdatedAt: row.UpdatedAt}
	if row.FetchWatermark != nil {
		watermark.FetchWatermark = *row.FetchWatermark
	}
	if row.DatasetWatermark != nil {
		watermark.DatasetWatermark = *row.DatasetWatermark
	}
	if row.LastRunID != nil {
		watermark.LastRunID = *row.LastRunID
	}
	return watermark, nil
}

// Expire drops the day partitions that ended at or before now minus the
// dataset's retention, and deletes quarantine rows older than that.
func (store *PostgresStore) Expire(ctx context.Context, transaction *gorm.DB, datasetName string, now time.Time) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	database := transaction.WithContext(ctx)
	if err := lockDataset(database, datasetName); err != nil {
		return err
	}
	dataset, err := loadDataset(database, datasetName)
	if err != nil {
		return err
	}
	cutoff := now.Add(-durationFromInterval(dataset.Retention))
	if err := dropExpiredDayPartitions(database, datasetName, cutoff); err != nil {
		return err
	}
	err = database.Exec(
		"DELETE FROM dataset_quarantine WHERE dataset = ? AND created_at < ?",
		datasetName, cutoff,
	).Error
	if err != nil {
		return fmt.Errorf("delete expired quarantine of dataset %q: %w", datasetName, err)
	}
	return nil
}

// dropExpiredDayPartitions derives each day partition's upper bound from its
// name, which only this package writes: ds_<dataset>_<yyyymmdd>.
func dropExpiredDayPartitions(transaction *gorm.DB, datasetName string, cutoff time.Time) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	var children []string
	err := transaction.Raw(`
		SELECT child.relname
		FROM pg_inherits
		JOIN pg_class AS child ON child.oid = pg_inherits.inhrelid
		WHERE pg_inherits.inhparent = to_regclass(?)`, "ds_"+datasetName).Scan(&children).Error
	if err != nil {
		return fmt.Errorf("list partitions of dataset %q: %w", datasetName, err)
	}

	prefix := "ds_" + datasetName + "_"
	for _, partitionName := range children {
		dayText, found := strings.CutPrefix(partitionName, prefix)
		if !found || len(dayText) != 8 {
			continue
		}
		day, err := time.Parse("20060102", dayText)
		if err != nil {
			continue
		}
		if day.Add(24 * time.Hour).After(cutoff) {
			continue
		}
		statement := fmt.Sprintf(`DROP TABLE "%s"`, partitionName)
		if err := transaction.Exec(statement).Error; err != nil {
			return fmt.Errorf("drop partition %q: %w", partitionName, err)
		}
	}
	return nil
}

// partitionExists reports whether relationName is a partition of parentName.
func partitionExists(transaction *gorm.DB, relationName, parentName string) (bool, error) {
	var exists bool
	err := transaction.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM pg_inherits
			WHERE inhrelid = to_regclass(?) AND inhparent = to_regclass(?)
		)`, relationName, parentName).Scan(&exists).Error
	if err != nil {
		return false, fmt.Errorf("look up partition %q: %w", relationName, err)
	}
	return exists, nil
}

// createListPartition creates ds_<name> under dataset_events when it is
// missing. It validates the name itself, so every fmt.Sprintf below runs
// only on a name that matches the dataset pattern.
func createListPartition(transaction *gorm.DB, datasetName string) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	partitionName := "ds_" + datasetName

	exists, err := partitionExists(transaction, partitionName, "dataset_events")
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	statement := fmt.Sprintf(
		`CREATE TABLE "%s" PARTITION OF "dataset_events" FOR VALUES IN ('%s') PARTITION BY RANGE (event_time)`,
		partitionName, datasetName,
	)
	if err := transaction.Exec(statement).Error; err != nil {
		return fmt.Errorf("create partition %q: %w", partitionName, err)
	}
	return nil
}
