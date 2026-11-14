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

const (
	maxQuarantinePayload = 65536
	// partitionBoundLayout always carries an explicit offset, so a session
	// time zone can never shift a partition's bounds.
	partitionBoundLayout = "2006-01-02 15:04:05-07:00"
)

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
// allowed lateness, and creates its list partition. The advisory lock comes
// first so two registrations of one dataset cannot race the insert and the
// partition DDL.
func (store *PostgresStore) RegisterDataset(ctx context.Context, transaction *gorm.DB, dataset Dataset) error {
	if err := validateDatasetName(dataset.Name); err != nil {
		return err
	}
	database := transaction.WithContext(ctx)
	if err := lockDataset(database, dataset.Name); err != nil {
		return err
	}

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
// records, and advances the watermarks, all in the caller's transaction. The
// day partition DDL runs in its own short transaction before the caller's
// write.
func (store *PostgresStore) WriteBatch(ctx context.Context, transaction *gorm.DB, datasetName string, batch Batch) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	database := transaction.WithContext(ctx)
	stored, now, err := loadDatasetWithClock(database, datasetName)
	if err != nil {
		return err
	}
	retention, err := datasetDurations(stored)
	if err != nil {
		return fmt.Errorf("dataset %q: %w", datasetName, err)
	}
	if err := checkRetention(batch.Records, now, retention); err != nil {
		return err
	}

	// The caller's transaction may stay open for the rest of the run. Commit
	// the day partitions first so the ACCESS EXCLUSIVE lock of PARTITION OF is
	// not held against every reader until that transaction ends. An empty
	// early partition is harmless.
	if err := store.ensureDayPartitions(ctx, datasetName, batch.Records); err != nil {
		return err
	}
	if err := lockDataset(database, datasetName); err != nil {
		return err
	}

	if len(batch.Records) > 0 {
		records := lastRecordPerKey(batch.Records)
		rows := make([]eventRow, len(records))
		for index, record := range records {
			rows[index] = eventRowFromRecord(datasetName, record, now)
		}
		// shortcut: dataset writes go through GORM batch upserts; switch this store to pgx CopyFrom if the smoke budget misses.
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
		err := database.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "dataset"}, {Name: "source_key_hash"}},
			DoUpdates: append(
				clause.AssignmentColumns([]string{
					"payload", "payload_truncated", "mapping_id", "mapping_version",
					"errors", "pipeline_run_id",
				}),
				clause.Assignment{Column: clause.Column{Name: "created_at"}, Value: gorm.Expr("now()")},
			),
		}).CreateInBatches(&rows, 1000).Error
		if err != nil {
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

// loadDatasetWithClock reads the dataset row and takes the database clock in
// the same statement, one round trip instead of two.
func loadDatasetWithClock(database *gorm.DB, datasetName string) (datasetRow, time.Time, error) {
	var loaded datasetLoad
	err := database.Table("datasets").
		Select("datasets.*, now() AS database_now").
		Where("datasets.name = ?", datasetName).
		Take(&loaded).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return datasetRow{}, time.Time{}, fmt.Errorf("%w: %q", ErrUnknownDataset, datasetName)
	case err != nil:
		return datasetRow{}, time.Time{}, fmt.Errorf("read dataset %q: %w", datasetName, err)
	}
	return loaded.Dataset, loaded.DatabaseNow, nil
}

// datasetDurations returns the retention a write must respect. It also refuses
// month-based lateness so both stored intervals stay convertible.
func datasetDurations(row datasetRow) (time.Duration, error) {
	retention, err := durationFromInterval(row.Retention)
	if err != nil {
		return 0, fmt.Errorf("retention: %w", err)
	}
	if _, err := durationFromInterval(row.AllowedLateness); err != nil {
		return 0, fmt.Errorf("allowed lateness: %w", err)
	}
	return retention, nil
}

func intervalFromDuration(duration time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: duration.Microseconds(), Valid: true}
}

// durationFromInterval converts a stored interval. Months have no fixed
// duration, so an interval with a month part is refused instead of being read
// as zero.
func durationFromInterval(interval pgtype.Interval) (time.Duration, error) {
	if interval.Months != 0 {
		return 0, fmt.Errorf("%w: interval has a month part", ErrInvalidRetention)
	}
	return time.Duration(interval.Microseconds)*time.Microsecond +
		time.Duration(interval.Days)*24*time.Hour, nil
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
		SourceKeyHash:     record.Key.Hash(),
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

// recordKey is the upsert conflict key inside one batch. Event times are
// compared at PostgreSQL's microsecond resolution so two times that the column
// stores as one value also dedupe as one value.
type recordKey struct {
	eventTime int64
	hash      string
}

// lastRecordPerKey keeps the last record per (event time, source key hash) in
// input order. PostgreSQL refuses an upsert that would touch one row twice.
func lastRecordPerKey(records []Record) []Record {
	seen := make(map[recordKey]struct{}, len(records))
	kept := make([]Record, 0, len(records))
	for index := len(records) - 1; index >= 0; index-- {
		record := records[index]
		key := recordKey{
			eventTime: record.EventTime.UTC().Truncate(time.Microsecond).UnixNano(),
			hash:      string(record.Key.Hash()),
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		kept = append(kept, record)
	}
	slices.Reverse(kept)
	return kept
}

// ensureDayPartitions creates the UTC day partitions the batch needs in a
// short transaction on the store's own connection.
func (store *PostgresStore) ensureDayPartitions(ctx context.Context, datasetName string, records []Record) error {
	days := make(map[time.Time]struct{}, len(records))
	for _, record := range records {
		days[utcDay(record.EventTime)] = struct{}{}
	}
	if len(days) == 0 {
		return nil
	}
	ordered := make([]time.Time, 0, len(days))
	for day := range days {
		ordered = append(ordered, day)
	}
	slices.SortFunc(ordered, func(left, right time.Time) int { return left.Compare(right) })

	database := store.database.WithContext(ctx)
	return database.Transaction(func(transaction *gorm.DB) error {
		if err := lockDataset(transaction, datasetName); err != nil {
			return err
		}
		return createMissingDayPartitions(transaction, datasetName, ordered)
	})
}

// createMissingDayPartitions creates the day partitions among ordered that do
// not exist yet. The name is checked again right before the DDL is formatted.
func createMissingDayPartitions(transaction *gorm.DB, datasetName string, ordered []time.Time) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	existing, err := listDayPartitionNames(transaction, datasetName)
	if err != nil {
		return err
	}
	for _, day := range ordered {
		partitionName := dayPartitionName(datasetName, day)
		if _, present := existing[partitionName]; present {
			continue
		}
		statement := fmt.Sprintf(
			`CREATE TABLE "%s" PARTITION OF "%s" FOR VALUES FROM ('%s') TO ('%s')`,
			partitionName,
			listPartitionName(datasetName),
			day.Format(partitionBoundLayout),
			day.Add(24*time.Hour).Format(partitionBoundLayout),
		)
		if err := transaction.Exec(statement).Error; err != nil {
			return fmt.Errorf("create partition %q: %w", partitionName, err)
		}
	}
	return nil
}

// listDayPartitionNames reads every child of the dataset's list partition with
// one catalog query.
func listDayPartitionNames(transaction *gorm.DB, datasetName string) (map[string]struct{}, error) {
	var names []string
	err := transaction.Raw(`
		SELECT child.relname
		FROM pg_inherits
		JOIN pg_class AS child ON child.oid = pg_inherits.inhrelid
		WHERE pg_inherits.inhparent = to_regclass(?)`, listPartitionName(datasetName)).Scan(&names).Error
	if err != nil {
		return nil, fmt.Errorf("list partitions of dataset %q: %w", datasetName, err)
	}
	existing := make(map[string]struct{}, len(names))
	for _, name := range names {
		existing[name] = struct{}{}
	}
	return existing, nil
}

func utcDay(value time.Time) time.Time {
	utc := value.UTC()
	return time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
}

func listPartitionName(datasetName string) string {
	return "dsl_" + datasetName
}

func dayPartitionName(datasetName string, day time.Time) string {
	return "dsd_" + datasetName + "_" + day.Format("20060102")
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
// dataset's retention, and deletes quarantine rows older than that. The DROP
// stays in the caller's transaction: the runner calls Expire in a short
// transaction of its own, so the locks are not held while it writes a batch.
func (store *PostgresStore) Expire(ctx context.Context, transaction *gorm.DB, datasetName string, now time.Time) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	database := transaction.WithContext(ctx)
	if err := lockDataset(database, datasetName); err != nil {
		return err
	}
	stored, err := loadDataset(database, datasetName)
	if err != nil {
		return err
	}
	retention, err := datasetDurations(stored)
	if err != nil {
		return fmt.Errorf("dataset %q: %w", datasetName, err)
	}
	cutoff := now.Add(-retention)
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
// name, which only this package writes: dsd_<dataset>_<yyyymmdd>.
func dropExpiredDayPartitions(transaction *gorm.DB, datasetName string, cutoff time.Time) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	partitions, err := listDayPartitionNames(transaction, datasetName)
	if err != nil {
		return err
	}

	prefix := "dsd_" + datasetName + "_"
	for partitionName := range partitions {
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

// createListPartition creates dsl_<name> under dataset_events when it is
// missing. It validates the name itself, so every fmt.Sprintf below runs
// only on a name that matches the dataset pattern.
func createListPartition(transaction *gorm.DB, datasetName string) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	partitionName := listPartitionName(datasetName)

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
