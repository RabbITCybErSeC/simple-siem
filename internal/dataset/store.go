package dataset

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"gorm.io/gorm"
)

// datasetNamePattern matches the names the datasets table accepts. The store
// checks it again even though config validated the name, immediately before
// any DDL is formatted.
var datasetNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// PostgresStore implements Store on PostgreSQL.
type PostgresStore struct{}

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

func validateDatasetName(name string) error {
	if !datasetNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidDatasetName, name)
	}
	return nil
}

func intervalFromDuration(duration time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: duration.Microseconds(), Valid: true}
}

// createListPartition creates ds_<name> under dataset_events when it is
// missing. It validates the name itself, so every fmt.Sprintf below runs
// only on a name that matches the dataset pattern.
func createListPartition(transaction *gorm.DB, datasetName string) error {
	if err := validateDatasetName(datasetName); err != nil {
		return err
	}
	partitionName := "ds_" + datasetName

	var exists bool
	err := transaction.Raw(`
		SELECT EXISTS (
			SELECT 1 FROM pg_inherits
			WHERE inhrelid = to_regclass(?) AND inhparent = to_regclass('dataset_events')
		)`, partitionName).Scan(&exists).Error
	if err != nil {
		return fmt.Errorf("look up partition %q: %w", partitionName, err)
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
