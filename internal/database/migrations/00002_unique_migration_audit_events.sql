-- +goose Up
CREATE UNIQUE INDEX audit_events_migration_applied_idx
    ON audit_events (target_id)
    WHERE event_name = 'simple_siem.database.migration_applied';

-- +goose Down
DROP INDEX audit_events_migration_applied_idx;
