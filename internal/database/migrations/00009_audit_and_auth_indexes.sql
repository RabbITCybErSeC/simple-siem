-- +goose Up
-- Audit list filters and the auth purge job read these columns; without these
-- indexes each list page and each purge pass scans the whole table. Sessions
-- and reset tokens stay unindexed: the session slide rewrites
-- idle_expires_at about once a minute, and both tables are small.
CREATE INDEX audit_events_event_name_created_at_idx ON audit_events (event_name, created_at DESC);
CREATE INDEX audit_events_event_outcome_created_at_idx ON audit_events (event_outcome, created_at DESC);
CREATE INDEX audit_events_request_id_idx ON audit_events (request_id) WHERE request_id IS NOT NULL;
CREATE INDEX audit_events_trace_id_idx ON audit_events (trace_id) WHERE trace_id IS NOT NULL;
CREATE INDEX login_attempts_created_at_idx ON login_attempts (created_at);

-- +goose Down
DROP INDEX login_attempts_created_at_idx;
DROP INDEX audit_events_trace_id_idx;
DROP INDEX audit_events_request_id_idx;
DROP INDEX audit_events_event_outcome_created_at_idx;
DROP INDEX audit_events_event_name_created_at_idx;
