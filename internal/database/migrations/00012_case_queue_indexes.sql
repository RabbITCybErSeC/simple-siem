-- +goose Up
-- shortcut: plain CREATE INDEX locks cases writes while it builds; fine before
-- the first release on a populated database. A later index on a populated
-- cases table uses CONCURRENTLY with goose's NO TRANSACTION annotation.
CREATE INDEX cases_last_event_idx ON cases (last_event_at DESC, id DESC);
CREATE INDEX cases_created_idx ON cases (created_at, id);

-- +goose Down
DROP INDEX cases_created_idx;
DROP INDEX cases_last_event_idx;
