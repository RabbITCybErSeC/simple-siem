-- +goose Up
CREATE TABLE pipeline_runs (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    pipeline_id text NOT NULL,
    dataset text NOT NULL REFERENCES datasets(name),
    status text NOT NULL CHECK (status IN ('RUNNING', 'OK', 'PARTIAL', 'FAILED', 'TIMED_OUT', 'CANCELED', 'SKIPPED')),
    window_start timestamptz, window_end timestamptz,
    gap_start timestamptz, gap_end timestamptz,
    records_read int NOT NULL DEFAULT 0,
    records_written int NOT NULL DEFAULT 0,
    records_quarantined int NOT NULL DEFAULT 0,
    records_unmapped int NOT NULL DEFAULT 0,
    records_late_beyond_retention int NOT NULL DEFAULT 0,
    batches_committed int NOT NULL DEFAULT 0,
    truncated boolean NOT NULL DEFAULT false,
    rendered_query_hash text,
    fetch_errors jsonb NOT NULL DEFAULT '[]',
    warnings jsonb NOT NULL DEFAULT '[]',
    error text,
    started_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    version int NOT NULL DEFAULT 1
);
CREATE INDEX pipeline_runs_pipeline_started ON pipeline_runs (pipeline_id, started_at DESC);

-- +goose Down
DROP TABLE pipeline_runs;
