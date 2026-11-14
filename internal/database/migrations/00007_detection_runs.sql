-- +goose Up
CREATE TABLE detection_runs (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    detection_id text NOT NULL,
    detection_version text NOT NULL,
    status text NOT NULL CHECK (status IN ('OK', 'FAILED', 'TIMED_OUT')),
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL,
    revision int NOT NULL CHECK (revision >= 1),
    rows_read int NOT NULL DEFAULT 0,
    proposals int NOT NULL DEFAULT 0,
    error text,
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (detection_id, window_start, window_end, revision)
);

CREATE TABLE detection_proposals (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    detection_run_id uuid NOT NULL REFERENCES detection_runs(id),
    identity_hash text NOT NULL,
    identity jsonb NOT NULL,
    subject jsonb NOT NULL,
    summary text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}',
    severity text NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
    evidence jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX detection_proposals_run ON detection_proposals (detection_run_id);

-- +goose Down
DROP TABLE detection_proposals;
DROP TABLE detection_runs;
