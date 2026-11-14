-- +goose Up
CREATE TABLE datasets (
    name text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_]{0,39}$'),
    pipeline_id text NOT NULL,
    retention interval NOT NULL CHECK (retention > interval '0'),
    allowed_lateness interval NOT NULL CHECK (allowed_lateness >= interval '0'),
    fetch_watermark timestamptz,
    dataset_watermark timestamptz,
    last_run_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version int NOT NULL DEFAULT 1
);

CREATE TABLE dataset_events (
    dataset text NOT NULL REFERENCES datasets(name),
    event_time timestamptz NOT NULL,
    source_key_hash bytea NOT NULL,
    fetcher_instance_id text NOT NULL,
    source_index text NOT NULL,
    document_id text NOT NULL,
    event_type text NOT NULL,
    target_user text, target_host text, principal_ip text,
    event jsonb NOT NULL,
    pipeline_run_id text NOT NULL,
    written_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (dataset, event_time, source_key_hash)
) PARTITION BY LIST (dataset);

CREATE TABLE dataset_quarantine (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    dataset text NOT NULL REFERENCES datasets(name),
    source_key_hash bytea NOT NULL,
    fetcher_instance_id text NOT NULL, source_index text NOT NULL, document_id text NOT NULL,
    payload bytea NOT NULL,
    payload_truncated boolean NOT NULL,
    mapping_id text, mapping_version int,
    errors jsonb NOT NULL,
    pipeline_run_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX dataset_quarantine_dataset_source_key
    ON dataset_quarantine (dataset, source_key_hash);
CREATE INDEX dataset_quarantine_dataset_created ON dataset_quarantine (dataset, created_at);

-- +goose Down
DROP TABLE dataset_quarantine;
DROP TABLE dataset_events;
DROP TABLE datasets;
