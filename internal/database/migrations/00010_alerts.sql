-- +goose Up
CREATE TABLE detection_runtime (
    detection_id text PRIMARY KEY,
    status text NOT NULL CHECK (status IN ('ENABLED','SHADOW','DISABLED','AUTO_DISABLED','MISSING')),
    reason text,
    changed_at timestamptz NOT NULL DEFAULT now(),
    version int NOT NULL DEFAULT 1
);

CREATE TABLE alerts (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    detection_id text NOT NULL,
    detection_version text NOT NULL,
    identity_hash text NOT NULL,
    identity_schema_version int NOT NULL,
    identity jsonb NOT NULL,
    subject jsonb NOT NULL,
    summary text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}',
    severity text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH')),
    status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','CLOSED')),
    coalescing boolean NOT NULL DEFAULT true,
    first_event_at timestamptz NOT NULL,
    last_event_at timestamptz NOT NULL CHECK (last_event_at >= first_event_at),
    occurrence_count int NOT NULL DEFAULT 1 CHECK (occurrence_count >= 1),
    evidence_count int NOT NULL CHECK (evidence_count >= 1),
    previous_alert_id uuid REFERENCES alerts(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version int NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX alerts_open_identity ON alerts (detection_id, identity_hash)
    WHERE status = 'OPEN' AND coalescing;
CREATE INDEX alerts_identity_recent ON alerts (detection_id, identity_hash, last_event_at DESC);

CREATE TABLE alert_evidence (
    alert_id uuid NOT NULL REFERENCES alerts(id),
    source_key_hash bytea NOT NULL,
    fetcher_instance_id text NOT NULL,
    source_index text NOT NULL,
    document_id text NOT NULL,
    event_time timestamptz NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (alert_id, source_key_hash)
);
CREATE INDEX alert_evidence_source ON alert_evidence (source_key_hash);

CREATE TABLE alert_occurrences (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    alert_id uuid NOT NULL REFERENCES alerts(id),
    detection_run_id uuid NOT NULL REFERENCES detection_runs(id),
    new_evidence_count int NOT NULL CHECK (new_evidence_count > 0),
    first_event_at timestamptz NOT NULL,
    last_event_at timestamptz NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX alert_occurrences_alert ON alert_occurrences (alert_id, observed_at);

ALTER TABLE detection_runs
    ADD COLUMN mode text NOT NULL DEFAULT 'SHADOW' CHECK (mode IN ('ENABLED','SHADOW')),
    ADD COLUMN alerts_created int NOT NULL DEFAULT 0,
    ADD COLUMN alerts_merged int NOT NULL DEFAULT 0,
    ADD COLUMN proposals_deduplicated int NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE detection_runs
    DROP COLUMN proposals_deduplicated,
    DROP COLUMN alerts_merged,
    DROP COLUMN alerts_created,
    DROP COLUMN mode;
DROP TABLE alert_occurrences;
DROP TABLE alert_evidence;
DROP TABLE alerts;
DROP TABLE detection_runtime;
