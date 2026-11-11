-- +goose Up
CREATE TABLE audit_events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    event_name text NOT NULL,
    event_category text NOT NULL,
    event_outcome text NOT NULL CHECK (event_outcome IN (
        'SUCCESS',
        'DENIED',
        'VALIDATION_FAILED',
        'FAILED',
        'PARTIAL',
        'CANCELED',
        'SKIPPED'
    )),
    actor_type text NOT NULL,
    actor_id text,
    request_id text,
    trace_id text,
    source_ip inet,
    target_type text NOT NULL,
    target_id text NOT NULL,
    action text NOT NULL,
    changes jsonb,
    redactions jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_events_created_at_idx ON audit_events (created_at);
CREATE INDEX audit_events_target_idx ON audit_events (target_type, target_id, created_at);

-- +goose Down
DROP TABLE audit_events;
