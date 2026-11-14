-- +goose Up
CREATE TABLE event_outbox (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    type text NOT NULL,
    version integer NOT NULL CHECK (version >= 1),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor jsonb NOT NULL CHECK (jsonb_typeof(actor) = 'object'),
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    dispatched_at timestamptz
);
CREATE INDEX event_outbox_undispatched_idx ON event_outbox (occurred_at)
    WHERE dispatched_at IS NULL;

-- +goose Down
DROP TABLE event_outbox;
