-- +goose Up
CREATE SEQUENCE case_number_seq;

CREATE TABLE cases (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    case_number bigint NOT NULL UNIQUE DEFAULT nextval('case_number_seq'),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 500),
    status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','IN_PROGRESS','CLOSED')),
    severity text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH')),
    detection_id text NOT NULL,
    assignee_user_id uuid REFERENCES users(id),
    outcome text CHECK (outcome IN ('MALICIOUS','ACCEPTED')),
    closure_reason text,
    conclusion text,
    first_event_at timestamptz NOT NULL,
    last_event_at timestamptz NOT NULL,
    last_activity_at timestamptz NOT NULL DEFAULT now(),
    previous_case_id uuid REFERENCES cases(id),
    merged_into uuid REFERENCES cases(id),
    closed_at timestamptz,
    closed_by uuid REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1
);
CREATE INDEX cases_queue_last_event_idx ON cases (status, last_event_at DESC, id DESC);
CREATE INDEX cases_queue_created_idx ON cases (status, created_at, id);
CREATE INDEX cases_assignee_idx ON cases (assignee_user_id, status);
CREATE INDEX cases_title_prefix_idx ON cases (lower(title) text_pattern_ops);

CREATE TABLE case_alerts (
    case_id uuid NOT NULL REFERENCES cases(id),
    alert_id uuid NOT NULL UNIQUE REFERENCES alerts(id),
    outcome text,
    closure_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, alert_id)
);

CREATE TABLE detection_guardrails (
    detection_id text NOT NULL,
    hour_bucket timestamptz NOT NULL,
    cases_opened integer NOT NULL DEFAULT 0,
    PRIMARY KEY (detection_id, hour_bucket)
);

CREATE TABLE on_call_rotation (
    id integer PRIMARY KEY CHECK (id = 1),
    last_user_id uuid REFERENCES users(id)
);
INSERT INTO on_call_rotation (id) VALUES (1);

-- +goose Down
DROP TABLE on_call_rotation;
DROP TABLE detection_guardrails;
DROP TABLE case_alerts;
DROP TABLE cases;
DROP SEQUENCE case_number_seq;
