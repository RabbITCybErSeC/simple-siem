-- +goose Up
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    email text NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED', 'INVITED')),
    on_call boolean NOT NULL DEFAULT false,
    last_login_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1
);

CREATE TABLE user_identities (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES users(id),
    provider text NOT NULL,
    subject text NOT NULL,
    password_hash text,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1,
    UNIQUE (provider, subject)
);
CREATE INDEX user_identities_user_id_idx ON user_identities (user_id);

CREATE TABLE roles (
    name text PRIMARY KEY,
    description text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO roles (name, description) VALUES
    ('ADMIN', 'Full system administration'),
    ('SECURITY_ENGINEER', 'Manage detections, pipelines, fetchers, indicators, suppressions, and configuration'),
    ('ANALYST', 'Work alerts, cases, notes, and tasks'),
    ('READ_ONLY', 'View alerts, cases, detections, indicators, and reports'),
    ('SERVICE', 'Non-human automation identity for future integrations');

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users(id),
    role_name text NOT NULL REFERENCES roles(name),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_name)
);
CREATE INDEX user_roles_role_name_idx ON user_roles (role_name);

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES users(id),
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    auth_provider text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz NOT NULL DEFAULT now(),
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    client_ip inet,
    user_agent text CHECK (length(user_agent) <= 512)
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE TABLE login_attempts (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    email_hash bytea NOT NULL,
    client_ip inet NOT NULL,
    succeeded boolean NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_email_idx ON login_attempts (email_hash, created_at) WHERE NOT succeeded;
CREATE INDEX login_attempts_ip_idx ON login_attempts (client_ip, created_at) WHERE NOT succeeded;

ALTER TABLE audit_events ADD COLUMN actor_session_id uuid;

-- +goose Down
ALTER TABLE audit_events DROP COLUMN actor_session_id;
DROP TABLE login_attempts;
DROP TABLE sessions;
DROP TABLE user_roles;
DROP TABLE roles;
DROP TABLE user_identities;
DROP TABLE users;
