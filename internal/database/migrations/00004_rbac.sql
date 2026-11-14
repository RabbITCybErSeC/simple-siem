-- +goose Up
CREATE TABLE permissions (
    name text PRIMARY KEY CHECK (name ~ '^[a-z_]+:[a-z_]+$'),
    description text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO permissions (name, description) VALUES
    ('user:read', 'Read users'),
    ('user:write', 'Create, update, disable, and enable users'),
    ('role:assign', 'Assign and remove user roles'),
    ('user:on_call', 'Put users on or off call'),
    ('config:read', 'Read configuration'),
    ('config:write', 'Change configuration'),
    ('detection:read', 'Read detections'),
    ('detection:run', 'Manual shadow runs and fixture tests'),
    ('detection:write', 'Enable, disable, or shadow detections and reset state'),
    ('detection:reload', 'Reload detections'),
    ('dataset:read', 'Read cached log data and quarantine'),
    ('pipeline:read', 'Read pipelines'),
    ('pipeline:write', 'Change pipelines'),
    ('pipeline:run', 'Run pipelines'),
    ('alert:read', 'Read alerts'),
    ('suppression:read', 'Read suppressions'),
    ('suppression:write', 'Change suppressions'),
    ('suppression:broad_write', 'Change broad suppressions'),
    ('case:read', 'Read cases'),
    ('case:write', 'Work cases'),
    ('case:close', 'Close cases'),
    ('case:merge', 'Merge cases'),
    ('task:read', 'Read tasks'),
    ('task:write', 'Change tasks'),
    ('template:write', 'Change task templates'),
    ('tag:manage', 'Manage tags, approve or merge free-form tags'),
    ('view:share', 'Share saved views with the team'),
    ('webhook:read', 'Read webhooks'),
    ('webhook:write', 'Change webhooks'),
    ('audit:read', 'Read audit events');

CREATE TABLE role_permissions (
    role_name text NOT NULL REFERENCES roles(name),
    permission text NOT NULL REFERENCES permissions(name),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_name, permission)
);
CREATE INDEX role_permissions_permission_idx ON role_permissions (permission);

-- ===== Default role mapping (rbac-admin-api decision 3) =====
-- Reviewed with the owner; any change ships as a new migration.
INSERT INTO role_permissions (role_name, permission) VALUES
    -- ADMIN
    ('ADMIN', 'alert:read'),
    ('ADMIN', 'audit:read'),
    ('ADMIN', 'case:close'),
    ('ADMIN', 'case:merge'),
    ('ADMIN', 'case:read'),
    ('ADMIN', 'case:write'),
    ('ADMIN', 'config:read'),
    ('ADMIN', 'config:write'),
    ('ADMIN', 'dataset:read'),
    ('ADMIN', 'detection:read'),
    ('ADMIN', 'detection:reload'),
    ('ADMIN', 'detection:run'),
    ('ADMIN', 'detection:write'),
    ('ADMIN', 'pipeline:read'),
    ('ADMIN', 'pipeline:run'),
    ('ADMIN', 'pipeline:write'),
    ('ADMIN', 'role:assign'),
    ('ADMIN', 'suppression:broad_write'),
    ('ADMIN', 'suppression:read'),
    ('ADMIN', 'suppression:write'),
    ('ADMIN', 'tag:manage'),
    ('ADMIN', 'task:read'),
    ('ADMIN', 'task:write'),
    ('ADMIN', 'template:write'),
    ('ADMIN', 'user:on_call'),
    ('ADMIN', 'user:read'),
    ('ADMIN', 'user:write'),
    ('ADMIN', 'view:share'),
    ('ADMIN', 'webhook:read'),
    ('ADMIN', 'webhook:write'),

    -- SECURITY_ENGINEER
    ('SECURITY_ENGINEER', 'alert:read'),
    ('SECURITY_ENGINEER', 'audit:read'),
    ('SECURITY_ENGINEER', 'case:read'),
    ('SECURITY_ENGINEER', 'config:read'),
    ('SECURITY_ENGINEER', 'config:write'),
    ('SECURITY_ENGINEER', 'dataset:read'),
    ('SECURITY_ENGINEER', 'detection:read'),
    ('SECURITY_ENGINEER', 'detection:reload'),
    ('SECURITY_ENGINEER', 'detection:run'),
    ('SECURITY_ENGINEER', 'detection:write'),
    ('SECURITY_ENGINEER', 'pipeline:read'),
    ('SECURITY_ENGINEER', 'pipeline:run'),
    ('SECURITY_ENGINEER', 'pipeline:write'),
    ('SECURITY_ENGINEER', 'suppression:broad_write'),
    ('SECURITY_ENGINEER', 'suppression:read'),
    ('SECURITY_ENGINEER', 'suppression:write'),
    ('SECURITY_ENGINEER', 'tag:manage'),
    ('SECURITY_ENGINEER', 'task:read'),
    ('SECURITY_ENGINEER', 'template:write'),
    ('SECURITY_ENGINEER', 'view:share'),
    ('SECURITY_ENGINEER', 'webhook:read'),
    ('SECURITY_ENGINEER', 'webhook:write'),

    -- ANALYST
    ('ANALYST', 'alert:read'),
    ('ANALYST', 'case:close'),
    ('ANALYST', 'case:merge'),
    ('ANALYST', 'case:read'),
    ('ANALYST', 'case:write'),
    ('ANALYST', 'dataset:read'),
    ('ANALYST', 'detection:read'),
    ('ANALYST', 'pipeline:read'),
    ('ANALYST', 'suppression:read'),
    ('ANALYST', 'suppression:write'),
    ('ANALYST', 'task:read'),
    ('ANALYST', 'task:write'),
    ('ANALYST', 'view:share'),

    -- READ_ONLY
    ('READ_ONLY', 'alert:read'),
    ('READ_ONLY', 'case:read'),
    ('READ_ONLY', 'detection:read'),
    ('READ_ONLY', 'pipeline:read'),
    ('READ_ONLY', 'suppression:read'),
    ('READ_ONLY', 'task:read');

-- SERVICE: none until Phase 10 defines service accounts.
-- ===== End of default role mapping =====

CREATE TABLE password_reset_tokens (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES users(id),
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_by uuid NOT NULL REFERENCES users(id),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_tokens_user_id_idx ON password_reset_tokens (user_id);

CREATE INDEX audit_events_actor_idx ON audit_events (actor_id, created_at);

-- +goose Down
DROP INDEX audit_events_actor_idx;
DROP TABLE password_reset_tokens;
DROP TABLE role_permissions;
DROP TABLE permissions;
