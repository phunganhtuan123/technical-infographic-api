-- Technical Infographic API — initial schema.
--
-- Written by hand rather than generated from the models: AutoMigrate cannot
-- express a partial unique index, and the one on users.email is what stops two
-- accounts claiming the same address.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- searching project titles

CREATE TABLE users (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email             citext,
    email_verified_at timestamptz,
    password_hash     text,
    display_name      text NOT NULL DEFAULT '',
    avatar_url        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    deleted_at        timestamptz
);

-- Email is optional, because Facebook does not always give one, but where it
-- exists it must be unique among live accounts. A plain UNIQUE column cannot
-- say that: it would also collide every soft-deleted row.
CREATE UNIQUE INDEX users_email_key ON users (email)
    WHERE email IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX users_deleted_at_idx ON users (deleted_at);

CREATE TABLE identities (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider   text NOT NULL,
    subject    text NOT NULL,
    email      citext,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- The key is who the provider says you are, never the email on the account.
CREATE UNIQUE INDEX identities_provider_subject_key ON identities (provider, subject);
CREATE INDEX identities_user_id_idx ON identities (user_id);

CREATE TABLE refresh_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id  uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    user_agent text,
    ip         text,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_user_live_idx ON refresh_tokens (user_id) WHERE revoked_at IS NULL;
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens (expires_at);

CREATE TABLE user_settings (
    user_id           uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    ai_gateway_origin text,
    ai_provider       text,
    ai_model          text,
    editor            jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       text NOT NULL,
    purpose     text NOT NULL DEFAULT '',
    format      text NOT NULL DEFAULT '16:9',
    mode        text NOT NULL DEFAULT 'architecture',
    document    jsonb NOT NULL,
    version     bigint NOT NULL DEFAULT 1,
    scene_count integer NOT NULL DEFAULT 1,
    node_count  integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);
CREATE INDEX projects_owner_recent_idx ON projects (owner_id, updated_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX projects_title_trgm_idx ON projects USING gin (title gin_trgm_ops);
CREATE INDEX projects_deleted_at_idx ON projects (deleted_at);

CREATE TABLE project_versions (
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version    bigint NOT NULL,
    document   jsonb NOT NULL,
    label      text,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, version)
);
