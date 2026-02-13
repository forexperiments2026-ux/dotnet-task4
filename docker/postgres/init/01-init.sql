CREATE EXTENSION IF NOT EXISTS citext;

CREATE SCHEMA IF NOT EXISTS app;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE t.typname = 'user_status' AND n.nspname = 'app') THEN
        CREATE TYPE app.user_status AS ENUM ('unverified', 'active', 'blocked');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS app.users
(
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    email CITEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status app.user_status NOT NULL,
    last_login_at TIMESTAMPTZ NULL,
    last_activity_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    row_version INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON app.users (email);
CREATE INDEX IF NOT EXISTS ix_users_last_login_at ON app.users (last_login_at);
CREATE INDEX IF NOT EXISTS ix_users_status ON app.users (status);
