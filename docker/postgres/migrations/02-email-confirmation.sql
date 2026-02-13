CREATE TABLE IF NOT EXISTS app.email_confirmation_tokens
(
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES app.users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_email_confirmation_tokens_token_hash ON app.email_confirmation_tokens (token_hash);
CREATE INDEX IF NOT EXISTS ix_email_confirmation_tokens_user_id ON app.email_confirmation_tokens (user_id);
CREATE INDEX IF NOT EXISTS ix_email_confirmation_tokens_expires_at ON app.email_confirmation_tokens (expires_at);
