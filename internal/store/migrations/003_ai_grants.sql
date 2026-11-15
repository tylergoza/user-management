-- AI-connection grants: a confidential app that may act for users (its
-- acts_in list isn't empty) gets a grant of its own for a person, not
-- tied to a browser session here. It survives signing out of this site and
-- ends on password change, account disabled, losing the app role, or
-- revocation. Only the hash of the grant is stored.
CREATE TABLE ai_grants (
    id_hash         TEXT PRIMARY KEY,
    app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_checked_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX ai_grants_user ON ai_grants(user_id);

-- umd_ tokens can now hang off either kind of grant. Rebuilt (nothing
-- points at it; tokens last 15 minutes, so any live ones just get asked
-- for again). Exactly one of the two hashes is set.
DROP TABLE delegated_tokens;
CREATE TABLE delegated_tokens (
    token_hash      TEXT PRIMARY KEY,
    grant_hash      TEXT REFERENCES grants(id_hash) ON DELETE CASCADE,
    ai_grant_hash   TEXT REFERENCES ai_grants(id_hash) ON DELETE CASCADE,
    audience_app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    CHECK ((grant_hash IS NULL) <> (ai_grant_hash IS NULL))
);
CREATE INDEX delegated_tokens_grant ON delegated_tokens(grant_hash);
CREATE INDEX delegated_tokens_ai_grant ON delegated_tokens(ai_grant_hash);
