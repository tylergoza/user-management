-- Timestamps are UTC "YYYY-MM-DD HH:MM:SS", so they compare as text.

CREATE TABLE users (
    id                  INTEGER PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name        TEXT NOT NULL DEFAULT '',
    email               TEXT NOT NULL DEFAULT '',
    password_hash       TEXT NOT NULL,
    disabled            INTEGER NOT NULL DEFAULT 0,
    is_admin            INTEGER NOT NULL DEFAULT 0,  -- user admin: of THIS service
    password_changed_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at       TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Signed-in browsers (the um_session cookie). Only a hash of the token is
-- kept, so a copy of the database can't be used to sign in.
CREATE TABLE sessions (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    expires_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Apps that sign people in through this service (OAuth "clients").
CREATE TABLE apps (
    id            INTEGER PRIMARY KEY,
    client_id     TEXT NOT NULL UNIQUE,         -- e.g. 'planner'
    name          TEXT NOT NULL,
    base_url      TEXT NOT NULL DEFAULT '',
    redirect_uris TEXT NOT NULL DEFAULT '',     -- one per line, matched exactly
    secret_hash   TEXT NOT NULL DEFAULT '',
    roles         TEXT NOT NULL DEFAULT 'user,admin',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Who may use which app, and as what. No row means no access.
CREATE TABLE user_apps (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    suspended  INTEGER NOT NULL DEFAULT 0,      -- app admin turned access off; row kept
    locked     INTEGER NOT NULL DEFAULT 0,      -- user admin pinned it; app admins can't change it
    granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, app_id)
);
CREATE INDEX user_apps_app ON user_apps(app_id);

-- One-time codes handed to an app in the sign-in redirect.
CREATE TABLE auth_codes (
    code_hash      TEXT PRIMARY KEY,
    app_id         INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id     INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    pkce_challenge TEXT NOT NULL,
    expires_at     TEXT NOT NULL
);

-- An app's sign-in, tied to the session here that made it. Ending that
-- session ends the grant.
CREATE TABLE grants (
    id_hash         TEXT PRIMARY KEY,
    app_id          INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_checked_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX grants_session ON grants(session_id);

CREATE TABLE audit_log (
    id             INTEGER PRIMARY KEY,
    at             TEXT NOT NULL DEFAULT (datetime('now')),
    actor_user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action         TEXT NOT NULL,               -- e.g. 'login', 'user.disable'
    target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    app_id         INTEGER REFERENCES apps(id) ON DELETE SET NULL,
    detail         TEXT NOT NULL DEFAULT '',
    ip             TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_actor ON audit_log(actor_user_id);
CREATE INDEX audit_log_target ON audit_log(target_user_id);
