-- Per-app tokens (MEMBERS_PLAN.md): an app acts for a signed-in person in
-- another app. Both sides opt in, and each app can give new people a role.
-- Plain ADD COLUMN / CREATE TABLE, so no table rebuild. The browser
-- (public) sign-in columns come in a later migration.

ALTER TABLE apps ADD COLUMN acts_in      TEXT NOT NULL DEFAULT '';  -- "May act for users in": client IDs, comma separated
ALTER TABLE apps ADD COLUMN accepts_from TEXT NOT NULL DEFAULT '';  -- "Accepts tokens from": client IDs, comma separated
ALTER TABLE apps ADD COLUMN default_role TEXT NOT NULL DEFAULT '';  -- role a new user gets; '' for none

-- umd_ tokens: one app acting for a person in another (the audience).
-- Bound to the grant they were made from: ending the session deletes its
-- grants, which deletes these.
CREATE TABLE delegated_tokens (
    token_hash      TEXT PRIMARY KEY,
    grant_hash      TEXT NOT NULL REFERENCES grants(id_hash) ON DELETE CASCADE,
    audience_app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX delegated_tokens_grant ON delegated_tokens(grant_hash);
