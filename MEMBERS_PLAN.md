# User Management: browser sign-in, per-app tokens and default roles for the members site

The cross-app design is in `../.claude/plans/members-site.md`; this is User
Management's part. The endpoint names and shapes in that file are the
contract: other apps are planning against them. Everything here is optional
for the other apps: nothing changes for an app that doesn't opt in.

Status: planned 2026-10-16, not built.

`001_initial.sql` is frozen: User Management is live at
`accounts.mountainviewbaptist.cloud` (PLAN.md, rolled out 2026-10-10) and
`internal/store/migrations/` holds only 001. So all of this goes in new
migrations (`002_…`, `003_…`). Plain `ALTER TABLE … ADD COLUMN` and `CREATE
TABLE` need no table rebuild, so the `noForeignKeys` flag
(`internal/store/store.go`) isn't needed.

## What changes, in short

| | Now | After |
|--|-----|-------|
| Redirect URIs | Per app, exact match, code swapped at `/token` with the app's secret | An app can also have **public** redirect URIs: no secret, PKCE required, grant marked public |
| Browser calls | None. `/token` and `/api/v1/*` are for servers only (Basic auth, no CORS) | CORS on `/token` and `/api/v1/*` for the origins of public redirect URIs only |
| A grant | Always an app server's. 5-minute checks, slides the 30-day session | Can be a **browser grant**: 8 hours idle, can't use the app-admin APIs |
| Acting in another app | Not possible | `POST /api/v1/delegate` gives a `umd_` token for one app, 15 min, bound to the grant |
| Checking a token | n/a | `GET /api/v1/token` (the receiving app's Basic auth plus `X-Token`) |
| What a person can reach | Apps list on `/account` and the launcher | Also `GET /api/v1/me/apps` for the website's nav |
| Who may delegate | n/a | App A "May act for users in" B **and** B "Accepts tokens from" A, both on the Apps page |
| New users | No access until a user admin grants it | A "New users get role ___" setting per app, applied when a user admin creates a person |

## Steps

### 1. Migration `002_members.sql`
- [ ] `apps`: add `public_redirect_uris TEXT NOT NULL DEFAULT ''` (one per line, like `redirect_uris`), `acts_in TEXT NOT NULL DEFAULT ''` ("May act for users in": client IDs, comma separated), `accepts_from TEXT NOT NULL DEFAULT ''` ("Accepts tokens from": client IDs), `default_role TEXT NOT NULL DEFAULT ''` (empty means no default)
- [ ] `grants`: add `public INTEGER NOT NULL DEFAULT 0` (1 for a grant made by a public redirect URI). Existing grants stay 0
- [ ] New table `delegated_tokens (token_hash TEXT PRIMARY KEY, grant_hash TEXT NOT NULL REFERENCES grants(id_hash) ON DELETE CASCADE, audience_app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))` plus an index on `grant_hash`. Deleting the session deletes its grants (`grants.session_id` cascades), which deletes the tokens: that is how a token dies with sign-out
- [ ] `auth_codes`: add `public INTEGER NOT NULL DEFAULT 0`, so `/token` knows which kind of redirect URI the code was issued for
- [ ] Why columns for the two lists: `roles` and `redirect_uris` already work this way, client IDs can't change, and a stale ID in a list matches nothing
- [ ] Test in `internal/store/store_test.go`: run 001 only (`openAt(path, 1)`) on a copy holding sample apps, users, grants and codes, then 002; old rows keep working and the new columns have their defaults

### 2. Apps: store and the Apps page
- [ ] `store.App` (`internal/store/apps.go`): add `PublicRedirectURIs`, `ActsIn`, `AcceptsFrom` (`[]string`) and `DefaultRole`; extend `appCols`, `scanApp`, `CreateApp`, `UpdateApp`
- [ ] `App.RedirectAllowed` stays "exact match in `RedirectURIs` or `PublicRedirectURIs`"; add `App.PublicRedirect(uri)` for the public list only. A URI can't be in both lists
- [ ] `appForm` / `readAppForm` / `validate` (`internal/server/handlers_apps.go`): fields for the three lists and `default_role`. Rules: a public URI must be `https` (or `http://localhost` for development), no `#`, no wildcard; `acts_in` / `accepts_from` entries must be existing client IDs other than the app itself; `default_role` must be one of `Roles` and may not be `admin`
- [ ] `appChanges` writes the new fields to the audit log (`app.update`), so a user admin can see who opened a door
- [ ] Apps page templates (`web/templates/pages/`, the app form): a "Browser sign-in (public)" box for the public URIs, "May act for users in" and "Accepts tokens from" as checkbox lists of the other registered apps, and a "New users get role" select with a "no default" choice. Each box has one line of help text
- [ ] `Server.cspHeader` already lists the origin of every redirect URI in `form-action`; make it read `PublicRedirectURIs` too, since the sign-in form redirects to the website
- [ ] `registerapp` (`internal/registerapp/registerapp.go`): `--public-redirect-uri` (repeatable), `--acts-in`, `--accepts-from`, `--default-role` flags, and the same checks. `changeRoles` / `store.ChangeAppRoles` keep `default_role` valid: a rename updates it; removing the default role is refused with a clear message
- [ ] Tests: form validation for each rule above; round trip through `registerapp` including a dry run

### 3. Browser sign-in: public redirect URIs
- [ ] `handleAuthorize` (`internal/server/sso.go`): accept a `redirect_uri` found in `PublicRedirectURIs`; carry `public` into `CreateAuthCode` (`internal/store/sso.go`, `AuthCode.Public`). Everything else (state, S256 challenge, the `no_access` page) stays as is. PKCE is already required for every app
- [ ] `/token` route (`internal/server/routes.go`): today it is wrapped in `requireClient`. Change it to a small wrapper: if an `Authorization: Basic` header is sent, use `requireClient` exactly as now; if not, look up the app by the `client_id` form field and go on as a public client. `handleToken` then checks, after `ConsumeAuthCode`: a public client may only exchange a code whose `Public` is 1, and a Basic-authenticated app only a code whose `Public` is 0. Redirect URI and PKCE checks are unchanged
- [ ] A public exchange returns `{grant, user}` like now and creates the grant with `public = 1` (`CreateGrant` gets a `public` argument). The audit action is `app.signin` with detail `browser`
- [ ] Rate limit the public `/token` per IP, with the same limiter the login form uses (`internal/server/auth.go`), so a code can't be guessed in bulk. Codes are 60 s and single use, so this is a second wall
- [ ] The Basic-auth "is this client ID and secret good" probe that the apps' Connections pages use must keep working: invalid_client for a bad pair, invalid_grant for a good pair with a made-up code. Add a test for it, since the wrapper touches that path
- [ ] Tests: public code exchange without a secret works; a confidential code without a secret is refused; a public code with a wrong redirect URI or bad verifier is refused; a code can't be used twice

### 4. Browser grants: 8 hours idle, no app-admin calls
- [ ] `store.CheckGrant` (`internal/store/sso.go`): return `Grant.Public`. For a public grant, if `last_checked_at` is older than 8 hours (`browserIdle` constant), delete the grant and return `ErrNotFound`. Every browser call that uses the grant (`me/apps`, `delegate`, `logout`) counts as use and updates `last_checked_at`. The 5-minute server checks are not involved
- [ ] A check by the browser grant still slides the `um_session` expiry as the existing code does, so someone who uses the members area stays signed in here for 30 days
- [ ] `apiGrant` (`GET /api/v1/grant`) and `apiAppUserUpdate` (`X-Acting-Grant`): refuse a public grant with 403 `public_grant` ("a browser sign-in can't do this"). Do it in one helper used by both, and by `apiAppUsers` if it ever reads a grant. A public grant is therefore useless on `/api/v1/apps/{client_id}/users` and the PATCH. The website app normally has no secret anyway; this stays correct if one is ever set
- [ ] `apiLogout` (`POST /api/v1/logout`): accept either Basic auth (as now) or a bare `X-Grant` that is a public grant. Same answer, 204, same audit event
- [ ] Tests: a public grant is refused at `/api/v1/grant` and on the PATCH with 403 `public_grant`; idle for 8 hours ends it (move `last_checked_at` back by hand); a confidential grant is unaffected

### 5. CORS for the registered public origins only
- [ ] New middleware `s.cors` in `internal/server/routes.go`, placed outside the `mux` so it can answer `OPTIONS` (the mux patterns are method-specific and would 405). It applies to `/token` and `/api/` only
- [ ] The allowed set is the origins (scheme + host) of every app's `PublicRedirectURIs`, read fresh each time like `cspHeader`, so a new app works without a restart. Only an exact match gets `Access-Control-Allow-Origin: <that origin>`; never `*`, never `Allow-Credentials` (no cookies are used). Always send `Vary: Origin`
- [ ] Preflight: answer 204 with `Allow-Methods: GET, POST, OPTIONS`, `Allow-Headers: X-Grant, Content-Type`, `Max-Age: 600` for an allowed origin. For any other origin, answer 204 with no CORS headers, so the browser blocks the call
- [ ] Not-allowed origins on a real request still reach the handler (the Basic-auth server calls send no `Origin`); they just don't get the headers. The handlers' own checks (client secret, grant) are what protect the data
- [ ] `securityHeaders`/`browserless` already treat `/token` and `/api/` as non-browser (no session, no CSRF); nothing changes there. `connect-src 'self'` on this site's own pages stays, because the website's pages call this site, not the other way round
- [ ] Tests: allowed origin gets exact-origin headers; preflight works; an unregistered origin gets none; a confidential-only app's redirect origin gets none (only the public list counts)

### 6. `GET /api/v1/me/apps`
- [ ] New auth wrapper `requireBrowserGrant` (`internal/server/api.go`): reads `X-Grant`, no Basic auth, looks the grant up without an app ID (new `store.CheckBrowserGrant(grantID, ttl)`), requires `public = 1`, the session alive, the user not disabled, and the app's access unsuspended. Errors are the usual JSON: 401 `invalid_grant`. `Cache-Control: no-store`
- [ ] `store.DelegableApps(grantAppID, userID)`: the apps the person has an unsuspended role in, where the grant's app lists the app in `ActsIn` **and** the app lists the grant's app in `AcceptsFrom`. The grant's own app is left out
- [ ] Response: `{"apps": [{"audience": "calendar", "name": "Church Calendar", "role": "member", "url": "https://calendar.<zone>"}]}`. `audience` is the client ID; `url` is `base_url` (so the website can build its `connect-src` list and links)
- [ ] Tests: the list holds only apps with a role and both opt-ins; an app missing either list is left out; a suspended role is left out; a confidential grant is refused

### 7. `POST /api/v1/delegate`
- [ ] Handler `apiDelegate`: `requireBrowserGrant`, JSON `{"audience": "calendar"}` (64 KB body limit). Checks in this order: audience exists (404 `unknown_audience`); the grant's app has it in `ActsIn` and it has the grant's app in `AcceptsFrom` (403 `not_accepted`); the person has an unsuspended role there (403 `no_access`)
- [ ] `store.CreateDelegatedToken(grantHash, audienceAppID, userID)`: `umd_` + `RandomToken()`, stored hashed with `HashToken`, expires in `delegatedTTL = 15 * time.Minute`. Return the token and the role
- [ ] Response `{"token": "umd_…", "expires_in": 900, "role": "member"}`. No refresh token: the website asks again near expiry, and that also re-checks idle time and access
- [ ] Audit event `token.delegate` (actor, app = audience, detail `via website`). Not one row per call if that would flood the log: log it at most once per grant and audience per hour
- [ ] `PurgeExpired` (`internal/store/sessions.go`) also deletes expired `delegated_tokens`
- [ ] Tests: a good token for the right app; 403 `no_access` for a person with no role there; 403 `not_accepted` when either list is missing; unknown audience; expired and idle grants refused; the token is stored hashed

### 8. `GET /api/v1/token`
- [ ] Handler `apiToken`: behind `requireClient` (the receiving app's Basic auth) plus the `X-Token` header (token in a header, never the path, like grant IDs). `Cache-Control: no-store`
- [ ] `store.CheckDelegatedToken(token, audienceAppID)` finds the token and requires, all at once: it has not expired; its audience is the calling app; its grant still exists and is public, with a live session; the user is not disabled; the person still has an unsuspended role in the audience app; the audience still lists the grant's app in `AcceptsFrom` and the grant's app still lists the audience in `ActsIn`. Anything else is `ErrNotFound`
- [ ] Every failure is 401 `invalid_token` with the same text, so a caller can't tell a token for another app from an expired one. The caller treats 401 as "ask for a new token"
- [ ] Response: `{"user": {sub, username, name, email, role}, "via": "website"}`. `role` is the role in the audience app, `via` is the grant's app client ID. `apiUserOf` also sends `user_admin`; leave it, the apps ignore unknown fields
- [ ] A token check does not update `last_checked_at` on the grant. Only the browser's own calls keep the 8 hours alive, so a busy app can't keep an abandoned tab signed in
- [ ] Tests: wrong audience; expired (set `expires_at` back by hand); after sign-out (`apiLogout`, then the token fails); after the account is disabled; after the role is suspended or removed; after an opt-in list changes; a bad or missing client secret

### 9. Default role per app
- [ ] `handleUserCreate` (`internal/server/handlers_admin.go`), after `CreateUser`: for each app with a `DefaultRole`, call `SetAccess(userID, app.ID, app.DefaultRole, false, false, actorID)`. Put the loop in `store.ApplyDefaultRoles(userID, by)` so it runs in one transaction and can be tested alone. The audit entry `user.create` lists the roles given
- [ ] Not applied: the first-run `/setup` user (`internal/server/auth.go`), `main.go` user creation, and `internal/importer` (`import-users` sets roles from the old apps' `is_admin`). Not applied to people who already exist when a default is set; a user admin uses the grid for them
- [ ] User form (`web/templates/pages/`): after the fields, a line "They will get: Website: member, Calendar: member" so the admin sees what happens; the admin can change any cell afterwards on the person's page as today
- [ ] Tests: new user gets the default in every app that has one and nothing in the others; an app with no default gives no row; changing the default later doesn't touch existing people; `import-users` and `/setup` are unchanged

### 10. Tests that tie it together
All in `internal/server/` (new `members_test.go`, using the helpers in `sso_test.go`):
- [ ] Wrong audience: a token made for the calendar is refused when the directory presents it at `/api/v1/token`
- [ ] Expired token refused at `/api/v1/token`
- [ ] Token after sign-out: `POST /api/v1/logout` with the browser grant, then the token fails and `me/apps` returns 401
- [ ] App not accepting the website: `delegate` is 403 `not_accepted`, and `me/apps` doesn't list it
- [ ] Person with no role: `delegate` is 403 `no_access`
- [ ] Unregistered origin refused by CORS: no headers on a preflight or call from it
- [ ] Public grant refused on the app-admin APIs: `GET /api/v1/grant` and the users PATCH with 403 `public_grant`
- [ ] Default role on a new user: created through `/admin/users`, the person has the default role in each app that has one
- [ ] Browser grant idle for 8 hours is ended; a confidential app's SSO flow test (`TestSSOFlow`) passes unchanged
- [ ] `go vet ./...` and `go test ./...` pass; `go.mod` is unchanged

### 11. Docs and rollout
- [ ] `PLAN.md`: data model block (new columns, `delegated_tokens`), a "Browser sign-in and per-app tokens" section short enough to read, and a pointer to this file. Token table gains `umd_` tokens (15 min) and the browser grant (8 hours idle)
- [ ] README: the new endpoints, the three lists on the Apps page, `register-app` flags, and the running-alone table
- [ ] `.claude/CLAUDE.md`: a line that public grants never reach the app-admin APIs and that CORS follows the public redirect URIs only
- [ ] Rollout order: deploy this service first (the migration is additive, nothing reads the new columns until set up). Then register the website: public redirect URI `https://www.<zone>/members/callback/`, roles `member,editor,admin`, default role `member`, "May act for users in" calendar, directory, events, cms. Then each app sets "Accepts tokens from" `website` when it ships its `/me` API. Give existing members the website's `member` role with `register-app --copy-access-from` or the grid
- [ ] Back up the DB before deploying (the deploy playbook already does)

## Running alone

None of this changes the existing confidential SSO flow. `/authorize`,
`/token` with Basic auth, `/api/v1/grant`, `/api/v1/logout` and the
app-admin users API answer as they do now, and the tests for them are not
edited. An app that never opts in (no public redirect URI, nothing in the
lists, no default role) sees no change. The new columns have empty or zero
defaults, and without a public redirect URI no CORS header is ever sent.

## Notes for the other apps

Where the contract sits awkwardly against the real code. The contract is kept as written.

- **`GET /api/v1/token` uses the existing `requireClient`**, so the receiving
  app sends the same Basic auth it already uses for `/api/v1/grant`. Nothing new
  to set up in an app's connection, but it only works once the app is
  registered here, and the website app has no secret.
- **Errors and codes** follow the existing JSON shape
  (`{"error", "error_description"}`). New codes: `invalid_token` (401, every
  token failure alike), `no_access`, `not_accepted`, `unknown_audience`,
  `public_grant` (all 403 except `unknown_audience`, 404). The contract only
  names `no_access`; the others are mine.
- **Apps must treat any 401 from `/api/v1/token` as "ask for a new token"**,
  and must not cache a failure. A good answer may be cached for 60 s as the
  design says; disabling someone takes effect within a minute.
- **The token response also carries `user_admin`** (from the shared `apiUser`).
  Ignore it.
- **Sign-out here ends the whole `um_session`**, as `POST /api/v1/logout`
  always has. Signing out of the website therefore signs the person out of the
  calendar and the others at their next 5-minute grant check, and the next
  website visit needs the password. Making a website-only sign-out would need
  a second session type; not planned.
- **Disabling a person** takes effect on a token check at once (the check reads
  the account), so the 60 s cache in the apps is the only delay.
- **Client IDs are stable** (they can't change), so apps can put them in
  config. `audience` in `delegate` and `me/apps` is the client ID.
- **`sso_subject` is the same `sub`** as in SSO sign-in, so a person found by
  token is the person found by SSO.
- **8 hours idle is measured on the browser's own calls** (`me/apps`,
  `delegate`), not on apps checking tokens. A tab that stops asking for tokens
  signs out after 8 hours, and the website's silent `/authorize` redirect
  brings it back while the 30-day cookie lasts.
- **The website's CORS origin on each app is the app's own setting** (design);
  User Management's CORS only covers calls to User Management.
