# User Management: plan

One place to keep the church's user accounts. The maintenance tracker and the
production planner stop keeping their own passwords and sign people in
through this app instead. Each person has one username and password, and an
admin adds people and sets what they can do in each app from here.

Status: step 1 of the build order (this service, standalone) is built.
Steps 2 onward are not.

## What the apps do today

Both siblings (`../maintenance_tracking`, `../production_planning`) work the
same way:

- A `users` table (`username` unique NOCASE, `display_name`,
  `password_hash` bcrypt, `is_admin`).
- A `sessions` table holding random opaque tokens in an HttpOnly `mt_*` or
  `pp_*` cookie, with a per-session CSRF token. Changing a password deletes
  every session for that user.
- Their own login, first-run `/setup`, `/account` (change password) and
  `/admin/users` pages, plus a per-IP login rate limiter.
- Other tables point at `users(id)`:
  - Tracker: `created_by`, `assigned_to`, `reported_by`, `requested_by`
    and so on, all `ON DELETE SET NULL`.
  - Planner: `production_members.user_id`, `ON DELETE CASCADE`. Locked
    productions are only shown to their members.
- Both run on the same droplet behind Caddy, which uses one site file per app
  in `/etc/caddy/sites/`. Both are deployed by Ansible.

Each app has one user right now.

## Suggested approach (and how it differs from the original idea)

The original idea: each app shows its own login form, then checks the
password with this service server-to-server. After that, the browser and the
app use a token. The token part is right, and we already have it: it's the
session cookie. What I'd change is where the password gets typed in.

**Recommendation: redirect sign-in (the OAuth2 / OpenID Connect
"authorization code" flow), built small, without extra libraries.**

1. Someone opens the planner without a session. The planner sends them to
   `accounts.<church domain>/authorize?client_id=planner&...`.
2. If they don't have a session on this service, they sign in here. **This is
   the only page where a password is ever typed.**
3. This service sends them back to `planner/auth/callback?code=...`, using a
   code that works once and expires in 60 seconds.
4. The planner exchanges the code server-to-server (sending its own client
   secret) and gets back the user and their role in the planner.
5. The planner creates its own local session cookie, as it does now. Every
   request after that works exactly as it does today.

Why this is better than checking passwords from inside each app:

- **Real single sign-on.** If you're signed in to the tracker and open the
  planner, step 2 is skipped. The redirect goes there and back in under a
  second, and you never see a login page. Checking passwords from each app
  would still make you type your password in each one.
- **The apps never see passwords.** If an app has a bug, it can't leak them.
  Rate limiting, lockout, password rules, and later passkeys or 2FA all live
  in one place.
- **Per-request speed stays the same.** Apps still check their own SQLite
  session table, with no network call per request.
- **It's the standard flow.** If we ever want to swap in an off-the-shelf
  identity provider, or add an app we didn't write (a wiki, Nextcloud...), the
  shape is already right.

Things I'd **avoid**:

- **JWTs in localStorage.** XSS can read them, they can't be revoked, and
  they'd need a JWT library. HttpOnly cookies backed by the database are
  simpler and safer.
- **One cookie shared across the parent domain.** This works only if every
  app reads the same session store. That ties the apps together and spreads
  the session cookie to every subdomain.
- **An off-the-shelf identity provider** (Authentik, Keycloak, Authelia,
  Kanidm, Pocket ID). These are good projects, but:
  - Authentik and Keycloak are too heavy for a $6, 1 GB droplet.
  - Authelia has no user admin UI.
  - Pocket ID allows passkeys only.
  - None of them would manage per-app roles the way we want without more
    setup than the code itself.

  A small Go app in the same stack (about 1–2k lines) fits better here. It
  would follow the OIDC flow closely, so moving to one of these later stays
  possible.

### Token details (all opaque random strings, stored hashed in SQLite)

| Token | Lives where | Lifetime |
|---|---|---|
| `um_session` cookie | Browser ↔ this service | 30 days, sliding |
| Authorization code | URL, once | 60 s, single use, bound to client + redirect URI + PKCE |
| Client secret | Each app's env (like `PP_TRACKER_TOKEN` today) | Until rotated |
| Grant ID | Stored in the app's local session row | Until sign-out or revocation |
| App session cookie (`mt_session` / `pp_session`) | Browser ↔ app | As today |

Protections on the flow:

- `state` parameter, checked against a short-lived cookie (stops login CSRF).
- PKCE (`S256`). It costs about 10 lines.
- Redirect URIs must match the registered ones exactly.
- The client secret is compared in constant time.

No signing keys, no JWKS, no new dependencies. We only need `crypto/rand`,
`crypto/sha256` and the bcrypt package the apps already use.

### Keeping apps current (disable, role change, password change)

Each app session stores the **grant ID** it got at sign-in. At most every
**5 minutes** per session, the app's `loadSession` middleware calls
`GET /api/v1/grants/{id}` on this service:

- `200` with the current user and role: the app updates its local user row
  and carries on.
- `401/404` (signed out, disabled, password changed, access removed): the app
  deletes the local session and redirects to sign in.
- **Can't reach the service:** the app keeps going on the cached session (a
  grace period of something like 1 hour), so a restart of this service
  doesn't sign anyone out.

This avoids building "back-channel logout" pushes, retries, and the endpoints
apps would need to receive them. All the apps are on the same droplet, so
these calls go to `http://127.0.0.1:<port>` and are very cheap.

**Sign-out:** the app clears its session and redirects to `/logout` here,
which ends the central session and every grant tied to it. The other app
notices on its next check, within 5 minutes.

## Data model (this service)

```sql
users        (id, username UNIQUE NOCASE, display_name, email, password_hash,
              disabled, is_admin,        -- admin of THIS service
              password_changed_at, last_login_at, created_at)
apps         (id, client_id UNIQUE, name, base_url, redirect_uris,
              secret_hash, roles,        -- e.g. 'user,admin' (the roles this app understands)
              created_at)
user_apps    (user_id, app_id, role,     -- no row = no access to that app
              suspended,                 -- app admin turned access off; row kept
              locked,                    -- user admin pinned it; app admins can't change it
              granted_by, updated_by, updated_at)
sessions     (id, token_hash, user_id, ip, user_agent, expires_at, last_seen_at, ...)  -- um_session
auth_codes   (code_hash, app_id, user_id, session_id, redirect_uri, pkce_challenge, expires_at)
grants       (id_hash, app_id, user_id, session_id, created_at, last_checked_at)
audit_log    (id, at, actor_user_id, action, target_user_id, app_id, detail, ip)
settings     (key, value)
```

**What stays in each app:** domain-specific permissions. Production
membership (`production_members`) is planner data. It stays in the planner,
keyed by the planner's own local user ID. This service only answers "may
this person use the planner, and as a `user` or an `admin`?"

## Who can change what

There are two levels of admin:

- **User admin** (`users.is_admin` here): the business/office role. They work
  in this service. They:
  - Create and disable people, and reset passwords.
  - **Grant someone access to an app for the first time.**
  - Can change anything an app admin did.
- **App admin** (role `admin` in `user_apps` for one app): they work **inside
  their own app**, on its Users page. That page reads and writes through this
  service's API, so the data lives here, not in the app. For people who
  already have access to *their* app, an app admin can:
  - Change their role (any of the roles the app registered).
  - Suspend and restore their access.

  An app admin can't:
  - Create people, reset passwords, or rename anyone.
  - Grant access to someone who doesn't have it yet. That's the user admin's
    call, so the user admin stays the gatekeeper for who has an account in
    which app.
  - See or touch other apps.
  - Change a row a user admin has **locked**. A lock is how a user admin
    overrides an app admin, e.g. "this person stays admin" or "this person
    stays suspended". The app's page shows locked rows read-only, with a note.
  - Demote or suspend the last active admin of the app.

Decided: app admins can suspend people, so they can act fast on their own
app. They can also restore access, unless a user admin has locked the row.

Suspending sets `suspended` instead of deleting the row, so:

- The user admin can see what happened and undo it.
- The app keeps its local user row, so their history stays attributed.

A suspension takes effect at once. The app that made the change deletes
that person's local sessions straight away. If it's done from this service,
the app notices at its next grant check, within 5 minutes.

### How the app's Users page talks to this service

```
GET   /api/v1/apps/{client_id}/users             -- list, with role/suspended/locked
PATCH /api/v1/apps/{client_id}/users/{user_id}   -- {role} or {suspended}
```

Each call carries two credentials:

1. **The app's client secret.** It proves which app is calling. The scope is
   always that one app, so even a compromised app can only change
   permissions for itself, never other apps or anyone's password.
2. **The acting person's grant ID** (from their app session, in an
   `X-Acting-Grant` header). This service looks up who that is and checks,
   **on its own records**, that they are an active admin of that app right
   now. The app's own idea of "is admin" isn't trusted.

Every change goes into the audit log, with the actor and the app it was made
through. A user admin sees it there, and also on the user's page here ("Role
changed to admin by Sam via Planner").

Roles are still per app and pass straight through. If the tracker later adds
a `reporter` role, it's added to its `roles` list here and becomes available
on both pages automatically.

## Changes to each app

The same work is needed in both repos, so it should land in both at once
(per the planner's CLAUDE.md note about shared patterns).

1. **Migration:** `ALTER TABLE users ADD COLUMN sso_subject TEXT UNIQUE`
   (this service's user ID). `password_hash` becomes nullable, and stays
   unused once SSO is on.
2. **Keep the local `users` table as a cache.** This is what keeps every
   `created_by` / `assigned_to` / `production_members` foreign key working
   unchanged. On every sign-in and check, insert or update the row by
   `sso_subject` (username, display name, `is_admin` set from the role).
3. **Sync users so they show up before they've ever signed in.** Assignee
   pickers and production members must include people who haven't used that
   app yet. Add `GET /api/v1/apps/{client_id}/users` here, which returns
   everyone with access to that app. The app pulls it when an admin opens a
   people picker, cached for about a minute, like `internal/tracker`. Users
   whose access is removed keep their local row, so history stays
   attributed, but they're marked inactive.
4. **New `internal/sso` package:** about 150 lines, built like
   `internal/tracker`. It handles the authorize redirect, the callback, the
   code exchange, and the grant check.
5. **Routes:**
   - `/login` redirects to this service.
   - New `/auth/callback`.
   - `/logout` also signs out here.
   - `/account` links to this service's account page.
   - `/admin/users` becomes the **app-admin Users page** (see "Who can
     change what"). It lists people from this service's API and changes
     role or suspended through it. It has no add, password or rename fields.
     It also has a "Need someone added? Ask a user admin" note, or a "Manage
     in User Management" link if the viewer is also a user admin.
   - `/setup` goes away when SSO is configured.
6. **Config:** `SSO_URL` (public, for browser redirects), `SSO_INTERNAL_URL`
   (`http://127.0.0.1:8100` on the droplet), `SSO_CLIENT_ID`,
   `SSO_CLIENT_SECRET` (from env, like `PP_TRACKER_TOKEN`). If `SSO_URL` is
   empty, the app keeps the current local login. That covers development and
   gives a fallback during the switch.
7. **Break-glass:** keep a CLI command in each app that turns local login
   back on. If this service is ever broken, an admin can still get in over
   SSH.
8. **PWA:**
   - `sw.js` must never cache `/login`, `/auth/*` or `/logout`, and must let
     navigation redirects through.
   - Test the round trip from an **installed** PWA on iOS and Android. iOS
     opens other-origin pages in an in-app browser sheet and returns to the
     app once the redirect lands back in scope. That should work, but it's
     the riskiest UX part, so test it early.
   - This service is a PWA too (manifest + icons), so admins can add users
     from a phone.

## This service's pages

- `/login`, `/logout`, `/authorize`.
- `/account`: change your own password, see your apps and where you're
  signed in.
- After sign-in with no `return_to`: an **app launcher** with tiles for the
  apps you have access to.
- Admin:
  - **Users:** add, edit, disable, reset password, and a role per app shown
    as a grid (rows are users, columns are apps). In the grid you can grant
    first access, set a role, suspend, and lock or unlock each cell. Each
    cell shows who last changed it.
  - **Apps:** register an app, redirect URIs, roles, rotate secret.
  - **Audit log:** sign-ins, failed attempts, every admin change.
- `/setup` on first run (or created by Ansible, as the planner does).
- Same stack as the siblings:
  - Go, SQLite (`modernc.org/sqlite`), `x/crypto/bcrypt`.
  - Server-rendered templates with the zero-build Stimulus autoloader.
  - CSP `style-src 'self'`.
  - Double-submit CSRF, login rate limiter.

  Copy the shared pieces from the planner, don't reinvent them.
- Cookies are named `um_*`. It listens on **8100** locally (tracker is on
  8080, planner on 8090).

## Moving the existing user over

bcrypt hashes are portable, so **the current password keeps working with
nothing to reset.**

1. Run `user-management import-users --tracker /var/lib/.../maintenance.db
   --planner /var/lib/production-planner/productions.db`. It reads both
   `users` tables read-only, matches by username (case-insensitive), and
   creates one user here per username:
   - It copies the hash.
   - It grants `user` or `admin` per app based on `is_admin`.
   - If the two hashes differ (different passwords in each app), it takes the
     newer one. It prints which, unless `--prefer tracker|planner` is given.
2. It registers both apps as clients and prints their secrets once.
3. Each app's SSO migration links its existing local user to the new one by
   username **only if `sso_subject` is still NULL**. So the existing user
   (ID 1) keeps all their history, assignments and memberships.

With one user this is a two-minute job. The command is mostly there so the
migration can be rehearsed against copies of the production databases first.

## Deployment (Ansible)

- Same layout as the siblings:
  - `deploy/ansible/{provision,deploy}.yml`, `defaults.yml`, and a
    gitignored `vars.yml`.
  - Finds the droplet by tag `maintenance-tracker`.
  - Own service user, `/var/lib/user-management`, systemd unit, and
    `/etc/caddy/sites/user-management.caddy`.
  - The main Caddyfile text must stay identical across all three repos.
- Backs up the DB before each deploy, like the others.
- **Deploy this service first.** Then deploy each app with `SSO_*` set. Until
  then, the apps keep working with local login.
- Secrets come from env vars (`UM_TRACKER_SECRET`, `UM_PLANNER_SECRET`), never
  files.
- DNS: add the `accounts.<church domain>` subdomain.

## Build order

Notes from step 1, for step 2:

- All the tables above already exist (`001_initial.sql`). Grants and codes
  point at `sessions.id`, so ending a session here (sign-out, password
  change, account turned off) deletes its grants and codes by cascade.
- The CSRF middleware checks every POST. `/token` and the `/api/v1/` routes
  are called server-to-server, so they need to skip it (they authenticate
  with the client secret instead).
- `/login?next=/authorize?...` already keeps the query string (see
  `safeRedirect`).
- `/logout` is POST only today; apps will redirect a browser to it, so it
  needs a GET form that asks to confirm, or a signed `post_logout` flow.

1. **Done.** **This service, standalone:** skeleton copied from the planner (main,
   store, migrations, templates, Stimulus, PWA), users, sessions, login,
   setup, account, admin users, audit log. Tests.
2. **SSO endpoints:** apps registry, `/authorize`, `/token`, grant check,
   app-admin users API (list + PATCH), logout. Tests for the flow, including
   the attacks: wrong redirect URI, reused code, bad PKCE, wrong secret,
   disabled user. For the app-admin API, also test:
   - A non-admin's grant.
   - Another app's user.
   - A locked row.
   - Granting new access.
   - Demoting the last admin.
3. **`import-users` command:** rehearse against copies of both production
   databases.
4. **Planner:** `internal/sso`, migration, routes, user sync, app-admin
   Users page. Local login stays as a fallback when `SSO_URL` is unset.
5. **Tracker:** the same change.
6. **Ansible** for this service, and the new env vars in both apps' deploys.
7. **Roll out.** Deploy this service and import. Then the planner, then the
   tracker, testing each from an installed PWA on a phone.
8. **Cleanup** after a few weeks: remove the local password code paths
   (keep break-glass).

## Decisions (2026-10-06)

- **Domain:** `accounts.<church domain>`.
- **Roles per app:** just `user` / `admin` for now, matching today. A
  read-only or `reporter` role can be added to an app's `roles` later.
- **Session lengths:** 30 days, sliding, here. The apps keep theirs as they
  are today.
- **Password resets:** an admin resets them; no email or SMTP. Everyone can
  change their own password on `/account`.
- **Passkeys:** wanted, as an optional way to sign in. Talk through the
  approach once the build order above is done; not part of it.
