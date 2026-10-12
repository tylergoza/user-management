# User Management: project notes

Central accounts for the church apps. Sibling of `../maintenance_tracking`,
`../production_planning` and `../event_planning` (client `events`), same stack and conventions (Go + SQLite +
server-rendered templates + Stimulus autoloader, no build step). Copy shared
pieces (CSRF, layout, rate limiter, Ansible) from the planner rather than
reinventing them.

- `PLAN.md` is the design: redirect-based SSO (authorization code + PKCE),
  opaque tokens hashed in SQLite, no JWTs, no new dependencies. Apps keep
  their own session cookies and a local `users` cache keyed by `sso_subject`
  so their foreign keys keep working.
- Domain-specific permissions (e.g. planner `production_members`) stay in
  the apps; this service only holds per-app roles.
- Cookies are `um_*`; local port 8100 (tracker 8080, planner 8090, event planner 8110).
- Deploys onto the maintenance tracker's droplet with its own Caddy site
  file; the main Caddyfile text must stay identical in all three repos.
- The user runs all `git commit`s themselves (YubiKey signing). Don't commit.
- `register-app` (internal/registerapp) registers an app and can copy another
  app's access list; `make register-app` runs it on the droplet.
  `--roles` / `--rename-role` also change an existing app's roles (see README).
- `CALENDAR_PLAN.md` is this app's part of joining `../calendar` (8120);
  tick its checkboxes as steps are done. Everything there is optional:
  this app must keep working when `CALENDAR_URL` is unset.
- `CONNECTIONS_PLAN.md` (design in `../event_planning/CONNECTIONS_PLAN.md`): links to
  other apps are admin settings on `/admin/connections`; env vars override
  them per whole connection. Secrets encrypted with `secrets.key`.
