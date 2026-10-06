# User Management: project notes

Central accounts for the church apps. Sibling of `../maintenance_tracking`
and `../production_planning`, same stack and conventions (Go + SQLite +
server-rendered templates + Stimulus autoloader, no build step). Copy shared
pieces (CSRF, layout, rate limiter, Ansible) from the planner rather than
reinventing them.

- `PLAN.md` is the design: redirect-based SSO (authorization code + PKCE),
  opaque tokens hashed in SQLite, no JWTs, no new dependencies. Apps keep
  their own session cookies and a local `users` cache keyed by `sso_subject`
  so their foreign keys keep working.
- Domain-specific permissions (e.g. planner `production_members`) stay in
  the apps; this service only holds per-app roles.
- Cookies are `um_*`; local port 8100 (tracker 8080, planner 8090).
- Deploys onto the maintenance tracker's droplet with its own Caddy site
  file; the main Caddyfile text must stay identical in all three repos.
- The user runs all `git commit`s themselves (YubiKey signing). Don't commit.
