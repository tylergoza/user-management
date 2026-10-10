# Church User Management

One place for the church's user accounts. People get one username and
password for every church app, and user admins decide who can use which app.
The [maintenance tracker](../maintenance_tracking) and the
[production planner](../production_planning) will sign people in through it.
See [PLAN.md](PLAN.md) for the design and what's built so far.

Built the same way as the other apps:

- **Backend:** Go, one static binary with its templates, JS and CSS embedded
- **Database:** SQLite (one file, pure-Go driver, no CGO)
- **Frontend:** server-rendered HTML + [Stimulus](https://stimulus.hotwired.dev), vendored, with the
  same no-build autoloader. No Node, no bundler.

## Quick start

Needs Go 1.27 or newer.

```sh
make dev                     # http://127.0.0.1:8100, edits to web/ show on refresh
```

The first visit goes to `/setup` to create the first user admin. It runs on
port 8100, so the tracker (8080) and planner (8090) can run alongside it.

## Features

| Area | What it does |
|------|--------------|
| My apps | After signing in, a tile for each app you can use. |
| My account | Change your password (which signs you out everywhere else), see your apps, and see where you're signed in, with sign-out for any other device. |
| Users | User admins add people, edit their username, name and email, reset passwords, and turn accounts off and back on. Nothing is deleted, so the apps keep their history. The list shows everyone's access to each app; each person's page sets it (role, suspended, locked) and shows their recent activity. |
| Apps | Register an app (client ID, redirect URIs, roles). Its client secret is shown once; make a new one any time. |
| Single sign-on | OAuth 2 authorization code flow with PKCE: `/authorize`, `/token`, and grant checks at `/api/v1/grant`. App admins change roles and suspend people from inside their app through `/api/v1/apps/{client_id}/users`. See PLAN.md for the details the apps need. |
| Audit log | Sign-ins, failed attempts and every change to an account, filterable by person. |
| Settings | Site name and a database backup download. |
| Sign-in | Passwords are bcrypt hashes; session tokens are stored only as SHA-256 hashes. Sessions last 30 days from last use. Sign-in attempts are limited per address and per username. |
| Offline | Installable as an app. No pages are kept offline, since account pages shouldn't linger on a device. |

Not built yet (see PLAN.md's build order): the apps' side of sign-in and the
Ansible deployment.

## Configuration

Set with a flag or an environment variable. Flags go **before** any command.

| Env var | Flag | Default | |
|---|---|---|---|
| `ADDR` | `-addr` | `:8100` | Listen address |
| `DB_PATH` | `-db` | `data/users.db` | SQLite file. Created, with migrations applied, on start. |
| `TZ` | | system | Time zone for times shown on pages |
| `TRUST_PROXY=1` | `-trust-proxy` | off | Trust `X-Forwarded-For/Proto` from a reverse proxy. Only when a proxy is the only way in. |
| `DEV=1` | `-dev` | off | Load templates/static from `./web` on disk. Restart after changing CSS or JS: the asset version (and so the service worker's cache) is worked out at start. |

## Commands

```sh
user-management create-user alice [--admin]   # prompts for a password (10–72 characters)
user-management reset-password alice          # also signs alice out everywhere
user-management backup /path/to/copy.db
user-management import-users \
    --tracker /var/lib/.../maintenance.db --tracker-url https://maintenance.example.org \
    --planner /var/lib/production-planner/productions.db --planner-url https://planner.example.org \
    [--prefer tracker|planner] [--dry-run]
```

The first user created is always a user admin.

`import-users` copies people from the tracker's and planner's own users
tables (opened read-only; either can be left out). People are matched by
username, ignoring case, and keep their current password (the bcrypt hash is
copied). Each gets `admin` or `user` access to the apps they were in, from
their `is_admin`. If someone's passwords differ between the apps, the one
from the app they used most recently is kept, unless `--prefer` says
otherwise; the choice is printed. The apps are registered as `tracker` and
`planner` (redirect URI `<url>/auth/callback`, roles `user, admin`) if they
aren't already, and their `SSO_CLIENT_ID` / `SSO_CLIENT_SECRET` are printed
once. The `-url` flags are only needed for an app that isn't registered yet.
If this service has no users yet, one imported admin becomes a user admin
here (an admin of both apps first, then alphabetically). Running it again is
safe: people already here are left alone apart from getting access to an app
they don't have yet, and registered apps keep their secrets.
`import-users -h` has the details.

## Tests

```sh
make test
```
