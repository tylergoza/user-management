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

Not built yet (see PLAN.md's build order): the SSO settings in the tracker's
and planner's own deploys, and the rollout.

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

## Deploying

The app is one binary plus one `.db` file, behind [Caddy](https://caddyserver.com)
for HTTPS. `deploy/` has the systemd unit and a Caddyfile for doing it by
hand. Follow the comments at the top of `deploy/user-management.service`.

### DigitalOcean with Ansible

`deploy/ansible/` works like the planner's and puts User Management **on the
maintenance tracker's droplet**: it finds it by the tracker's tag
(`maintenance-tracker`) and adds itself alongside, on 127.0.0.1:8100 with its
own service user (`accounts`), data folder (`/var/lib/user-management`) and
Caddy site (`/etc/caddy/sites/user-management.caddy`). The main Caddyfile it
writes is the same as the tracker's and planner's. Provision adds the DNS
record for `accounts.<dns_zone>` and the service user; it only creates a
droplet if nothing carries the tag. Deploy runs the tests, builds the Linux
binary here, backs up the database when the binary changes (keeping 10),
installs, and checks `/healthz`.

While there are no users, deploy installs the app but leaves it stopped, so
`/setup` is never open to the internet: the import below starts it. For a
fresh start with no import, set `admin_username` in `vars.yml` and the first
deploy creates that user admin instead (`UM_ADMIN_PASSWORD`, or a random one
printed at the end). Don't do that before importing: an existing `admin` here
would be left alone by the import, keeping the new password.

Run the playbooks from `deploy/ansible/`. Rolling out single sign-on, in
order:

```sh
cd deploy/ansible
cp vars.example.yml vars.yml       # set dns_zone, tracker_url, planner_url
export DIGITALOCEAN_TOKEN=...

# 1. DNS record for accounts.<dns_zone>, service user, then a first deploy
ansible-playbook provision.yml
# 2. Later updates (make deploy from the repo root does the same)
ansible-playbook deploy.yml
# 3. Back up all three databases, here and under deploy/ansible/backups/
ansible-playbook backup.yml
# 4. Dry run: shows who'd be created and which password is kept
ansible-playbook import-users.yml                     # add -e prefer=tracker|planner to pick
# 5. For real: backs up users.db, imports, registers both apps, starts the app
ansible-playbook import-users.yml -e dry_run=false
export UM_PLANNER_SECRET=...       # the planner's SSO_CLIENT_SECRET from step 5
export UM_TRACKER_SECRET=...       # the tracker's
# 6. Then the planner, then the tracker, each from its own repo's
#    deploy/ansible with its SSO settings (SSO_URL=https://accounts.<domain>,
#    SSO_INTERNAL_URL=http://127.0.0.1:8100, SSO_CLIENT_ID planner/tracker,
#    the secret from the variable above). Test each from an installed PWA.
```

`import-users.yml` copies the tracker's and planner's databases with their
own `backup` commands into a temporary folder only this app's service user
can read, runs `import-users` on the copies, and always removes them. The
client secrets are shown once, on your terminal only; the play refuses a
real run while Ansible is set to write a log file. Keep them somewhere safe
(a password manager) and export them before deploying the apps. Running it
again is safe; apps already registered keep their secrets.

`backup.yml` can be run any time: it skips apps that aren't installed, leaves
`manual-<time>.db` in each app's backups folder on the droplet, and copies
them to `deploy/ansible/backups/<time>/` (gitignored; they hold password
hashes).

### Moving between hosts

**Settings → Download backup** (or the `backup` command), stop the app on the
new host, copy the file to its database path
(`/var/lib/user-management/users.db`, owned by `accounts`), and start it.
Droplet backups cover all three apps when they share a droplet.

## Tests

```sh
make test
```
