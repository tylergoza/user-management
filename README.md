# Church User Management

One place for the church's user accounts. People get one username and
password for every church app, and user admins decide who can use which app.
The [maintenance tracker](../maintenance_tracking) and the
[production planner](../production_planning) sign people in through it, and so
does the [event planner](../event_planning).
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
port 8100, so the tracker (8080), planner (8090) and event planner (8110) can run alongside it.

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
user-management register-app events --name "Event Planner" --url https://events.example.org \
    [--roles user,admin] [--rename-role old=new] [--copy-access-from planner] [--rotate-secret] [--dry-run]
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

`register-app` registers one app from the command line, like the Apps page
(redirect URI `<url>/auth/callback`, address `<url>`, roles default to
`user,admin` and must include `admin`). A new app's `SSO_CLIENT_ID` and
`SSO_CLIENT_SECRET` are printed once. If the client ID is already registered
nothing about the app changes (unless `--roles` or `--rename-role` is given),
no secret is printed, and it's safe to re-run.
`--roles a,b,admin` on an app that's already registered replaces its roles
list (in that order, audit-logged like an edit on the Apps page). Adding roles
is always fine; removing a role people still have is refused. Without
`--roles` an existing app's roles are never touched.
`--rename-role old=new` (repeatable) moves everyone with role `old` in that
app to `new` (each change is audit-logged) and swaps `old` for `new` in its
roles list, in one transaction with `--roles`: the rename happens first, then
the check. Running it again does nothing. `--dry-run` prints the counts.
`--rotate-secret` makes a new secret for an app that's already registered
(the same as "make a new one" on the Apps page, and audit-logged the same way)
and prints it once; the old secret stops working at once, so the app can't
sign anyone in until it's redeployed with the new one. For an app that isn't
registered yet it does nothing extra (a new app gets a secret anyway).
`--copy-access-from planner` gives everyone with access to that app the same
role in the new one, only where they have no row yet (a role the new app
doesn't have becomes `user` if the new app has that role, else its first role
other than `admin`; suspended access stays suspended; existing rows
are never touched). Each grant goes in the audit log, and a count is printed.
`--dry-run` changes nothing. `register-app -h` has the details.

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

Run these from the repo root (`with-do` or any way of setting
`DIGITALOCEAN_TOKEN`). Rolling out single sign-on, in order:

```sh
cp deploy/ansible/vars.example.yml deploy/ansible/vars.yml   # set dns_zone, tracker_url, planner_url
export DIGITALOCEAN_TOKEN=...

# 1. DNS record for accounts.<dns_zone>, service user, then a first deploy
make provision
# 2. Later updates
make deploy
# 3. Back up every app's database, here and under deploy/ansible/backups/
make backup
# 4. Dry run: shows who'd be created and which password is kept
make import-users                        # add PREFER=tracker|planner to pick
# 5. For real: backs up users.db, imports, registers both apps, starts the app
make import-users DRY_RUN=false
export UM_PLANNER_SECRET=...             # the planner's SSO_CLIENT_SECRET from step 5
export UM_TRACKER_SECRET=...             # the tracker's
# 6. Then the planner, then the tracker: set sso_url (https://accounts.<domain>)
#    and base_url (the app's own address) in its deploy/ansible/vars.yml and
#    `make deploy` from its repo. Test each from an installed PWA.
```

#### Adding the event planner (and rotating any app's secret)

The event planner (`../event_planning`) runs on 127.0.0.1:8110 as user
`events` (`/usr/local/bin/event-planner`, `/var/lib/event-planner/events.db`),
and signs in as client `events`. Set `events_url` in `vars.yml`, then:

```sh
with-do make register-app APP=events                            # dry run, the event planner
with-do make register-app APP=events DRY_RUN=false              # register it; secret saved as um-events
with-do make register-app APP=planner DRY_RUN=false ROTATE=true # new planner secret, saved over um-planner
with-do make register-app APP=tracker DRY_RUN=false ROTATE=true
# then, at once, in the app's repo (../event_planning, ../production_planning, ../maintenance_tracking):
with-do with-um make deploy
# (with sso_url https://accounts.<domain> and base_url, its own address, set.)
```

The event planner has three roles: `helper`, `planner` and `admin`. Planners
create events but can't manage users; helpers help on events but can't create
them; admins do both and manage people. Its `sso_apps` entry sets
`roles: helper,planner,admin` and `rename_roles: ["user=helper"]`, so the dry
run above shows the change and `DRY_RUN=false` updates its roles to helper,
planner, admin and moves everyone who has `user` to `helper` (an app that is
already registered keeps its secret).

`APP` is a key of `sso_apps` in `deploy/ansible/defaults.yml` (`events`,
`planner`, `tracker`); each entry holds the app's name, address (`events_url`,
`planner_url`, `tracker_url` in `vars.yml`), Keychain service, secret variable
and who it copies access from. A new app is one entry there plus one line in
your `with-um`. The planner and tracker were registered by `import-users`, so
without `ROTATE=true` their run changes nothing (they copy access from no one
by default). Everyone with access to the planner gets the same access to the
event planner (`copy_access_from: planner` in its entry; override with
`-e copy_access_from=other`, or `-e copy_access_from=` to copy nobody). Like
`import-users`, a real run backs up `users.db` first and refuses to run while
Ansible writes a log file. Running it again is safe.

When a real run makes a secret (a new app, or `ROTATE=true`) on a Mac, it is
saved to your login Keychain under the app's service (`um-events`,
`um-planner`, `um-tracker`; `-U` updates the old item) and not shown. It goes
to `security -i` on stdin, so it is never in a command line, and every task
that touches it has `no_log`. `with-um` (in your `~/.zshrc`) must export
`UM_EVENTS_SECRET`, `UM_PLANNER_SECRET` and `UM_TRACKER_SECRET` from those
services. Use `KEYCHAIN=other-name`, or `KEYCHAIN=` to print the secret
instead (also what happens on a non-Mac or if the save fails: save it then, it
isn't shown again). `ROTATE=true` invalidates the old secret at once, so the
app can't sign anyone in until it's redeployed with the new one: run
`with-do with-um make deploy` in its repo straight away.

If a third-party apt repo is down (Caddy's has returned 402), provision
skips the system updates with a warning and carries on; Caddy is only
installed from it on a new droplet.

`import-users.yml` copies the tracker's and planner's databases with their
own `backup` commands into a temporary folder only this app's service user
can read, runs `import-users` on the copies, and always removes them. The
client secrets are shown once, on your terminal only; the play refuses a
real run while Ansible is set to write a log file. Keep them somewhere safe
(a password manager) and export them before deploying the apps. Running it
again is safe; apps already registered keep their secrets.

`backup.yml` (all four apps) can be run any time: it skips apps that aren't installed, leaves
`manual-<time>.db` in each app's backups folder on the droplet, and copies
them to `deploy/ansible/backups/<time>/` (gitignored; they hold password
hashes).

### Moving between hosts

**Settings → Download backup** (or the `backup` command), stop the app on the
new host, copy the file to its database path
(`/var/lib/user-management/users.db`, owned by `accounts`), and start it.
Droplet backups cover all the apps when they share a droplet.

## Tests

```sh
make test
```
