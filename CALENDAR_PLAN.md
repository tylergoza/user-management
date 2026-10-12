# User Management: adding the Church Calendar

The design is in `../calendar/PLAN.md`. The calendar signs in the same way
as the event planner: client `calendar`, roles `member`, `scheduler`,
`admin`.

Status: planned, nothing built yet (2026-10-11).

## Steps

- [ ] Add `calendar` to `sso_apps` in `deploy/ansible/defaults.yml` (binary `/usr/local/bin/church-calendar`, data `/var/lib/church-calendar/calendar.db`, Keychain service `um-calendar`)
- [ ] `with-um` in `~/.zshrc` also exports `UM_CALENDAR_SECRET` from `um-calendar` (the user edits this; just say what to add)
- [ ] Add the calendar to the README's app list and the port list in `.claude/CLAUDE.md` (8120)
- [ ] Set `calendar_url` in `vars.yml`, then `with-do make register-app APP=calendar` (dry run) and `DRY_RUN=false` with `--roles member,scheduler,admin`
- [ ] Or do it in the app instead: register on the Apps page and paste into the calendar's **Connections → Single sign-on** (see `CONNECTIONS_PLAN.md`)
- [ ] Give access: everyone with event planner access gets `member` (`--copy-access-from events` then adjust), the office staff get `scheduler`
