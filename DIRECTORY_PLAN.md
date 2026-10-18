# User Management: adding the Member Directory

The design is in `../member_directory/PLAN.md`. The directory signs in the
same way as the calendar: client `directory`, roles `member`, `editor`,
`admin`.

No API changes are needed. The directory uses what's already here:

- `GET /api/v1/apps/directory/users` for its **Link to user** picker.
- `PATCH /api/v1/apps/directory/users/{id}` with `{"suspended": true}`
  and the staff member's `X-Acting-Grant` when it finds that a linked user
  is under 13. Turning off or deleting their whole account stays a manual
  decision here.

Profiles (people, households, notes) never come to this service.

Status: planned (2026-10-14). Do this when the directory reaches its SSO
step (step 11).

## Steps

- [ ] Add `directory` to `sso_apps` in `deploy/ansible/defaults.yml` (binary `/usr/local/bin/church-directory`, data `/var/lib/church-directory/directory.db`, Keychain service `um-directory`); also in `backup.yml`
- [ ] `with-um` in `~/.zshrc` also exports `UM_DIRECTORY_SECRET` from `um-directory` (the user edits this; just say what to add)
- [ ] Add the directory to the README's app list and the port list in `.claude/CLAUDE.md` (8130)
- [ ] Set `directory_url` in `vars.yml`, then `with-do make register-app APP=directory` (dry run) and `DRY_RUN=false` with `--roles member,editor,admin`
- [ ] Or do it in the app instead: register on the Apps page and paste into the directory's **Connections → Single sign-on** (see `CONNECTIONS_PLAN.md`)
- [ ] Give access: everyone with event planner access gets `member` (`--copy-access-from events` then adjust), the office staff get `editor`
