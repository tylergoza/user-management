# Connections as admin settings: User Management's part

The design is in `../event_planning/CONNECTIONS_PLAN.md`. User Management
has no outgoing connections; it's what the apps' **Single sign-on**
connection points at. Its part is making the in-app path work without the
command line.

Status: planned, nothing built yet (2026-10-11).

## The in-app way to connect an app

As well as `make register-app` + Keychain + Ansible (which keeps working):

1. In User Management, **Apps → Register** (client ID, the app's address,
   roles). The secret is shown once.
2. In the app, **Connections → Single sign-on**: paste User Management's
   address, the client ID and secret, **Save**, then **Test sign-in**.

## Steps

- [ ] A server-to-server check the apps can call with their client ID and secret before the sign-in test (e.g. `POST /api/v1/client-check`, Basic auth with client ID/secret, answers 204 or 401). Check first whether `/token` or `/api/v1/grant` can already answer this without a new endpoint; prefer that
- [ ] Apps page: after registering or making a new secret, show the three values the app's Connections page asks for (address, client ID, secret) together with a copy button each
- [ ] README: the in-app way above, next to `register-app`
