package server

import (
	"net/url"
	"strings"
	"testing"

	"github.com/tylergoza/user-management/internal/store"
)

// optIn sets an app's per-app token lists.
func optIn(t *testing.T, st *store.Store, a *testApp, actsIn, acceptsFrom []string) {
	t.Helper()
	app, err := st.GetApp(a.id)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAppDelegation(a.id, actsIn, acceptsFrom, app.DefaultRole); err != nil {
		t.Fatal(err)
	}
}

func (a *testApp) delegate(grant, audience string) (int, map[string]any) {
	a.t.Helper()
	return a.call("POST", "/api/v1/delegate", strings.NewReader(`{"audience":"`+audience+`"}`), "application/json", "X-Grant", grant)
}

func (a *testApp) checkToken(token string) (int, map[string]any) {
	a.t.Helper()
	return a.call("GET", "/api/v1/token", nil, "", "X-Token", token)
}

func (a *testApp) meApps(grant string) (int, map[string]any) {
	a.t.Helper()
	return a.call("GET", "/api/v1/me/apps", nil, "", "X-Grant", grant)
}

// delegationSetup: sam is signed in to the MCP server (client mcp), which
// may act in the calendar and the directory, and both accept it. Sam has a
// role in the calendar but not the directory. The events app accepts mcp
// but mcp doesn't list it; sam has a role there too.
type delegationEnv struct {
	admin, sam                       *client
	st                               *store.Store
	mcp, calendar, directory, events *testApp
	grant                            string
}

func delegationSetup(t *testing.T) *delegationEnv {
	t.Helper()
	admin, st := setup(t)
	addUser(admin, "sam", false)
	e := &delegationEnv{admin: admin, st: st,
		mcp: registerApp(t, admin, st, "mcp"), calendar: registerApp(t, admin, st, "calendar"),
		directory: registerApp(t, admin, st, "directory"), events: registerApp(t, admin, st, "events")}
	optIn(t, st, e.mcp, []string{"calendar", "directory"}, nil)
	optIn(t, st, e.calendar, nil, []string{"mcp"})
	optIn(t, st, e.directory, nil, []string{"mcp"})
	optIn(t, st, e.events, nil, []string{"mcp"})
	grantAccess(t, st, "sam", e.mcp, "user")
	grantAccess(t, st, "sam", e.calendar, "user")
	grantAccess(t, st, "sam", e.events, "admin")
	e.sam = admin.another()
	e.sam.login("sam", "member password", 200)
	e.grant = e.mcp.signIn(e.sam)
	return e
}

func (e *delegationEnv) token(t *testing.T) string {
	t.Helper()
	status, body := e.mcp.delegate(e.grant, "calendar")
	if status != 200 {
		t.Fatalf("delegate: %d %v", status, body)
	}
	return body["token"].(string)
}

func wantInvalidToken(t *testing.T, what string, status int, body map[string]any) {
	t.Helper()
	if status != 401 || body["error"] != "invalid_token" {
		t.Errorf("%s: %d %v, want 401 invalid_token", what, status, body)
	}
}

func TestDelegateRoundTrip(t *testing.T) {
	e := delegationSetup(t)

	status, body := e.mcp.delegate(e.grant, "calendar")
	if status != 200 || body["expires_in"] != float64(900) || body["role"] != "user" {
		t.Fatalf("delegate: %d %v", status, body)
	}
	token := body["token"].(string)
	if !strings.HasPrefix(token, "umd_") {
		t.Errorf("token should start umd_: %q", token)
	}
	var stored int
	e.st.DB.QueryRow(`SELECT COUNT(*) FROM delegated_tokens WHERE token_hash = ?`, store.HashToken(token)).Scan(&stored)
	var plain int
	e.st.DB.QueryRow(`SELECT COUNT(*) FROM delegated_tokens WHERE token_hash = ?`, token).Scan(&plain)
	if stored != 1 || plain != 0 {
		t.Error("only the token's hash should be stored")
	}

	// The token check doesn't count as using the grant.
	e.st.DB.Exec(`UPDATE grants SET last_checked_at = '2000-01-01 00:00:00'`)
	status, body = e.calendar.checkToken(token)
	if status != 200 || body["via"] != "mcp" {
		t.Fatalf("token check: %d %v", status, body)
	}
	user := body["user"].(map[string]any)
	if user["username"] != "sam" || user["role"] != "user" || user["sub"] != userID(t, e.st, "sam") {
		t.Errorf("user: %v", user)
	}
	var checked string
	e.st.DB.QueryRow(`SELECT last_checked_at FROM grants`).Scan(&checked)
	if checked != "2000-01-01 00:00:00" {
		t.Errorf("a token check moved the grant's last_checked_at to %s", checked)
	}

	// Asking again works and is one audit entry an hour, not one a call.
	e.token(t)
	entries, _ := e.st.ListAudit(store.AuditFilter{UserID: 0, Limit: 50})
	n := 0
	for _, en := range entries {
		if en.Action == "token.delegate" {
			n++
			if en.Detail != "via mcp" || en.AppName != "Calendar" || en.ActorName != "sam" {
				t.Errorf("audit entry: %+v", en)
			}
		}
	}
	if n != 1 {
		t.Errorf("token.delegate entries: %d, want 1", n)
	}
}

func TestDelegateRefusals(t *testing.T) {
	e := delegationSetup(t)

	// Person with no role in the audience.
	if status, body := e.mcp.delegate(e.grant, "directory"); status != 403 || body["error"] != "no_access" {
		t.Errorf("no role: %d %v", status, body)
	}
	// The caller doesn't list the audience in acts_in (events accepts mcp).
	if status, body := e.mcp.delegate(e.grant, "events"); status != 403 || body["error"] != "not_accepted" {
		t.Errorf("not in acts_in: %d %v", status, body)
	}
	// The audience doesn't accept the caller.
	optIn(t, e.st, e.calendar, nil, nil)
	if status, body := e.mcp.delegate(e.grant, "calendar"); status != 403 || body["error"] != "not_accepted" {
		t.Errorf("audience doesn't accept mcp: %d %v", status, body)
	}
	optIn(t, e.st, e.calendar, nil, []string{"mcp"})
	// A caller with no acts_in at all, with its own good grant.
	planner := registerApp(t, e.admin, e.st, "planner")
	grantAccess(t, e.st, "sam", planner, "user")
	optIn(t, e.st, e.calendar, nil, []string{"mcp", "planner"})
	plannerGrant := planner.signIn(e.sam)
	if status, body := planner.delegate(plannerGrant, "calendar"); status != 403 || body["error"] != "not_accepted" {
		t.Errorf("caller without acts_in: %d %v", status, body)
	}
	// Itself.
	if status, body := e.mcp.delegate(e.grant, "mcp"); status != 403 || body["error"] != "not_accepted" {
		t.Errorf("itself: %d %v", status, body)
	}
	// A grant that belongs to another app.
	if status, body := e.mcp.delegate(plannerGrant, "calendar"); status != 401 || body["error"] != "invalid_grant" {
		t.Errorf("another app's grant: %d %v", status, body)
	}
	if status, body := e.mcp.delegate("made-up", "calendar"); status != 401 || body["error"] != "invalid_grant" {
		t.Errorf("made-up grant: %d %v", status, body)
	}
	if status, body := e.mcp.delegate(e.grant, "nobody"); status != 404 || body["error"] != "unknown_audience" {
		t.Errorf("unknown audience: %d %v", status, body)
	}
	if status, body := e.mcp.call("POST", "/api/v1/delegate", strings.NewReader(`{}`), "application/json", "X-Grant", e.grant); status != 400 || body["error"] != "invalid_request" {
		t.Errorf("no audience: %d %v", status, body)
	}
	// Wrong secret.
	bad := *e.mcp
	bad.secret = "um_wrong"
	if status, body := bad.delegate(e.grant, "calendar"); status != 401 || body["error"] != "invalid_client" {
		t.Errorf("wrong secret: %d %v", status, body)
	}
}

func TestDelegatedTokenRefusals(t *testing.T) {
	e := delegationSetup(t)
	token := e.token(t)

	// Wrong audience: the directory (which also accepts mcp) and the
	// acting app itself can't use the calendar's token.
	status, body := e.directory.checkToken(token)
	wantInvalidToken(t, "another app", status, body)
	status, body = e.mcp.checkToken(token)
	wantInvalidToken(t, "the acting app", status, body)
	status, body = e.calendar.checkToken("umd_made-up")
	wantInvalidToken(t, "made-up token", status, body)
	status, body = e.calendar.checkToken("")
	wantInvalidToken(t, "no token", status, body)
	bad := *e.calendar
	bad.secret = "um_wrong"
	if status, body := bad.checkToken(token); status != 401 || body["error"] != "invalid_client" {
		t.Errorf("wrong secret: %d %v", status, body)
	}

	// Expired.
	e.st.DB.Exec(`UPDATE delegated_tokens SET expires_at = '2000-01-01 00:00:00' WHERE token_hash = ?`, store.HashToken(token))
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "expired", status, body)
	if err := e.st.PurgeExpired(); err != nil {
		t.Fatal(err)
	}
	var left int
	e.st.DB.QueryRow(`SELECT COUNT(*) FROM delegated_tokens WHERE token_hash = ?`, store.HashToken(token)).Scan(&left)
	if left != 0 {
		t.Error("PurgeExpired should delete expired tokens")
	}

	// An opt-in taken back after the token was made.
	token = e.token(t)
	optIn(t, e.st, e.calendar, nil, nil)
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "audience stopped accepting", status, body)
	optIn(t, e.st, e.calendar, nil, []string{"mcp"})
	optIn(t, e.st, e.mcp, []string{"directory"}, nil)
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "caller stopped acting in", status, body)
	optIn(t, e.st, e.mcp, []string{"calendar", "directory"}, nil)
	if status, body := e.calendar.checkToken(token); status != 200 {
		t.Fatalf("opt-ins back: %d %v", status, body)
	}

	// Role suspended or removed in the audience, or in the acting app.
	sam, _ := e.st.GetUserByUsername("sam")
	e.st.SetAccess(sam.ID, e.calendar.id, "user", true, false, 0)
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "suspended", status, body)
	e.st.SetAccess(sam.ID, e.calendar.id, "", false, false, 0)
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "role removed", status, body)
	e.st.SetAccess(sam.ID, e.calendar.id, "admin", false, false, 0)
	if status, body := e.calendar.checkToken(token); status != 200 || body["user"].(map[string]any)["role"] != "admin" {
		t.Fatalf("role back, as admin now: %d %v", status, body)
	}
	e.st.SetAccess(sam.ID, e.mcp.id, "user", true, false, 0)
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "suspended in the acting app", status, body)
	e.st.SetAccess(sam.ID, e.mcp.id, "user", false, false, 0)

	// The grant deleted on its own: the token goes with it.
	e.st.DB.Exec(`DELETE FROM grants WHERE id_hash = ?`, store.HashToken(e.grant))
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "grant deleted", status, body)
	e.st.DB.QueryRow(`SELECT COUNT(*) FROM delegated_tokens`).Scan(&left)
	if left != 0 {
		t.Errorf("deleting the grant should delete its tokens, %d left", left)
	}
}

func TestDelegatedTokenAfterSignOut(t *testing.T) {
	e := delegationSetup(t)
	token := e.token(t)
	if status, _ := e.mcp.call("POST", "/api/v1/logout", nil, "", "X-Grant", e.grant); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	status, body := e.calendar.checkToken(token)
	wantInvalidToken(t, "after sign-out", status, body)
	if status, body := e.mcp.meApps(e.grant); status != 401 || body["error"] != "invalid_grant" {
		t.Errorf("me/apps after sign-out: %d %v", status, body)
	}
	if status, body := e.mcp.delegate(e.grant, "calendar"); status != 401 || body["error"] != "invalid_grant" {
		t.Errorf("delegate after sign-out: %d %v", status, body)
	}

	// Turning the account off ends it too.
	e.sam.login("sam", "member password", 200)
	e.grant = e.mcp.signIn(e.sam)
	token = e.token(t)
	sam, _ := e.st.GetUserByUsername("sam")
	e.st.SetDisabled(sam.ID, true)
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "account off", status, body)
}

func TestMeApps(t *testing.T) {
	e := delegationSetup(t)
	// Directory: no role. Events: role, but mcp doesn't act in it.
	// Planner: role, mcp acts in it, but it doesn't accept mcp.
	planner := registerApp(t, e.admin, e.st, "planner")
	grantAccess(t, e.st, "sam", planner, "user")
	optIn(t, e.st, e.mcp, []string{"calendar", "directory", "planner"}, nil)
	status, body := e.mcp.meApps(e.grant)
	if status != 200 {
		t.Fatalf("me/apps: %d %v", status, body)
	}
	apps := body["apps"].([]any)
	if len(apps) != 1 {
		t.Fatalf("want only the calendar: %v", apps)
	}
	a := apps[0].(map[string]any)
	if a["audience"] != "calendar" || a["name"] != "Calendar" || a["role"] != "user" || a["url"] != "https://calendar.test" {
		t.Errorf("calendar entry: %v", a)
	}

	// A suspended role is left out; the list can be empty, never null.
	sam, _ := e.st.GetUserByUsername("sam")
	e.st.SetAccess(sam.ID, e.calendar.id, "user", true, false, 0)
	if status, body := e.mcp.meApps(e.grant); status != 200 || len(body["apps"].([]any)) != 0 {
		t.Errorf("suspended: %d %v", status, body)
	}
	if status, body := e.mcp.meApps("made-up"); status != 401 || body["error"] != "invalid_grant" {
		t.Errorf("bad grant: %d %v", status, body)
	}
}

func TestAppFormDelegation(t *testing.T) {
	admin, st := setup(t)
	registerApp(t, admin, st, "calendar")
	mcp := registerApp(t, admin, st, "mcp")
	path := "/admin/apps/" + itoa(mcp.id)
	form := func(actsIn []string, def string) url.Values {
		return url.Values{"name": {"MCP"}, "redirect_uris": {mcp.callback}, "roles": {"user, admin"},
			"acts_in": actsIn, "accepts_from": {"calendar"}, "default_role": {def}}
	}
	body := admin.post(path, path, form([]string{"mcp", "nobody"}, "admin"), 422)
	for _, want := range []string{"&#34;mcp&#34; isn&#39;t another registered app", "&#34;nobody&#34; isn&#39;t another registered app", "can&#39;t get admin by default"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing error %q", want)
		}
	}
	if body := admin.post(path, path, form(nil, "editor"), 422); !strings.Contains(body, "must be one of the app&#39;s roles") {
		t.Error("expected the default role to be checked against the roles")
	}
	admin.post(path, path, form([]string{"calendar"}, "user"), 200)
	a, _ := st.GetApp(mcp.id)
	if strings.Join(a.ActsIn, ",") != "calendar" || strings.Join(a.AcceptsFrom, ",") != "calendar" || a.DefaultRole != "user" {
		t.Errorf("saved app: %+v", a)
	}
	if body := admin.get(path, 200); !strings.Contains(body, `name="acts_in" value="calendar" checked`) || !strings.Contains(body, `<option value="user" selected>`) {
		t.Error("the form should show the saved settings")
	}
	entries, _ := st.ListAudit(store.AuditFilter{Limit: 1})
	if entries[0].Action != "app.update" || !strings.Contains(entries[0].Detail, "may act for users in calendar") ||
		!strings.Contains(entries[0].Detail, "accepts tokens from calendar") || !strings.Contains(entries[0].Detail, `new users get (none) → "user"`) {
		t.Errorf("audit: %+v", entries[0])
	}
	// Removing the default role from the roles is refused.
	f := form([]string{"calendar"}, "user")
	f.Set("roles", "member, admin")
	if body := admin.post(path, path, f, 422); !strings.Contains(body, "must be one of the app&#39;s roles") {
		t.Error("expected removing the default role to be refused")
	}
}

func TestDefaultRoleOnNewUser(t *testing.T) {
	admin, st := setup(t)
	calendar := registerApp(t, admin, st, "calendar")
	website := registerApp(t, admin, st, "website")
	planner := registerApp(t, admin, st, "planner")
	st.SetAppDelegation(calendar.id, nil, nil, "user")
	st.SetAppDelegation(website.id, nil, nil, "user")

	if body := admin.get("/admin/users/new", 200); !strings.Contains(body, "They will get: Calendar: user, Website: user.") {
		t.Errorf("the form should say what a new user gets:\n%s", body)
	}
	addUser(admin, "sam", false)
	sam, _ := st.GetUserByUsername("sam")
	for _, c := range []struct {
		app  *testApp
		want string
	}{{calendar, "user"}, {website, "user"}, {planner, ""}} {
		a, err := st.GetAccess(sam.ID, c.app.id)
		got := ""
		if err == nil {
			got = a.Role
		}
		if got != c.want {
			t.Errorf("%s: role %q, want %q", c.app.clientID, got, c.want)
		}
	}
	entries, _ := st.ListAudit(store.AuditFilter{Limit: 1})
	if entries[0].Action != "user.create" || entries[0].Detail != "default roles Calendar: user, Website: user" {
		t.Errorf("audit: %+v", entries[0])
	}
	// The first-run admin got nothing, and changing a default later
	// doesn't touch people who already exist.
	adminUser, _ := st.GetUserByUsername("admin")
	if a, err := st.GetAccess(adminUser.ID, calendar.id); err == nil {
		t.Errorf("setup user got a default role: %+v", a)
	}
	st.SetAppDelegation(planner.id, nil, nil, "user")
	if _, err := st.GetAccess(sam.ID, planner.id); err == nil {
		t.Error("a new default shouldn't reach existing people")
	}
}
