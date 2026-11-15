package server

import (
	"net/url"
	"strings"
	"testing"
)

func (a *testApp) makeAIGrant(sessionGrant string) (int, map[string]any) {
	a.t.Helper()
	return a.call("POST", "/api/v1/ai-grants", nil, "", "X-Grant", sessionGrant)
}

func (a *testApp) revokeAIGrant(grant string) (int, map[string]any) {
	a.t.Helper()
	return a.call("DELETE", "/api/v1/ai-grants", nil, "", "X-Grant", grant)
}

func (e *delegationEnv) aiGrant(t *testing.T) string {
	t.Helper()
	status, body := e.mcp.makeAIGrant(e.grant)
	if status != 200 {
		t.Fatalf("ai grant: %d %v", status, body)
	}
	g := body["grant"].(string)
	if !strings.HasPrefix(g, "umai_") {
		t.Fatalf("grant should start umai_: %q", g)
	}
	return g
}

func TestAIGrantSurvivesSignOut(t *testing.T) {
	e := delegationSetup(t)
	ai := e.aiGrant(t)

	var plain int
	e.st.DB.QueryRow(`SELECT COUNT(*) FROM ai_grants WHERE id_hash = ?`, ai).Scan(&plain)
	if plain != 0 {
		t.Error("only the hash should be stored")
	}
	if status, body := e.mcp.check(ai); status != 200 || body["user"].(map[string]any)["username"] != "sam" {
		t.Fatalf("check: %d %v", status, body)
	}
	if status, body := e.mcp.meApps(ai); status != 200 || len(body["apps"].([]any)) != 1 {
		t.Fatalf("me/apps: %d %v", status, body)
	}
	status, body := e.mcp.delegate(ai, "calendar")
	if status != 200 {
		t.Fatalf("delegate: %d %v", status, body)
	}
	token := body["token"].(string)

	// Signing out of the browser ends the session grant, not the AI one,
	// and a token made from the AI grant keeps working.
	e.sam.post("/", "/logout", url.Values{}, 200)
	if status, _ := e.mcp.check(e.grant); status != 401 {
		t.Errorf("session grant after sign-out: %d", status)
	}
	if status, _ := e.mcp.check(ai); status != 200 {
		t.Errorf("ai grant after sign-out: %d", status)
	}
	if status, body := e.calendar.checkToken(token); status != 200 || body["via"] != "mcp" {
		t.Errorf("token after sign-out: %d %v", status, body)
	}
	if status, _ := e.mcp.delegate(ai, "calendar"); status != 200 {
		t.Errorf("delegate after sign-out: %d", status)
	}

	// Another app can't use it.
	if status, _ := e.calendar.check(ai); status != 401 {
		t.Errorf("another app's check: %d", status)
	}
}

func TestAIGrantEnds(t *testing.T) {
	e := delegationSetup(t)
	id := userID(t, e.st, "sam")

	ends := func(what string, ai string) {
		t.Helper()
		if status, body := e.mcp.check(ai); status != 401 {
			t.Errorf("%s: grant still good: %d %v", what, status, body)
		}
		if status, _ := e.mcp.delegate(ai, "calendar"); status != 401 {
			t.Errorf("%s: delegate: %d", what, status)
		}
	}

	// Password reset.
	ai := e.aiGrant(t)
	token := func() string { _, b := e.mcp.delegate(ai, "calendar"); return b["token"].(string) }()
	e.admin.post("/admin/users/"+id, "/admin/users/"+id, url.Values{
		"username": {"sam"}, "password": {"a new password"}, "password_confirm": {"a new password"},
	}, 200)
	ends("password reset", ai)
	status, body := e.calendar.checkToken(token)
	wantInvalidToken(t, "token after password reset", status, body)

	// Account disabled.
	e.sam.login("sam", "a new password", 200)
	e.grant = e.mcp.signIn(e.sam)
	ai = e.aiGrant(t)
	e.admin.post("/admin/users/"+id, "/admin/users/"+id+"/disable", url.Values{}, 200)
	ends("disabled", ai)
	e.admin.post("/admin/users/"+id, "/admin/users/"+id+"/enable", url.Values{}, 200)
	ends("re-enabled (grant stays gone)", ai)

	// Losing the role in the mcp app, and suspension.
	e.sam.login("sam", "a new password", 200)
	e.grant = e.mcp.signIn(e.sam)
	ai = e.aiGrant(t)
	e.admin.post("/admin/users/"+id, "/admin/users/"+id+"/apps/"+itoa(e.mcp.id), url.Values{"role": {"user"}, "suspended": {"1"}}, 200)
	ends("suspended", ai)
	e.admin.post("/admin/users/"+id, "/admin/users/"+id+"/apps/"+itoa(e.mcp.id), url.Values{"role": {"user"}}, 200)
	ai = e.aiGrant(t)
	token = func() string { _, b := e.mcp.delegate(ai, "calendar"); return b["token"].(string) }()
	e.admin.post("/admin/users/"+id, "/admin/users/"+id+"/apps/"+itoa(e.mcp.id), url.Values{"role": {""}}, 200)
	ends("role removed", ai)
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "token after role removed", status, body)

	// Revocation, twice; and a token made from it dies.
	grantAccess(t, e.st, "sam", e.mcp, "user")
	e.grant = e.mcp.signIn(e.sam)
	ai = e.aiGrant(t)
	token = func() string { _, b := e.mcp.delegate(ai, "calendar"); return b["token"].(string) }()
	if status, body := e.mcp.revokeAIGrant(ai); status != 200 || body["revoked"] != true {
		t.Errorf("revoke: %d %v", status, body)
	}
	ends("revoked", ai)
	status, body = e.calendar.checkToken(token)
	wantInvalidToken(t, "token after revoke", status, body)
	if status, body := e.mcp.revokeAIGrant(ai); status != 200 || body["revoked"] != false {
		t.Errorf("revoke again: %d %v", status, body)
	}

	// The app can't revoke another app's grant, nor a session grant.
	ai = e.aiGrant(t)
	if _, body := e.calendar.revokeAIGrant(ai); body["revoked"] == true {
		t.Error("another app revoked it")
	}
	if status, _ := e.mcp.check(ai); status != 200 {
		t.Error("grant should still be good")
	}
	if status, _ := e.mcp.revokeAIGrant(e.grant); status != 400 {
		t.Errorf("revoke with a session grant: %d", status)
	}
}

func TestAIGrantRefusals(t *testing.T) {
	e := delegationSetup(t)

	// The calendar has no acts_in list.
	grantAccess(t, e.st, "sam", e.calendar, "user")
	calGrant := e.calendar.signIn(e.sam)
	if status, body := e.calendar.makeAIGrant(calGrant); status != 403 || body["error"] != "not_allowed" {
		t.Errorf("app without acts_in: %d %v", status, body)
	}
	// An app that lost its acts_in list: existing grants stop working.
	ai := e.aiGrant(t)
	optIn(t, e.st, e.mcp, nil, nil)
	if status, _ := e.mcp.check(ai); status != 401 {
		t.Errorf("grant of an app no longer acting: %d", status)
	}
	optIn(t, e.st, e.mcp, []string{"calendar", "directory"}, nil)

	// Wrong secret, no auth.
	wrong := *e.mcp
	wrong.secret = "um_wrong"
	if status, body := wrong.makeAIGrant(e.grant); status != 401 || body["error"] != "invalid_client" {
		t.Errorf("wrong secret: %d %v", status, body)
	}
	if status, _ := wrong.revokeAIGrant(ai); status != 401 {
		t.Errorf("wrong secret revoke: %d", status)
	}
	if status, _ := e.mcp.check(ai); status != 200 {
		t.Errorf("grant should survive a wrong-secret revoke: %d", status)
	}

	// Bad or missing session grant; an AI grant can't make more.
	if status, _ := e.mcp.makeAIGrant("nonsense"); status != 401 {
		t.Errorf("bad grant: %d", status)
	}
	ai = e.aiGrant(t)
	if status, _ := e.mcp.makeAIGrant(ai); status != 401 {
		t.Errorf("ai grant minting another: %d", status)
	}
}

func TestAIGrantAccountPage(t *testing.T) {
	e := delegationSetup(t)
	ai := e.aiGrant(t)
	page := e.sam.get("/account", 200)
	if !strings.Contains(page, "AI connections") || !strings.Contains(page, "Mcp") {
		t.Fatal("account page should list the AI connection")
	}
	list, _ := e.st.ListAIGrants(1000000)
	if len(list) != 0 {
		t.Error("someone else's list")
	}
	u, _ := e.st.GetUserByUsername("sam")
	list, _ = e.st.ListAIGrants(u.ID)
	if len(list) != 1 {
		t.Fatalf("grants: %v", list)
	}
	if ok, _ := e.st.RevokeUserAIGrant(u.ID+99, list[0].ID); ok {
		t.Error("someone else revoked it")
	}
	e.sam.post("/account", "/account/ai-grants/"+list[0].ID+"/delete", url.Values{}, 200)
	if status, _ := e.mcp.check(ai); status != 401 {
		t.Errorf("after revoking on the page: %d", status)
	}
}
