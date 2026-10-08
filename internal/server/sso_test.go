package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/tylergoza/user-management/internal/store"
)

// testApp is an app's server talking to this service.
type testApp struct {
	t        *testing.T
	base     string
	id       int64
	clientID string
	secret   string
	callback string
}

func registerApp(t *testing.T, c *client, st *store.Store, clientID string) *testApp {
	t.Helper()
	callback := "https://" + clientID + ".test/auth/callback"
	a := store.App{ClientID: clientID, Name: strings.ToUpper(clientID[:1]) + clientID[1:], BaseURL: "https://" + clientID + ".test",
		RedirectURIs: []string{callback}, Roles: []string{"user", "admin"}}
	secret, err := st.CreateApp(&a)
	if err != nil {
		t.Fatal(err)
	}
	return &testApp{t: t, base: c.base, id: a.ID, clientID: clientID, secret: secret, callback: callback}
}

func grantAccess(t *testing.T, st *store.Store, username string, app *testApp, role string) {
	t.Helper()
	u, err := st.GetUserByUsername(username)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccess(u.ID, app.id, role, false, false, 0); err != nil {
		t.Fatal(err)
	}
}

// pkce makes a code verifier and its S256 challenge.
func pkce() (verifier, challenge string) {
	verifier = store.RandomToken() // 43 URL-safe characters
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func (a *testApp) authorizePath(challenge string) string {
	return "/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {a.clientID}, "redirect_uri": {a.callback},
		"state": {"xyz"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()
}

// backAt checks a response is the redirect back to the app and returns
// its query.
func backAt(t *testing.T, resp *http.Response, callback string) url.Values {
	t.Helper()
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), callback+"?") {
		t.Fatalf("expected a redirect back to %s, got %d %q", callback, resp.StatusCode, resp.Header.Get("Location"))
	}
	return loc.Query()
}

// authorize visits /authorize already signed in and returns the code.
func (c *client) authorize(a *testApp, challenge string) string {
	c.t.Helper()
	resp, err := c.http.Get(c.base + a.authorizePath(challenge))
	if err != nil {
		c.t.Fatal(err)
	}
	q := backAt(c.t, resp, a.callback)
	if q.Get("state") != "xyz" || q.Get("code") == "" {
		c.t.Fatalf("expected a code and the state back, got %v", q)
	}
	return q.Get("code")
}

// call makes a request as the app's server: client ID and secret with
// Basic auth. It returns the status and the decoded JSON.
func (a *testApp) call(method, path string, body io.Reader, contentType string, headers ...string) (int, map[string]any) {
	a.t.Helper()
	req, _ := http.NewRequest(method, a.base+path, body)
	req.SetBasicAuth(a.clientID, a.secret)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (a *testApp) token(code, redirectURI, verifier string) (int, map[string]any) {
	a.t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	return a.call("POST", "/token", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
}

// signIn runs the whole flow for a browser that's already signed in here
// and returns the grant.
func (a *testApp) signIn(c *client) string {
	a.t.Helper()
	verifier, challenge := pkce()
	status, body := a.token(c.authorize(a, challenge), a.callback, verifier)
	if status != 200 {
		a.t.Fatalf("token: %d %v", status, body)
	}
	return body["grant"].(string)
}

func (a *testApp) check(grant string) (int, map[string]any) {
	a.t.Helper()
	return a.call("GET", "/api/v1/grant", nil, "", "X-Grant", grant)
}

func TestSSOFlow(t *testing.T) {
	admin, st := setup(t)
	addUser(admin, "sam", false)
	planner := registerApp(t, admin, st, "planner")
	grantAccess(t, st, "sam", planner, "admin")

	// Signed out: /authorize leads to the sign-in page, which names the app.
	sam := admin.another()
	verifier, challenge := pkce()
	if body := sam.get(planner.authorizePath(challenge), 200); !strings.Contains(body, "continue to <strong>Planner</strong>") {
		t.Fatalf("expected the sign-in page for Planner:\n%s", body)
	}
	// Signing in carries on to /authorize and back to the app. The CSP
	// lets that last redirect happen after the sign-in form.
	m := csrfRe.FindStringSubmatch(sam.get("/login", 200))
	resp, err := sam.http.PostForm(sam.base+"/login", url.Values{"_csrf": {m[1]},
		"username": {"sam"}, "password": {"member password"}, "next": {planner.authorizePath(challenge)}})
	if err != nil {
		t.Fatal(err)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://planner.test") {
		t.Errorf("CSP form-action should allow the app: %s", csp)
	}
	q := backAt(t, resp, planner.callback)
	if q.Get("state") != "xyz" {
		t.Errorf("state should come back unchanged, got %q", q.Get("state"))
	}

	status, body := planner.token(q.Get("code"), planner.callback, verifier)
	if status != 200 {
		t.Fatalf("token: %d %v", status, body)
	}
	user := body["user"].(map[string]any)
	if user["username"] != "sam" || user["role"] != "admin" || user["sub"] != userID(t, st, "sam") {
		t.Errorf("unexpected user: %v", user)
	}
	grant := body["grant"].(string)

	// The code works once.
	if status, body := planner.token(q.Get("code"), planner.callback, verifier); status != 400 || body["error"] != "invalid_grant" {
		t.Errorf("reused code: %d %v", status, body)
	}

	if status, body := planner.check(grant); status != 200 || body["user"].(map[string]any)["role"] != "admin" {
		t.Errorf("grant check: %d %v", status, body)
	}

	// Already signed in here: straight back to the app, no sign-in page.
	sam.authorize(planner, challenge)

	// Signing out from the app ends the session here, and every grant.
	second := planner.signIn(sam)
	status, _ = planner.call("POST", "/api/v1/logout", nil, "", "X-Grant", grant)
	if status != 204 {
		t.Fatalf("logout: %d", status)
	}
	for _, g := range []string{grant, second} {
		if status, _ := planner.check(g); status != 401 {
			t.Errorf("after signing out, grant check: %d, want 401", status)
		}
	}
	if body := sam.get("/account", 200); strings.Contains(body, "My account") {
		t.Error("signing out from the app should sign out here too")
	}

	entries, _ := st.ListAudit(store.AuditFilter{UserID: 0, Limit: 5})
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action+"/"+e.AppName)
	}
	if got := strings.Join(actions, ","); !strings.HasPrefix(got, "app.signout/Planner,app.signin/Planner,app.signin/Planner") {
		t.Errorf("audit log: %s", got)
	}
}

func TestAuthorizeRefusals(t *testing.T) {
	admin, st := setup(t)
	planner := registerApp(t, admin, st, "planner")
	_, challenge := pkce()

	// An unknown app or unregistered redirect URI is shown here, never
	// redirected to.
	for _, path := range []string{
		strings.Replace(planner.authorizePath(challenge), "client_id=planner", "client_id=nope", 1),
		strings.Replace(planner.authorizePath(challenge), url.QueryEscape(planner.callback), url.QueryEscape("https://evil.test/cb"), 1),
		strings.Replace(planner.authorizePath(challenge), url.QueryEscape(planner.callback), url.QueryEscape(planner.callback+"/x"), 1),
	} {
		if body := admin.get(path, 400); !strings.Contains(body, "sign-in link isn") {
			t.Errorf("%s: expected the bad link page", path)
		}
	}

	// Other problems go back to the app as errors.
	for name, path := range map[string]string{
		"no PKCE":     strings.Replace(planner.authorizePath(challenge), "code_challenge_method=S256", "code_challenge_method=plain", 1),
		"bad PKCE":    strings.Replace(planner.authorizePath(challenge), "code_challenge="+challenge, "code_challenge=short", 1),
		"no state":    strings.Replace(planner.authorizePath(challenge), "state=xyz", "state=", 1),
		"token reply": strings.Replace(planner.authorizePath(challenge), "response_type=code", "response_type=token", 1),
	} {
		resp, err := admin.http.Get(admin.base + path)
		if err != nil {
			t.Fatal(err)
		}
		if q := backAt(t, resp, planner.callback); q.Get("error") == "" || q.Get("code") != "" {
			t.Errorf("%s: expected an error and no code, got %v", name, q)
		}
	}

	// Signed in, but no access: a page here, with a way to switch account.
	if body := admin.get(planner.authorizePath(challenge), 403); !strings.Contains(body, "No access to Planner") || !strings.Contains(body, "Sign in as someone else") {
		t.Error("expected the no-access page")
	}
	// Suspended counts as no access.
	grantAccess(t, st, "admin", planner, "admin")
	u, _ := st.GetUserByUsername("admin")
	st.SetAccess(u.ID, planner.id, "admin", true, false, 0)
	admin.get(planner.authorizePath(challenge), 403)
}

func TestTokenAttacks(t *testing.T) {
	admin, st := setup(t)
	planner := registerApp(t, admin, st, "planner")
	tracker := registerApp(t, admin, st, "tracker")
	grantAccess(t, st, "admin", planner, "admin")
	grantAccess(t, st, "admin", tracker, "admin")

	code := func() (string, string) {
		verifier, challenge := pkce()
		return admin.authorize(planner, challenge), verifier
	}

	c, v := code()
	if status, body := planner.token(c, planner.callback+"/other", v); status != 400 || body["error"] != "invalid_grant" {
		t.Errorf("wrong redirect URI: %d %v", status, body)
	}
	// A refused code is used up too.
	if status, _ := planner.token(c, planner.callback, v); status != 400 {
		t.Errorf("a code refused once should be gone: %d", status)
	}

	c, _ = code()
	if status, body := planner.token(c, planner.callback, strings.Repeat("a", 43)); status != 400 || body["error"] != "invalid_grant" {
		t.Errorf("wrong PKCE verifier: %d %v", status, body)
	}

	c, v = code()
	if status, body := tracker.token(c, planner.callback, v); status != 400 || body["error"] != "invalid_grant" {
		t.Errorf("another app's code: %d %v", status, body)
	}

	c, v = code()
	wrong := *planner
	wrong.secret = "um_wrong"
	if status, body := wrong.token(c, planner.callback, v); status != 401 || body["error"] != "invalid_client" {
		t.Errorf("wrong secret: %d %v", status, body)
	}
	// The code survives a wrong secret, so the real app can still use it.
	if status, _ := planner.token(c, planner.callback, v); status != 200 {
		t.Errorf("the code should still work for the real app: %d", status)
	}

	c, v = code()
	st.DB.Exec(`UPDATE auth_codes SET expires_at = '2000-01-01 00:00:00'`)
	if status, _ := planner.token(c, planner.callback, v); status != 400 {
		t.Errorf("expired code: %d", status)
	}

	// No credentials at all.
	resp, _ := http.PostForm(admin.base+"/token", url.Values{"grant_type": {"authorization_code"}})
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("no client auth: %d", resp.StatusCode)
	}
}

func TestGrantEnds(t *testing.T) {
	admin, st := setup(t)
	addUser(admin, "sam", false)
	planner := registerApp(t, admin, st, "planner")
	grantAccess(t, st, "sam", planner, "user")
	id := userID(t, st, "sam")
	sam := admin.another()
	sam.login("sam", "member password", 200)

	// A code issued just before the account is turned off is useless.
	verifier, challenge := pkce()
	c := sam.authorize(planner, challenge)
	admin.post("/admin/users/"+id, "/admin/users/"+id+"/disable", url.Values{}, 200)
	if status, _ := planner.token(c, planner.callback, verifier); status != 400 {
		t.Errorf("code of a turned-off user: %d", status)
	}
	admin.post("/admin/users/"+id, "/admin/users/"+id+"/enable", url.Values{}, 200)
	sam.login("sam", "member password", 200)

	// The tracker can't check the planner's grants.
	grant := planner.signIn(sam)
	tracker := registerApp(t, admin, st, "tracker")
	if status, _ := tracker.check(grant); status != 401 {
		t.Errorf("another app's grant: %d", status)
	}

	// Suspending ends it, and restoring brings it back.
	admin.post("/admin/users/"+id, "/admin/users/"+id+"/apps/"+itoa(planner.id), url.Values{"role": {"user"}, "suspended": {"1"}}, 200)
	if status, _ := planner.check(grant); status != 401 {
		t.Errorf("suspended: %d", status)
	}
	admin.post("/admin/users/"+id, "/admin/users/"+id+"/apps/"+itoa(planner.id), url.Values{"role": {"admin"}}, 200)
	if status, body := planner.check(grant); status != 200 || body["user"].(map[string]any)["role"] != "admin" {
		t.Errorf("restored as admin: %d %v", status, body)
	}

	// A password reset signs them out here, so the grant ends.
	admin.post("/admin/users/"+id, "/admin/users/"+id, url.Values{
		"username": {"sam"}, "password": {"a new password"}, "password_confirm": {"a new password"},
	}, 200)
	if status, _ := planner.check(grant); status != 401 {
		t.Errorf("after a password reset: %d", status)
	}

	// Removing access ends it.
	sam.login("sam", "a new password", 200)
	grant = planner.signIn(sam)
	admin.post("/admin/users/"+id, "/admin/users/"+id+"/apps/"+itoa(planner.id), url.Values{"role": {""}}, 200)
	if status, _ := planner.check(grant); status != 401 {
		t.Errorf("access removed: %d", status)
	}
}

func TestAppAdminAPI(t *testing.T) {
	admin, st := setup(t)
	for _, u := range []string{"boss", "sam", "kim", "outsider"} {
		addUser(admin, u, false)
	}
	planner := registerApp(t, admin, st, "planner")
	tracker := registerApp(t, admin, st, "tracker")
	grantAccess(t, st, "boss", planner, "admin")
	grantAccess(t, st, "sam", planner, "user")
	grantAccess(t, st, "kim", planner, "user")
	grantAccess(t, st, "outsider", tracker, "user")

	signedIn := func(username string) string {
		c := admin.another()
		c.login(username, "member password", 200)
		return planner.signIn(c)
	}
	boss, sam := signedIn("boss"), signedIn("sam")
	patch := func(grant, userID, body string) (int, map[string]any) {
		return planner.call("PATCH", "/api/v1/apps/planner/users/"+userID, strings.NewReader(body), "application/json", "X-Acting-Grant", grant)
	}

	// Listing needs only the app's secret, and covers only its own people.
	status, list := planner.call("GET", "/api/v1/apps/planner/users", nil, "")
	if status != 200 || len(list["users"].([]any)) != 3 {
		t.Fatalf("list: %d %v", status, list)
	}
	if status, _ := planner.call("GET", "/api/v1/apps/tracker/users", nil, ""); status != 403 {
		t.Errorf("listing another app's people: %d", status)
	}

	samID, kimID, bossID := userID(t, st, "sam"), userID(t, st, "kim"), userID(t, st, "boss")
	if status, body := patch(sam, kimID, `{"role":"admin"}`); status != 403 {
		t.Errorf("a non-admin's grant: %d %v", status, body)
	}
	if status, _ := patch("not-a-grant", kimID, `{"role":"admin"}`); status != 401 {
		t.Errorf("a bad grant: %d", status)
	}
	if status, body := patch(boss, userID(t, st, "outsider"), `{"role":"user"}`); status != 404 || body["error"] != "no_access" {
		t.Errorf("another app's user (granting new access): %d %v", status, body)
	}
	if status, body := patch(boss, kimID, `{"role":"owner"}`); status != 422 {
		t.Errorf("a role the app doesn't have: %d %v", status, body)
	}
	if status, _ := planner.call("PATCH", "/api/v1/apps/tracker/users/"+samID, strings.NewReader(`{"suspended":true}`), "application/json", "X-Acting-Grant", boss); status != 403 {
		t.Errorf("changing another app's people: %d", status)
	}

	// The last admin can't be demoted or suspended, even by themselves.
	if status, body := patch(boss, bossID, `{"role":"user"}`); status != 409 || body["error"] != "last_admin" {
		t.Errorf("demote the last admin: %d %v", status, body)
	}
	if status, _ := patch(boss, bossID, `{"suspended":true}`); status != 409 {
		t.Errorf("suspend the last admin: %d", status)
	}

	// A real change, recorded with who did it and through which app.
	status, body := patch(boss, samID, `{"role":"admin"}`)
	if status != 200 || body["role"] != "admin" || body["updated_by"] != "boss" {
		t.Fatalf("promote sam: %d %v", status, body)
	}
	if body := admin.get("/admin/users/"+samID, 200); !strings.Contains(body, "role user → admin") || !strings.Contains(body, "Planner") {
		t.Error("expected the change in sam's activity, with the app")
	}
	// With two admins, one can step down.
	if status, _ := patch(boss, bossID, `{"role":"user"}`); status != 200 {
		t.Errorf("step down with another admin left: %d", status)
	}
	// Boss's grant now has the user role, so boss can't make changes.
	if status, _ := patch(boss, kimID, `{"suspended":true}`); status != 403 {
		t.Errorf("a demoted admin: %d", status)
	}

	// A user admin locks kim's row; app admins can't change it.
	kim, _ := st.GetUserByUsername("kim")
	st.SetAccess(kim.ID, planner.id, "user", false, true, 0)
	if status, body := patch(sam, kimID, `{"suspended":true}`); status != 403 || body["error"] != "locked" {
		t.Errorf("a locked row: %d %v", status, body)
	}
	status, body = patch(sam, bossID, `{"suspended":true}`)
	if status != 200 || body["active"] != false {
		t.Errorf("suspend boss: %d %v", status, body)
	}
}

func TestManageApps(t *testing.T) {
	admin, st := setup(t)
	addUser(admin, "sam", false)

	if body := admin.post("/admin/apps/new", "/admin/apps", url.Values{
		"client_id": {"Bad ID"}, "name": {""}, "redirect_uris": {"ftp://x\n/relative"}, "roles": {"user"},
	}, 422); !strings.Contains(body, "Client ID must") || !strings.Contains(body, "Name is required") ||
		!strings.Contains(body, "must be a full web address") || !strings.Contains(body, "must include admin") {
		t.Errorf("expected every validation error:\n%s", body)
	}

	body := admin.post("/admin/apps/new", "/admin/apps", url.Values{
		"client_id": {"planner"}, "name": {"Planner"}, "base_url": {"https://planner.test"},
		"redirect_uris": {"https://planner.test/auth/callback\nhttp://localhost:8090/auth/callback"}, "roles": {"user, admin"},
	}, 200)
	m := regexp.MustCompile(`SSO_CLIENT_SECRET=(um_[A-Za-z0-9_-]+)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("expected the secret to be shown:\n%s", body)
	}
	app, _ := st.GetAppByClientID("planner")
	if _, err := st.AuthenticateApp("planner", m[1]); err != nil {
		t.Errorf("the shown secret should work: %v", err)
	}
	if body := admin.get("/admin/apps/"+itoa(app.ID), 200); strings.Contains(body, m[1]) {
		t.Error("the secret must only be shown once")
	}

	// Give sam access from their page; the grid shows it.
	id := userID(t, st, "sam")
	admin.post("/admin/users/"+id, "/admin/users/"+id+"/apps/"+itoa(app.ID), url.Values{"role": {"user"}, "locked": {"1"}}, 200)
	if body := admin.get("/admin/users", 200); !strings.Contains(body, "<th>Planner</th>") || !strings.Contains(body, "Locked") {
		t.Error("expected sam's planner access in the grid")
	}
	if body := admin.get("/admin/users/"+id, 200); !strings.Contains(body, "Gave app access") {
		t.Error("expected the grant in sam's activity")
	}

	// A role in use can't be removed.
	if body := admin.post("/admin/apps/"+itoa(app.ID), "/admin/apps/"+itoa(app.ID), url.Values{
		"name": {"Planner"}, "redirect_uris": {"https://planner.test/auth/callback"}, "roles": {"admin"},
	}, 422); !strings.Contains(body, "1 person is using it") {
		t.Error("expected removing a role in use to be refused")
	}

	// A new secret replaces the old one at once.
	body = admin.post("/admin/apps/"+itoa(app.ID), "/admin/apps/"+itoa(app.ID)+"/secret", url.Values{}, 200)
	n := regexp.MustCompile(`SSO_CLIENT_SECRET=(um_[A-Za-z0-9_-]+)`).FindStringSubmatch(body)
	if n == nil || n[1] == m[1] {
		t.Fatal("expected a new secret")
	}
	if _, err := st.AuthenticateApp("planner", m[1]); err == nil {
		t.Error("the old secret should stop working")
	}
	if _, err := st.AuthenticateApp("planner", n[1]); err != nil {
		t.Error("the new secret should work")
	}

	// Non-admins can't get in.
	sam := admin.another()
	sam.login("sam", "member password", 200)
	sam.get("/admin/apps", 403)
}

func TestLogoutPage(t *testing.T) {
	c, _ := setup(t)
	if body := c.get("/logout", 200); !strings.Contains(body, "Sign out?") {
		t.Error("GET /logout should ask first")
	}
	c.get("/account", 200) // still signed in
	// Signing out on the way somewhere keeps the destination.
	if body := c.post("/logout", "/logout", url.Values{"next": {"/account"}}, 200); !strings.Contains(body, `name="next" value="/account"`) {
		t.Error("expected the sign-in page carrying on to /account")
	}
}

func TestPKCE(t *testing.T) {
	verifier, challenge := pkce()
	if !validChallenge(challenge) || !pkceMatches(verifier, challenge) {
		t.Fatal("a matching pair should pass")
	}
	if pkceMatches(verifier[:42], challenge) || pkceMatches(verifier+"!", challenge) || validChallenge("short") {
		t.Error("too short, a bad character, or a bad challenge should fail")
	}
}
