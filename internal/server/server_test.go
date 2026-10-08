package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tylergoza/user-management/internal/store"
)

type client struct {
	t    *testing.T
	base string
	http *http.Client
}

func newTestServer(t *testing.T) (*client, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv, err := New(Config{}, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	c := &client{t: t, base: ts.URL}
	return c.another(), st
}

// another is a second browser on the same server, with its own cookies.
func (c *client) another() *client {
	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse(c.base)
	return &client{t: c.t, base: c.base, http: &http.Client{Jar: jar,
		// Follow redirects within this server, but stop at one to an app
		// (https://planner.test/...) so the test can read it.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host != base.Host {
				return http.ErrUseLastResponse
			}
			return nil
		}}}
}

func (c *client) get(path string, wantStatus int) string {
	c.t.Helper()
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		c.t.Fatalf("GET %s: status %d, want %d\n%s", path, resp.StatusCode, wantStatus, body)
	}
	return string(body)
}

var csrfRe = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

// post submits a form, pulling the CSRF token from a page first.
func (c *client) post(tokenPage, path string, form url.Values, wantStatus int) string {
	c.t.Helper()
	m := csrfRe.FindStringSubmatch(c.get(tokenPage, 200))
	if m == nil {
		c.t.Fatalf("no csrf token on %s", tokenPage)
	}
	form.Set("_csrf", m[1])
	resp, err := c.http.PostForm(c.base+path, form)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		c.t.Fatalf("POST %s: status %d, want %d\n%s", path, resp.StatusCode, wantStatus, body)
	}
	return string(body)
}

func (c *client) login(username, password string, wantStatus int) string {
	c.t.Helper()
	return c.post("/login", "/login", url.Values{"username": {username}, "password": {password}}, wantStatus)
}

// setup creates the first user admin, "admin", signed in on the returned client.
func setup(t *testing.T) (*client, *store.Store) {
	t.Helper()
	c, st := newTestServer(t)
	if body := c.get("/", 200); !strings.Contains(body, "Create the first user admin") {
		t.Fatal("with no users, everything should lead to setup")
	}
	c.post("/setup", "/setup", url.Values{
		"site_name": {"Grace Accounts"}, "username": {"admin"}, "display_name": {"Pat Admin"},
		"password": {"a long password"}, "password_confirm": {"a long password"},
	}, 200)
	return c, st
}

func addUser(c *client, username string, admin bool) {
	c.t.Helper()
	form := url.Values{"username": {username}, "password": {"member password"}, "password_confirm": {"member password"}}
	if admin {
		form.Set("is_admin", "1")
	}
	c.post("/admin/users/new", "/admin/users", form, 200)
}

func userID(t *testing.T, st *store.Store, username string) string {
	t.Helper()
	u, err := st.GetUserByUsername(username)
	if err != nil {
		t.Fatal(err)
	}
	return itoa(u.ID)
}

func TestSetupAndSignIn(t *testing.T) {
	c, st := setup(t)

	// Setup only works once.
	if body := c.another().get("/setup", 200); !strings.Contains(body, "Sign in") {
		t.Error("setup should send to sign-in once a user exists")
	}
	if body := c.get("/", 200); !strings.Contains(body, "Hello, Pat Admin") || !strings.Contains(body, "Grace Accounts") {
		t.Error("expected the launcher with the new site name")
	}

	c.post("/", "/logout", url.Values{}, 200)
	if body := c.get("/account", 200); !strings.Contains(body, `name="password"`) {
		t.Fatal("signed out: expected the sign-in page")
	}
	if body := c.login("admin", "wrong password", 401); !strings.Contains(body, "Incorrect username or password") {
		t.Error("expected a sign-in error")
	}

	// Signing in carries on to where you were going, query string and all.
	form := url.Values{"username": {"ADMIN"}, "password": {"a long password"}, "next": {"/admin/audit?user=1"}}
	if body := c.post("/login", "/login", form, 200); !strings.Contains(body, "Done by or to") {
		t.Error("expected to land on the filtered audit log")
	}

	entries, _ := st.ListAudit(store.AuditFilter{})
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	if got := strings.Join(actions, ","); got != "login,login.failed,logout,setup" {
		t.Errorf("audit log: got %s", got)
	}
}

func TestLoginRateLimit(t *testing.T) {
	c, _ := setup(t)
	c.post("/", "/logout", url.Values{}, 200)
	for range 10 {
		c.login("admin", "wrong password", 401)
	}
	if body := c.login("admin", "a long password", 429); !strings.Contains(body, "Too many sign-in attempts") {
		t.Error("expected to be rate limited even with the right password")
	}
}

func TestCSRF(t *testing.T) {
	c, _ := setup(t)
	resp, err := c.http.PostForm(c.base+"/admin/users", url.Values{"username": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without a CSRF token: status %d, want 403", resp.StatusCode)
	}
}

func TestManageUsers(t *testing.T) {
	admin, st := setup(t)
	addUser(admin, "sam", false)
	if body := admin.post("/admin/users/new", "/admin/users", url.Values{
		"username": {"SAM"}, "password": {"member password"}, "password_confirm": {"member password"},
	}, 422); !strings.Contains(body, "already taken") {
		t.Error("usernames should be unique regardless of case")
	}
	if body := admin.post("/admin/users/new", "/admin/users", url.Values{
		"username": {"two words"}, "email": {"nope"}, "password": {"short"}, "password_confirm": {"other"},
	}, 422); !strings.Contains(body, "no spaces") || !strings.Contains(body, "Email") || !strings.Contains(body, "at least 10") || !strings.Contains(body, "do not match") {
		t.Error("expected every validation error")
	}

	// Sam can sign in, but isn't a user admin.
	sam := admin.another()
	if body := sam.login("sam", "member password", 200); !strings.Contains(body, "No apps yet") {
		t.Error("expected sam's empty launcher")
	}
	sam.get("/admin/users", 403)

	// Renaming and a password reset: sam is signed out everywhere.
	id := userID(t, st, "sam")
	admin.post("/admin/users/"+id, "/admin/users/"+id, url.Values{
		"username": {"samuel"}, "display_name": {"Sam"}, "password": {"a new password"}, "password_confirm": {"a new password"},
	}, 200)
	if body := sam.get("/account", 200); !strings.Contains(body, `autocomplete="current-password"`) || strings.Contains(body, "My account") {
		t.Error("a password reset should sign sam out")
	}
	sam.login("samuel", "a new password", 200)
	if body := admin.get("/admin/users/"+id, 200); !strings.Contains(body, "username sam → samuel") || !strings.Contains(body, "Reset password") {
		t.Error("expected the edit and reset in sam's recent activity")
	}

	// Turning sam off signs them out and stops them signing back in.
	admin.post("/admin/users/"+id, "/admin/users/"+id+"/disable", url.Values{}, 200)
	if body := sam.get("/", 200); !strings.Contains(body, `name="password"`) {
		t.Error("a turned-off account should be signed out")
	}
	if body := sam.login("samuel", "a new password", 403); !strings.Contains(body, "turned off") {
		t.Error("expected the turned-off message")
	}
	admin.post("/admin/users/"+id, "/admin/users/"+id+"/enable", url.Values{}, 200)
	sam.login("samuel", "a new password", 200)
}

func TestLastAdminGuards(t *testing.T) {
	admin, st := setup(t)
	id := userID(t, st, "admin")
	if body := admin.post("/admin/users/"+id, "/admin/users/"+id, url.Values{"username": {"admin"}}, 422); !strings.Contains(body, "At least one active user admin") {
		t.Error("the last user admin can't stop being one")
	}
	if body := admin.post("/admin/users/"+id, "/admin/users/"+id+"/disable", url.Values{}, 200); !strings.Contains(body, "can&#39;t turn off your own account") {
		t.Error("you can't turn off your own account")
	}

	// With a second admin, the first can step down.
	addUser(admin, "deputy", true)
	if body := admin.post("/admin/users/"+id, "/admin/users/"+id, url.Values{"username": {"admin"}}, 200); !strings.Contains(body, "Hello,") {
		t.Error("stepping down should land on the launcher")
	}
	admin.get("/admin/users", 403)
}

func TestAccount(t *testing.T) {
	c, _ := setup(t)
	phone := c.another()
	phone.login("admin", "a long password", 200)

	body := c.get("/account", 200)
	if strings.Count(body, "Last used") != 2 || !strings.Contains(body, "This device") {
		t.Fatalf("expected both devices listed:\n%s", body)
	}

	if body := c.post("/account", "/account/password", url.Values{
		"current_password": {"wrong"}, "password": {"a newer password"}, "password_confirm": {"a newer password"},
	}, 422); !strings.Contains(body, "Current password is incorrect") {
		t.Error("expected the current password to be checked")
	}
	if body := c.post("/account", "/account/password", url.Values{
		"current_password": {"a long password"}, "password": {"a newer password"}, "password_confirm": {"a newer password"},
	}, 200); !strings.Contains(body, "Password updated") {
		t.Fatal("expected the password to change")
	}
	// This device stays signed in; the phone doesn't.
	if body := phone.get("/account", 200); strings.Contains(body, "My account") {
		t.Error("the phone should have been signed out")
	}
	c.get("/account", 200)

	phone.login("admin", "a newer password", 200)
	c.post("/account", "/account/sessions/others", url.Values{}, 200)
	if body := phone.get("/account", 200); strings.Contains(body, "My account") {
		t.Error("sign out everywhere else should sign the phone out")
	}
}

func TestBackupAndPages(t *testing.T) {
	c, _ := setup(t)
	for _, p := range []string{"/admin/users", "/admin/users/new", "/admin/audit", "/admin/settings", "/account", "/offline", "/manifest.webmanifest"} {
		c.get(p, 200)
	}
	if body := c.get("/sw.js", 200); !strings.Contains(body, "um-static-") || strings.Contains(body, "__PRECACHE__") {
		t.Error("service worker should have its version and precache list filled in")
	}
	if body := c.get("/admin/backup", 200); !strings.HasPrefix(body, "SQLite format 3") {
		t.Error("expected a SQLite backup")
	}
	c.post("/admin/settings", "/admin/settings", url.Values{"site_name": {"Mountain View Accounts"}}, 200)
	if body := c.get("/", 200); !strings.Contains(body, "Mountain View Accounts") {
		t.Error("expected the new site name")
	}
	c.get("/nope", 404)
}

func TestSafeRedirect(t *testing.T) {
	for in, want := range map[string]string{
		"":                             "/",
		"/account":                     "/account",
		"/authorize?client_id=planner": "/authorize?client_id=planner",
		"//evil.example":               "/",
		"/\\evil.example":              "/",
		"https://evil.example/":        "/",
		"/./\\evil.example":            "/%5Cevil.example",
		"/a/../b":                      "/b",
		"/%2F%2Fevil.example":          "/%2F%2Fevil.example",
		"account":                      "/",
	} {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}
