package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mustUser(t *testing.T, st *Store, username string, admin bool) int64 {
	t.Helper()
	id, err := st.CreateUser(&User{Username: username, IsAdmin: admin}, "a long password")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAuthenticate(t *testing.T) {
	st := openTest(t)
	id := mustUser(t, st, "Sam", false)

	if u, err := st.Authenticate("sam", "a long password"); err != nil || u.ID != id {
		t.Fatalf("usernames should match regardless of case: %v %v", u, err)
	}
	if _, err := st.Authenticate("sam", "wrong"); !errors.Is(err, ErrBadLogin) {
		t.Errorf("wrong password: got %v", err)
	}
	if _, err := st.Authenticate("nobody", "a long password"); !errors.Is(err, ErrBadLogin) {
		t.Errorf("unknown user: got %v", err)
	}

	st.SetDisabled(id, true)
	if _, err := st.Authenticate("sam", "wrong"); !errors.Is(err, ErrBadLogin) {
		t.Errorf("disabled with a wrong password should look like any wrong password, got %v", err)
	}
	if _, err := st.Authenticate("sam", "a long password"); !errors.Is(err, ErrDisabled) {
		t.Errorf("disabled with the right password: got %v", err)
	}
}

func TestSessions(t *testing.T) {
	st := openTest(t)
	id := mustUser(t, st, "sam", false)
	ttl := 30 * 24 * time.Hour

	sess, err := st.CreateSession(id, "10.0.0.1", "Mozilla/5.0 (iPhone) Safari/605", ttl)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	st.DB.QueryRow(`SELECT token_hash FROM sessions WHERE id = ?`, sess.ID).Scan(&stored)
	if stored == sess.Token || stored != HashToken(sess.Token) {
		t.Fatal("only the token's hash should be stored")
	}

	got, err := st.GetSession(sess.Token, ttl)
	if err != nil || got.User.ID != id || got.Extended {
		t.Fatalf("fresh session: %+v %v", got, err)
	}
	if _, err := st.GetSession("not-a-token", ttl); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token: got %v", err)
	}

	// A session used more than an hour ago slides forward.
	old := sqlTime(time.Now().Add(-2 * time.Hour))
	st.DB.Exec(`UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`, old, sqlTime(time.Now().Add(time.Hour)), sess.ID)
	got, err = st.GetSession(sess.Token, ttl)
	if err != nil || !got.Extended || got.ExpiresAt < sqlTime(time.Now().Add(ttl-time.Minute)) {
		t.Fatalf("expected the session to slide forward: %+v %v", got, err)
	}

	// Expired sessions are gone.
	st.DB.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, old, sess.ID)
	if _, err := st.GetSession(sess.Token, ttl); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session: got %v", err)
	}

	// Changing the password or turning the account off signs out everywhere.
	a, _ := st.CreateSession(id, "", "", ttl)
	b, _ := st.CreateSession(id, "", "", ttl)
	if n, _ := st.DeleteOtherSessions(id, a.ID); n != 1 {
		t.Errorf("sign out others: deleted %d, want 1", n)
	}
	if _, err := st.GetSession(b.Token, ttl); err == nil {
		t.Error("the other session should be gone")
	}
	st.SetPassword(id, "another long password")
	if _, err := st.GetSession(a.Token, ttl); err == nil {
		t.Error("a password change should end every session")
	}
	c, _ := st.CreateSession(id, "", "", ttl)
	st.SetDisabled(id, true)
	if _, err := st.GetSession(c.Token, ttl); err == nil {
		t.Error("turning an account off should end every session")
	}
}

func TestDeleteUserSessionOnlyOwn(t *testing.T) {
	st := openTest(t)
	sam, pat := mustUser(t, st, "sam", false), mustUser(t, st, "pat", false)
	sess, _ := st.CreateSession(pat, "", "", time.Hour)
	if ok, _ := st.DeleteUserSession(sam, sess.ID); ok {
		t.Fatal("one user must not be able to sign another out")
	}
	if ok, _ := st.DeleteUserSession(pat, sess.ID); !ok {
		t.Fatal("expected own session to be deleted")
	}
}

func TestCountActiveAdmins(t *testing.T) {
	st := openTest(t)
	a := mustUser(t, st, "a", true)
	mustUser(t, st, "b", true)
	mustUser(t, st, "c", false)
	if n, _ := st.CountActiveAdmins(); n != 2 {
		t.Fatalf("got %d admins, want 2", n)
	}
	st.SetDisabled(a, true)
	if n, _ := st.CountActiveAdmins(); n != 1 {
		t.Fatalf("a disabled admin doesn't count: got %d", n)
	}
}

func TestAudit(t *testing.T) {
	st := openTest(t)
	sam, pat := mustUser(t, st, "sam", true), mustUser(t, st, "pat", false)
	st.Audit(AuditEvent{Actor: sam, Action: "user.create", Target: pat, IP: "10.0.0.1"})
	st.Audit(AuditEvent{Actor: sam, Action: "login"})
	st.Audit(AuditEvent{Action: "login.failed", Detail: "username: mallory"})

	all, err := st.ListAudit(AuditFilter{})
	if err != nil || len(all) != 3 || all[0].Action != "login.failed" || all[0].ActorID != 0 {
		t.Fatalf("expected 3 entries newest first: %+v %v", all, err)
	}
	pats, _ := st.ListAudit(AuditFilter{UserID: pat})
	if len(pats) != 1 || pats[0].ActorName != "sam" || pats[0].TargetName != "pat" {
		t.Fatalf("pat's entries: %+v", pats)
	}
	older, _ := st.ListAudit(AuditFilter{Before: all[0].ID, Limit: 1})
	if len(older) != 1 || older[0].ID != all[1].ID {
		t.Fatalf("paging: %+v", older)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("héllo", 2); got != "h" {
		t.Errorf("should not split a character: %q", got)
	}
	if got := truncate("hi", 5); got != "hi" {
		t.Errorf("got %q", got)
	}
}

func TestGrantKeepsSessionAlive(t *testing.T) {
	st := openTest(t)
	id := mustUser(t, st, "sam", false)
	app := &App{ClientID: "planner", Name: "Planner", RedirectURIs: []string{"https://p.test/cb"}, Roles: []string{"user", "admin"}}
	if _, err := st.CreateApp(app); err != nil {
		t.Fatal(err)
	}
	st.SetAccess(id, app.ID, "user", false, false, 0)
	ttl := 30 * 24 * time.Hour
	sess, _ := st.CreateSession(id, "", "", ttl)
	grant, err := st.CreateGrant(app.ID, id, sess.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Someone who only uses the app: their session here was last used
	// long ago and is about to expire. The app's check slides it forward.
	st.DB.Exec(`UPDATE sessions SET last_seen_at = '2000-01-01 00:00:00', expires_at = ? WHERE id = ?`,
		sqlTime(time.Now().Add(time.Minute)), sess.ID)
	if _, err := st.CheckGrant(grant, app.ID, ttl); err != nil {
		t.Fatal(err)
	}
	var expires string
	st.DB.QueryRow(`SELECT expires_at FROM sessions WHERE id = ?`, sess.ID).Scan(&expires)
	if expires < sqlTime(time.Now().Add(ttl-time.Hour)) {
		t.Errorf("the session should have slid forward, expires %s", expires)
	}

	// An expired session ends the grant.
	st.DB.Exec(`UPDATE sessions SET expires_at = '2000-01-01 00:00:00' WHERE id = ?`, sess.ID)
	if _, err := st.CheckGrant(grant, app.ID, ttl); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session: got %v", err)
	}
}

// TestMigration002 runs 001 alone on a database holding apps, users,
// access, sessions, grants and codes, as the live one does, then 002:
// old rows keep working and the new columns have their defaults.
func TestMigration002(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := openAt(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.DB.Exec(`INSERT INTO apps (client_id, name, base_url, redirect_uris, roles, secret_hash) VALUES
		('planner', 'Planner', 'https://p.test', 'https://p.test/cb', 'user,admin', 'x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.DB.Exec(`SELECT acts_in FROM apps`); err == nil {
		t.Fatal("001 alone shouldn't have acts_in")
	}
	id := mustUser(t, old, "sam", false)
	old.DB.Exec(`INSERT INTO user_apps (user_id, app_id, role) VALUES (?, 1, 'user')`, id)
	ttl := 30 * 24 * time.Hour
	sess, _ := old.CreateSession(id, "", "", ttl)
	grant := RandomToken()
	old.DB.Exec(`INSERT INTO grants (id_hash, app_id, user_id, session_id) VALUES (?, 1, ?, ?)`, HashToken(grant), id, sess.ID)
	old.DB.Exec(`INSERT INTO auth_codes (code_hash, app_id, user_id, session_id, redirect_uri, pkce_challenge, expires_at)
		VALUES ('c', 1, ?, ?, 'https://p.test/cb', 'x', '2999-01-01 00:00:00')`, id, sess.ID)
	old.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	app, err := st.GetAppByClientID("planner")
	if err != nil {
		t.Fatal(err)
	}
	if app.ActsIn != nil || app.AcceptsFrom != nil || app.DefaultRole != "" || strings.Join(app.Roles, ",") != "user,admin" {
		t.Errorf("migrated app: %+v", app)
	}
	if g, err := st.CheckGrant(grant, app.ID, ttl); err != nil || g.Role != "user" {
		t.Errorf("old grant: %+v %v", g, err)
	}
	var codes int
	st.DB.QueryRow(`SELECT COUNT(*) FROM auth_codes`).Scan(&codes)
	if codes != 1 {
		t.Error("old codes should be kept")
	}
	if _, err := st.CreateDelegatedToken(grant, app.ID, id); err != nil {
		t.Errorf("delegated_tokens: %v", err)
	}
	// Deleting the session takes the grant and its tokens with it.
	st.DB.Exec(`DELETE FROM sessions WHERE id = ?`, sess.ID)
	var tokens int
	st.DB.QueryRow(`SELECT COUNT(*) FROM delegated_tokens`).Scan(&tokens)
	if tokens != 0 {
		t.Error("tokens should die with the session")
	}
}

func TestChangeAppRolesKeepsDefault(t *testing.T) {
	st := openTest(t)
	app := &App{ClientID: "web", Name: "Website", RedirectURIs: []string{"https://w.test/cb"}, Roles: []string{"user", "admin"}, DefaultRole: "user"}
	if _, err := st.CreateApp(app); err != nil {
		t.Fatal(err)
	}
	// A rename carries the default along.
	if _, err := st.ChangeAppRoles(app.ID, [][2]string{{"user", "member"}}, []string{"member", "admin"}, nil, false); err != nil {
		t.Fatal(err)
	}
	if a, _ := st.GetApp(app.ID); a.DefaultRole != "member" {
		t.Errorf("default after rename: %q", a.DefaultRole)
	}
	// Removing it is refused, unless the default changes too.
	var de *DefaultRoleError
	if _, err := st.ChangeAppRoles(app.ID, nil, []string{"editor", "admin"}, nil, false); !errors.As(err, &de) {
		t.Errorf("removing the default: %v", err)
	}
	editor := "editor"
	if _, err := st.ChangeAppRoles(app.ID, nil, []string{"editor", "admin"}, &editor, false); err != nil {
		t.Fatal(err)
	}
	if a, _ := st.GetApp(app.ID); a.DefaultRole != "editor" || strings.Join(a.Roles, ",") != "editor,admin" {
		t.Errorf("after changing both: %+v", a)
	}
	admin := "admin"
	if _, err := st.ChangeAppRoles(app.ID, nil, []string{"editor", "admin"}, &admin, false); err == nil {
		t.Error("admin as the default should be refused")
	}
}
