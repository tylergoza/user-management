package importer

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/tylergoza/user-management/internal/store"
)

// siblingSchema is the users and sessions tables as the tracker and planner
// have them.
const siblingSchema = `
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE sessions (
    token      TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);`

type fixtureUser struct {
	username, display, password string
	admin                       bool
	created, lastSession        string // "" for none / the default
}

// hashes caches bcrypt hashes so the tests stay quick.
var hashes = map[string]string{}

func hashOf(t *testing.T, pw string) string {
	t.Helper()
	if h, ok := hashes[pw]; ok {
		return h
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	hashes[pw] = string(h)
	return string(h)
}

func siblingDB(t *testing.T, name string, users ...fixtureUser) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(siblingSchema); err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		created := u.created
		if created == "" {
			created = "2026-01-01 00:00:00"
		}
		res, err := db.Exec(`INSERT INTO users (username, display_name, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)`,
			u.username, u.display, hashOf(t, u.password), u.admin, created)
		if err != nil {
			t.Fatal(err)
		}
		if u.lastSession != "" {
			id, _ := res.LastInsertId()
			db.Exec(`INSERT INTO sessions (token, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, 'x', '2099-01-01 00:00:00', ?)`,
				u.username+"-token", id, u.lastSession)
		}
	}
	return path
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func run(t *testing.T, st *store.Store, args ...string) string {
	t.Helper()
	o, err := ParseArgs(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(st, o, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	return out.String()
}

func role(t *testing.T, st *store.Store, username, clientID string) string {
	t.Helper()
	u, err := st.GetUserByUsername(username)
	if err != nil {
		t.Fatalf("%s: %v", username, err)
	}
	a, err := st.GetAppByClientID(clientID)
	if err != nil {
		t.Fatalf("%s: %v", clientID, err)
	}
	acc, err := st.GetAccess(u.ID, a.ID)
	if errors.Is(err, store.ErrNotFound) {
		return ""
	} else if err != nil {
		t.Fatal(err)
	}
	return acc.Role
}

func signsIn(st *store.Store, username, password string) bool {
	_, err := st.Authenticate(username, password)
	return err == nil
}

func countRows(t *testing.T, st *store.Store, q string) int {
	t.Helper()
	var n int
	if err := st.DB.QueryRow(q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func fileSum(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func TestMatchesAcrossBothApps(t *testing.T) {
	tracker := siblingDB(t, "maintenance.db",
		fixtureUser{username: "Tyler", display: "Tyler G", password: "same password", admin: true},
		fixtureUser{username: "sam", password: "sams password"})
	planner := siblingDB(t, "productions.db",
		fixtureUser{username: "tyler", password: "same password", admin: true},
		fixtureUser{username: "pat", display: "Pat", password: "pats password", admin: true})
	trackerSum, plannerSum := fileSum(t, tracker), fileSum(t, planner)

	st := openStore(t)
	out := run(t, st, "--tracker", tracker, "--planner", planner,
		"--tracker-url", "https://maintenance.example.org/", "--planner-url", "https://planner.example.org")

	if n := countRows(t, st, `SELECT COUNT(*) FROM users`); n != 3 {
		t.Fatalf("want 3 users (tyler matched across both), got %d\n%s", n, out)
	}
	if !signsIn(st, "tyler", "same password") || !signsIn(st, "sam", "sams password") || !signsIn(st, "PAT", "pats password") {
		t.Error("imported passwords should keep working")
	}
	tyler, _ := st.GetUserByUsername("tyler")
	if tyler.Username != "Tyler" || tyler.DisplayName != "Tyler G" {
		t.Errorf("tyler: %+v", tyler)
	}
	for _, c := range []struct{ user, app, want string }{
		{"tyler", "tracker", "admin"}, {"tyler", "planner", "admin"},
		{"sam", "tracker", "user"}, {"sam", "planner", ""},
		{"pat", "tracker", ""}, {"pat", "planner", "admin"},
	} {
		if got := role(t, st, c.user, c.app); got != c.want {
			t.Errorf("%s in %s: role %q, want %q", c.user, c.app, got, c.want)
		}
	}

	// Tyler is an admin of both apps, so becomes the user admin here.
	if !tyler.IsAdmin {
		t.Error("tyler should be a user admin here")
	}
	if pat, _ := st.GetUserByUsername("pat"); pat.IsAdmin {
		t.Error("only one imported person should become a user admin")
	}

	a, _ := st.GetAppByClientID("tracker")
	if a.BaseURL != "https://maintenance.example.org" || !a.RedirectAllowed("https://maintenance.example.org/auth/callback") ||
		!a.HasRole("user") || !a.HasRole("admin") {
		t.Errorf("tracker app: %+v", a)
	}
	for _, id := range []string{"tracker", "planner"} {
		if !strings.Contains(out, "SSO_CLIENT_ID="+id) {
			t.Errorf("output should show %s's client ID:\n%s", id, out)
		}
	}
	if strings.Count(out, "SSO_CLIENT_SECRET=um_") != 2 {
		t.Errorf("output should show both secrets:\n%s", out)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM audit_log WHERE action = 'user.import'`); n != 3 {
		t.Errorf("want 3 user.import audit entries, got %d", n)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM audit_log WHERE action = 'access.grant'`); n != 4 {
		t.Errorf("want 4 access.grant audit entries, got %d", n)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM audit_log WHERE action = 'app.create'`); n != 2 {
		t.Errorf("want 2 app.create audit entries, got %d", n)
	}

	if fileSum(t, tracker) != trackerSum || fileSum(t, planner) != plannerSum {
		t.Error("the source databases must not change")
	}
	for _, p := range []string{tracker, planner} {
		for _, suffix := range []string{"-wal", "-journal"} {
			if _, err := os.Stat(p + suffix); err == nil {
				t.Errorf("%s%s should not have been created", p, suffix)
			}
		}
	}
}

func TestPasswordConflict(t *testing.T) {
	tracker := siblingDB(t, "maintenance.db",
		fixtureUser{username: "tyler", password: "tracker password", admin: true, lastSession: "2026-09-01 10:00:00"})
	planner := siblingDB(t, "productions.db",
		fixtureUser{username: "tyler", password: "planner password", admin: true, lastSession: "2026-10-01 10:00:00"})
	urls := []string{"--tracker-url", "https://t.example.org", "--planner-url", "https://p.example.org"}

	t.Run("newer wins", func(t *testing.T) {
		st := openStore(t)
		out := run(t, st, append([]string{"--tracker", tracker, "--planner", planner}, urls...)...)
		if !signsIn(st, "tyler", "planner password") || signsIn(st, "tyler", "tracker password") {
			t.Error("the planner's password was used more recently and should be kept")
		}
		if !strings.Contains(out, "passwords differ: using the planner's") {
			t.Errorf("output should say which password was kept:\n%s", out)
		}
	})
	t.Run("prefer", func(t *testing.T) {
		st := openStore(t)
		out := run(t, st, append([]string{"--tracker", tracker, "--planner", planner, "--prefer", "tracker"}, urls...)...)
		if !signsIn(st, "tyler", "tracker password") {
			t.Error("--prefer tracker should keep the tracker's password")
		}
		if !strings.Contains(out, "using the tracker's (--prefer)") {
			t.Errorf("output:\n%s", out)
		}
	})
	t.Run("created_at when there are no sessions", func(t *testing.T) {
		tr := siblingDB(t, "maintenance.db", fixtureUser{username: "tyler", password: "tracker password", created: "2026-05-01 00:00:00"})
		pl := siblingDB(t, "productions.db", fixtureUser{username: "tyler", password: "planner password", created: "2026-03-01 00:00:00"})
		st := openStore(t)
		run(t, st, append([]string{"--tracker", tr, "--planner", pl}, urls...)...)
		if !signsIn(st, "tyler", "tracker password") {
			t.Error("the tracker's user row is newer, so its password should be kept")
		}
	})
}

func TestOneAppOnly(t *testing.T) {
	planner := siblingDB(t, "productions.db",
		fixtureUser{username: "tyler", password: "planner password", admin: true},
		fixtureUser{username: "sam", password: "sams password"})
	st := openStore(t)
	out := run(t, st, "--planner", planner, "--planner-url", "https://p.example.org")

	if role(t, st, "tyler", "planner") != "admin" || role(t, st, "sam", "planner") != "user" {
		t.Error("planner roles should come from is_admin")
	}
	if _, err := st.GetAppByClientID("tracker"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the tracker shouldn't be registered when it isn't imported: %v", err)
	}
	if strings.Contains(out, "SSO_CLIENT_ID=tracker") {
		t.Errorf("output:\n%s", out)
	}
}

func TestRerunIsIdempotent(t *testing.T) {
	tracker := siblingDB(t, "maintenance.db",
		fixtureUser{username: "tyler", password: "same password", admin: true},
		fixtureUser{username: "sam", password: "sams password"})
	planner := siblingDB(t, "productions.db",
		fixtureUser{username: "tyler", password: "same password", admin: true})
	args := []string{"--tracker", tracker, "--planner", planner,
		"--tracker-url", "https://t.example.org", "--planner-url", "https://p.example.org"}

	st := openStore(t)
	run(t, st, args...)
	planner2, _ := st.GetAppByClientID("planner")
	var secretHash string
	st.DB.QueryRow(`SELECT secret_hash FROM apps WHERE client_id = 'planner'`).Scan(&secretHash)

	// Meanwhile, sam changes their password here and a user admin
	// promotes them in the tracker.
	sam, _ := st.GetUserByUsername("sam")
	st.SetPassword(sam.ID, "a new password")
	tr, _ := st.GetAppByClientID("tracker")
	st.SetAccess(sam.ID, tr.ID, "admin", false, false, 0)

	out := run(t, st, args...)
	if n := countRows(t, st, `SELECT COUNT(*) FROM users`); n != 2 {
		t.Errorf("users duplicated: %d", n)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM user_apps`); n != 3 {
		t.Errorf("access rows duplicated: %d", n)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM apps`); n != 2 {
		t.Errorf("apps duplicated: %d", n)
	}
	if strings.Contains(out, "SSO_CLIENT_SECRET") {
		t.Errorf("an already registered app's secret shouldn't be printed again:\n%s", out)
	}
	var after string
	st.DB.QueryRow(`SELECT secret_hash FROM apps WHERE client_id = 'planner'`).Scan(&after)
	if after != secretHash || planner2 == nil {
		t.Error("an already registered app's secret must not change")
	}
	if !signsIn(st, "sam", "a new password") {
		t.Error("an existing user's password must not be overwritten")
	}
	if role(t, st, "sam", "tracker") != "admin" {
		t.Error("existing access must not be changed")
	}
	if !strings.Contains(out, "sam: already here") || !strings.Contains(out, "created 0 user(s), skipped 2") {
		t.Errorf("output:\n%s", out)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM audit_log WHERE action IN ('user.import', 'access.grant', 'app.create')`); n != 2+3+2 {
		t.Errorf("a re-run shouldn't log anything new, got %d entries", n)
	}
}

func TestExistingUserGetsMissingAccessOnly(t *testing.T) {
	st := openStore(t)
	id, _ := st.CreateUser(&store.User{Username: "tyler", IsAdmin: true}, "set up here first")
	tracker := siblingDB(t, "maintenance.db", fixtureUser{username: "Tyler", password: "tracker password", admin: true})
	run(t, st, "--tracker", tracker, "--tracker-url", "https://t.example.org")

	if !signsIn(st, "tyler", "set up here first") {
		t.Error("existing password must be kept")
	}
	if role(t, st, "tyler", "tracker") != "admin" {
		t.Error("an existing user should still get access they don't have yet")
	}
	if u, _ := st.GetUser(id); !u.IsAdmin {
		t.Error("existing user admin flag must be kept")
	}
}

func TestNoUserAdminWhenServiceHasUsers(t *testing.T) {
	st := openStore(t)
	st.CreateUser(&store.User{Username: "office", IsAdmin: true}, "a long password")
	tracker := siblingDB(t, "maintenance.db", fixtureUser{username: "tyler", password: "tracker password", admin: true})
	run(t, st, "--tracker", tracker, "--tracker-url", "https://t.example.org")
	if u, _ := st.GetUserByUsername("tyler"); u.IsAdmin {
		t.Error("an import into a service that already has users shouldn't make user admins")
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	tracker := siblingDB(t, "maintenance.db", fixtureUser{username: "tyler", password: "tracker password", admin: true})
	st := openStore(t)
	out := run(t, st, "--tracker", tracker, "--tracker-url", "https://t.example.org", "--dry-run")
	for _, table := range []string{"users", "apps", "user_apps", "audit_log"} {
		if n := countRows(t, st, `SELECT COUNT(*) FROM `+table); n != 0 {
			t.Errorf("dry run wrote %d row(s) to %s", n, table)
		}
	}
	if !strings.Contains(out, "would create") || !strings.Contains(out, "would give tracker: admin") {
		t.Errorf("output:\n%s", out)
	}
}

func TestNeedsURLForNewApp(t *testing.T) {
	tracker := siblingDB(t, "maintenance.db", fixtureUser{username: "tyler", password: "tracker password"})
	st := openStore(t)
	o, _ := ParseArgs([]string{"--tracker", tracker}, io.Discard)
	if err := Run(st, o, io.Discard); err == nil || !strings.Contains(err.Error(), "--tracker-url") {
		t.Fatalf("want an error asking for --tracker-url, got %v", err)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM users`); n != 0 {
		t.Error("nothing should be written when an app can't be registered")
	}
}

func TestParseArgs(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "give --tracker, --planner or both"},
		{[]string{"--tracker", "x", "--prefer", "both"}, "--prefer must be"},
		{[]string{"--planner", "x", "--tracker-url", "https://t.example.org"}, "--tracker-url needs --tracker"},
		{[]string{"--tracker", "x", "--tracker-url", "t.example.org"}, "full web address"},
		{[]string{"--tracker", "x", "extra"}, "unexpected argument"},
	} {
		if _, err := ParseArgs(c.args, io.Discard); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: got %v, want %q", c.args, err, c.want)
		}
	}
	if _, err := ParseArgs([]string{"-h"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
	if _, err := ParseArgs([]string{"--tracker", "a", "-planner=b", "--dry-run"}, io.Discard); err != nil {
		t.Error(err)
	}
}

func TestMissingSourceFile(t *testing.T) {
	st := openStore(t)
	missing := filepath.Join(t.TempDir(), "nope.db")
	o, _ := ParseArgs([]string{"--tracker", missing, "--tracker-url", "https://t.example.org"}, io.Discard)
	if err := Run(st, o, io.Discard); err == nil {
		t.Fatal("want an error for a missing database")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("a missing source database must not be created")
	}
}

// The live apps keep their databases in WAL mode. Reading one read-only
// may leave an empty -wal/-shm beside it, but the database itself and its
// contents must not change.
func TestWALSourceUnchanged(t *testing.T) {
	path := siblingDB(t, "productions.db", fixtureUser{username: "tyler", password: "planner password", admin: true})
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE users SET display_name = 'Tyler'`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	before := fileSum(t, path)

	st := openStore(t)
	run(t, st, "--planner", path, "--planner-url", "https://p.example.org")
	if u, err := st.GetUserByUsername("tyler"); err != nil || u.DisplayName != "Tyler" {
		t.Fatalf("tyler: %+v %v", u, err)
	}
	if fileSum(t, path) != before {
		t.Error("the source database must not change")
	}
	if fi, err := os.Stat(path + "-wal"); err == nil && fi.Size() != 0 {
		t.Errorf("nothing should be written to the source's WAL, got %d bytes", fi.Size())
	}
}
