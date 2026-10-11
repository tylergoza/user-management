package registerapp

import (
	"bytes"
	"errors"
	"flag"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tylergoza/user-management/internal/store"
)

func openTest(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func parse(t *testing.T, args ...string) Options {
	t.Helper()
	o, err := ParseArgs(args, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func run(t *testing.T, st *store.Store, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := Run(st, parse(t, args...), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func secretHash(t *testing.T, st *store.Store, clientID string) string {
	t.Helper()
	var h string
	if err := st.DB.QueryRow(`SELECT secret_hash FROM apps WHERE client_id = ?`, clientID).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

var base = []string{"events", "--name", "Event Planner", "--url", "https://events.example.org/"}

func TestCreateAndRerun(t *testing.T) {
	st := openTest(t)
	out := run(t, st, base...)
	if !strings.Contains(out, "SSO_CLIENT_ID=events") || !strings.Contains(out, "SSO_CLIENT_SECRET=um_") {
		t.Fatalf("missing credentials:\n%s", out)
	}
	a, err := st.GetAppByClientID("events")
	if err != nil {
		t.Fatal(err)
	}
	if a.BaseURL != "https://events.example.org" || len(a.RedirectURIs) != 1 || a.RedirectURIs[0] != "https://events.example.org/auth/callback" ||
		strings.Join(a.Roles, ",") != "user,admin" || a.Name != "Event Planner" {
		t.Errorf("app = %+v", a)
	}
	before := secretHash(t, st, "events")

	out = run(t, st, append([]string{"--name", "Other", "--url", "https://x.example.org"}, "events")...)
	if strings.Contains(out, "SSO_CLIENT_SECRET") || !strings.Contains(out, "already registered") {
		t.Errorf("re-run output:\n%s", out)
	}
	if secretHash(t, st, "events") != before {
		t.Error("secret changed on re-run")
	}
	b, _ := st.GetAppByClientID("events")
	if b.Name != "Event Planner" || b.BaseURL != a.BaseURL || strings.Join(b.Roles, ",") != "user,admin" {
		t.Errorf("app changed on re-run: %+v", b)
	}
}

func TestCopyAccess(t *testing.T) {
	st := openTest(t)
	src := &store.App{ClientID: "planner", Name: "Planner", Roles: []string{"user", "admin", "producer"},
		RedirectURIs: []string{"https://p.example.org/auth/callback"}}
	if _, err := st.CreateApp(src); err != nil {
		t.Fatal(err)
	}
	mk := func(name string) int64 {
		id, err := st.CreateUser(&store.User{Username: name}, "correct horse battery")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	admin, prod, sus, existing, none := mk("admin1"), mk("prod"), mk("sus"), mk("existing"), mk("none")
	_ = none
	set := func(u, app int64, role string, suspended bool) {
		if err := st.SetAccess(u, app, role, suspended, false, 0); err != nil {
			t.Fatal(err)
		}
	}
	set(admin, src.ID, "admin", false)
	set(prod, src.ID, "producer", false)
	set(sus, src.ID, "user", true)
	set(existing, src.ID, "admin", false)

	// Create the target first with a pre-existing row for "existing".
	run(t, st, base...)
	dst, _ := st.GetAppByClientID("events")
	set(existing, dst.ID, "user", false)

	out := run(t, st, append(base, "--copy-access-from", "planner")...)
	if !strings.Contains(out, "gave 3") && !strings.Contains(out, "Gave 3") {
		t.Errorf("summary:\n%s", out)
	}
	check := func(u int64, has bool, role string, suspended bool) {
		t.Helper()
		a, err := st.GetAccess(u, dst.ID)
		if !has {
			if err == nil && a.Has {
				t.Errorf("user %d should have no row", u)
			}
			return
		}
		if err != nil || a.Role != role || a.Suspended != suspended {
			t.Errorf("user %d: %+v, %v; want %s suspended=%v", u, a, err, role, suspended)
		}
	}
	check(admin, true, "admin", false)
	check(prod, true, "user", false)     // role fallback
	check(sus, true, "user", true)       // suspended kept
	check(existing, true, "user", false) // untouched
	check(none, false, "", false)

	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'access.grant' AND app_id = ?`, dst.ID).Scan(&n)
	if n != 3 {
		t.Errorf("audit grants = %d, want 3", n)
	}

	// Again: nothing new.
	out = run(t, st, append(base, "--copy-access-from", "planner")...)
	if !strings.Contains(out, "Gave 0") {
		t.Errorf("second copy:\n%s", out)
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	st := openTest(t)
	src := &store.App{ClientID: "planner", Name: "Planner", Roles: []string{"user", "admin"},
		RedirectURIs: []string{"https://p.example.org/auth/callback"}}
	st.CreateApp(src)
	u, _ := st.CreateUser(&store.User{Username: "a"}, "correct horse battery")
	st.SetAccess(u, src.ID, "admin", false, false, 0)

	out := run(t, st, append(base, "--copy-access-from", "planner", "--dry-run")...)
	if !strings.Contains(out, "Would register") || !strings.Contains(out, "Would give 1") || strings.Contains(out, "SSO_CLIENT_SECRET") {
		t.Errorf("dry run output:\n%s", out)
	}
	if _, err := st.GetAppByClientID("events"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("dry run registered the app: %v", err)
	}

	// Dry run against an existing app adds no rows either.
	run(t, st, base...)
	run(t, st, append(base, "--copy-access-from", "planner", "--dry-run")...)
	dst, _ := st.GetAppByClientID("events")
	if a, err := st.GetAccess(u, dst.ID); err == nil && a.Has {
		t.Error("dry run granted access")
	}
}

func TestBadInput(t *testing.T) {
	for name, args := range map[string][]string{
		"no admin role": append([]string{"--roles", "user,viewer"}, base...),
		"no name":       {"events", "--url", "https://e.example.org"},
		"bad url":       {"events", "--name", "E", "--url", "events.example.org"},
		"bad id":        {"Events", "--name", "E", "--url", "https://e.example.org"},
		"self copy":     append([]string{"--copy-access-from", "events"}, base...),
		"no id":         {"--name", "E", "--url", "https://e.example.org"},
	} {
		if _, err := ParseArgs(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := ParseArgs([]string{"-h"}, &bytes.Buffer{}); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: %v", err)
	}
	st := openTest(t)
	if err := Run(st, parse(t, append(base, "--copy-access-from", "nope")...), &bytes.Buffer{}); err == nil {
		t.Error("unknown source should fail")
	}
	if _, err := st.GetAppByClientID("events"); err == nil {
		t.Error("app registered despite bad source")
	}
}

func auditCount(t *testing.T, st *store.Store, action string) int {
	t.Helper()
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, action).Scan(&n)
	return n
}

func TestRotateSecret(t *testing.T) {
	st := openTest(t)
	run(t, st, base...)
	before := secretHash(t, st, "events")

	out := run(t, st, append(base, "--rotate-secret", "--dry-run")...)
	if !strings.Contains(out, "Would make a new secret") || strings.Contains(out, "SSO_CLIENT_SECRET") {
		t.Errorf("dry run output:\n%s", out)
	}
	if secretHash(t, st, "events") != before || auditCount(t, st, "app.secret") != 0 {
		t.Error("dry run changed something")
	}

	out = run(t, st, append(base, "--rotate-secret")...)
	if !strings.Contains(out, "SSO_CLIENT_SECRET=um_") || !strings.Contains(out, "can't sign anyone in until it's redeployed") {
		t.Errorf("output:\n%s", out)
	}
	if secretHash(t, st, "events") == before {
		t.Error("secret not changed")
	}
	if n := auditCount(t, st, "app.secret"); n != 1 {
		t.Errorf("app.secret audit rows = %d, want 1", n)
	}
}

func TestRotateUnregisteredCreates(t *testing.T) {
	st := openTest(t)
	out := run(t, st, append(base, "--rotate-secret")...)
	if !strings.Contains(out, "Registered") || !strings.Contains(out, "SSO_CLIENT_SECRET=um_") || strings.Contains(out, "WARNING") {
		t.Errorf("output:\n%s", out)
	}
	if auditCount(t, st, "app.create") != 1 || auditCount(t, st, "app.secret") != 0 {
		t.Error("audit rows wrong")
	}
	out = run(t, st, append(base, "--rotate-secret", "--dry-run")...)
	if !strings.Contains(out, "Would make a new secret") {
		t.Errorf("registered dry run:\n%s", out)
	}
	fresh := openTest(t)
	out = run(t, fresh, append(base, "--rotate-secret", "--dry-run")...)
	if !strings.Contains(out, "Would register") {
		t.Errorf("unregistered dry run:\n%s", out)
	}
}

func newEvents(t *testing.T) (*store.Store, *store.App) {
	t.Helper()
	st := openTest(t)
	run(t, st, base...)
	a, _ := st.GetAppByClientID("events")
	return st, a
}

func addUser(t *testing.T, st *store.Store, app *store.App, name, role string) int64 {
	t.Helper()
	id, err := st.CreateUser(&store.User{Username: name}, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccess(id, app.ID, role, false, false, 0); err != nil {
		t.Fatal(err)
	}
	return id
}

func roles(t *testing.T, st *store.Store) string {
	t.Helper()
	a, _ := st.GetAppByClientID("events")
	return strings.Join(a.Roles, ",")
}

func TestRolesAddForExistingApp(t *testing.T) {
	st, _ := newEvents(t)
	out := run(t, st, append(base, "--roles", "helper,planner,admin,user")...)
	if roles(t, st) != "helper,planner,admin,user" || !strings.Contains(out, "Changed roles") {
		t.Errorf("roles = %s\n%s", roles(t, st), out)
	}
	if n := auditCount(t, st, "app.update"); n != 1 {
		t.Errorf("app.update audits = %d", n)
	}
	// Same again: no change, no new audit.
	run(t, st, append(base, "--roles", "helper,planner,admin,user")...)
	if n := auditCount(t, st, "app.update"); n != 1 {
		t.Errorf("app.update audits after rerun = %d", n)
	}
}

func TestRolesRemoveInUseRefused(t *testing.T) {
	st, app := newEvents(t)
	addUser(t, st, app, "bob", "user")
	var out bytes.Buffer
	err := Run(st, parse(t, append(base, "--roles", "helper,admin")...), &out)
	var inUse *store.RoleInUseError
	if !errors.As(err, &inUse) || inUse.Role != "user" {
		t.Fatalf("err = %v", err)
	}
	if roles(t, st) != "user,admin" {
		t.Errorf("roles changed to %s", roles(t, st))
	}
	// Removing an unused role is fine.
	run(t, st, append(base, "--roles", "user,admin,extra")...)
	run(t, st, append(base, "--roles", "user,admin")...)
	if roles(t, st) != "user,admin" {
		t.Errorf("roles = %s", roles(t, st))
	}
}

func TestRenameRole(t *testing.T) {
	st, app := newEvents(t)
	a := addUser(t, st, app, "a", "user")
	b := addUser(t, st, app, "b", "user")
	c := addUser(t, st, app, "c", "admin")
	args := append(base, "--roles", "helper,planner,admin", "--rename-role", "user=helper")
	out := run(t, st, args...)
	if roles(t, st) != "helper,planner,admin" || !strings.Contains(out, "role user to helper for 2 person") {
		t.Errorf("roles = %s\n%s", roles(t, st), out)
	}
	for id, want := range map[int64]string{a: "helper", b: "helper", c: "admin"} {
		if got, _ := st.GetAccess(id, app.ID); got.Role != want {
			t.Errorf("user %d role = %s, want %s", id, got.Role, want)
		}
	}
	if n := auditCount(t, st, "access.update"); n != 2 {
		t.Errorf("access.update audits = %d, want 2", n)
	}
	if n := auditCount(t, st, "app.update"); n != 1 {
		t.Errorf("app.update audits = %d, want 1", n)
	}
	// Idempotent.
	out = run(t, st, args...)
	if strings.Contains(out, "Renamed") || auditCount(t, st, "access.update") != 2 || auditCount(t, st, "app.update") != 1 {
		t.Errorf("second run changed things:\n%s", out)
	}
}

func TestRenameWithoutRolesFlag(t *testing.T) {
	st, app := newEvents(t)
	addUser(t, st, app, "a", "user")
	run(t, st, append(base, "--rename-role", "user=helper")...)
	if roles(t, st) != "helper,admin" {
		t.Errorf("roles = %s", roles(t, st))
	}
}

func TestRolesDryRun(t *testing.T) {
	st, app := newEvents(t)
	a := addUser(t, st, app, "a", "user")
	out := run(t, st, append(base, "--roles", "helper,planner,admin", "--rename-role", "user=helper", "--dry-run")...)
	if !strings.Contains(out, "Would rename role user to helper for 1 person") || !strings.Contains(out, "Would change roles") {
		t.Errorf("dry run output:\n%s", out)
	}
	if got, _ := st.GetAccess(a, app.ID); got.Role != "user" || roles(t, st) != "user,admin" {
		t.Errorf("dry run changed things: %s, %s", got.Role, roles(t, st))
	}
	if auditCount(t, st, "access.update") != 0 || auditCount(t, st, "app.update") != 0 {
		t.Error("dry run wrote audit entries")
	}
}

func TestRolesAdminRequiredAndBadRename(t *testing.T) {
	for _, args := range [][]string{
		{"--roles", "helper,planner"},
		{"--roles", "helper,admin", "--rename-role", "user=planner"}, // new not in roles
		{"--rename-role", "user"},
		{"--rename-role", "user=user"},
	} {
		if _, err := ParseArgs(append(append([]string{}, base...), args...), &bytes.Buffer{}); err == nil {
			t.Errorf("%v: want an error", args)
		}
	}
	// Renaming admin away on an existing app leaves no admin role.
	st, _ := newEvents(t)
	var out bytes.Buffer
	if err := Run(st, parse(t, append(base, "--rename-role", "admin=owner")...), &out); err == nil {
		t.Error("renaming admin should fail")
	}
	if roles(t, st) != "user,admin" {
		t.Errorf("roles = %s", roles(t, st))
	}
}

func TestCopyFallbackRole(t *testing.T) {
	st := openTest(t)
	src := &store.App{ClientID: "planner", Name: "Planner", Roles: []string{"user", "admin", "producer"},
		RedirectURIs: []string{"https://p.example.org/auth/callback"}}
	if _, err := st.CreateApp(src); err != nil {
		t.Fatal(err)
	}
	pid, _ := st.CreateUser(&store.User{Username: "prod"}, "correct horse battery")
	st.SetAccess(pid, src.ID, "producer", false, false, 0)
	// Target without "user": first non-admin role.
	run(t, st, append(base, "--roles", "admin,helper,planner", "--copy-access-from", "planner")...)
	dst, _ := st.GetAppByClientID("events")
	if got, _ := st.GetAccess(pid, dst.ID); got.Role != "helper" {
		t.Errorf("fallback role = %q, want helper", got.Role)
	}
	// Target with "user" keeps using it.
	st2 := openTest(t)
	st2.CreateApp(&store.App{ClientID: "planner", Name: "Planner", Roles: []string{"user", "admin", "producer"},
		RedirectURIs: []string{"https://p.example.org/auth/callback"}})
	p2, _ := st2.GetAppByClientID("planner")
	pid2, _ := st2.CreateUser(&store.User{Username: "prod"}, "correct horse battery")
	st2.SetAccess(pid2, p2.ID, "producer", false, false, 0)
	run(t, st2, append(base, "--roles", "helper,user,admin", "--copy-access-from", "planner")...)
	d2, _ := st2.GetAppByClientID("events")
	if got, _ := st2.GetAccess(pid2, d2.ID); got.Role != "user" {
		t.Errorf("role = %q, want user", got.Role)
	}
}
