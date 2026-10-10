// Package importer moves people from the maintenance tracker's and the
// production planner's own users tables into this service (the
// import-users command). See "Moving the existing user over" in PLAN.md.
package importer

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/tylergoza/user-management/internal/store"
)

// source is one sibling app the command can import from.
type source struct {
	Key      string // flag name and --prefer value
	ClientID string
	Name     string
}

var sources = []source{
	{Key: "tracker", ClientID: "tracker", Name: "Maintenance Tracker"},
	{Key: "planner", ClientID: "planner", Name: "Production Planner"},
}

// Options is the parsed command line.
type Options struct {
	TrackerDB, PlannerDB   string
	TrackerURL, PlannerURL string
	Prefer                 string // "", "tracker" or "planner"
	DryRun                 bool
}

func (o Options) dbPath(key string) string {
	if key == "tracker" {
		return o.TrackerDB
	}
	return o.PlannerDB
}

func (o Options) baseURL(key string) string {
	if key == "tracker" {
		return o.TrackerURL
	}
	return o.PlannerURL
}

// Usage is the command's help text.
const Usage = `usage: user-management [-db FILE] import-users [flags]

Copies people from the tracker's and the planner's users tables into this
service. Both databases are opened read-only; either may be left out.

  --tracker FILE        the maintenance tracker's database
  --planner FILE        the production planner's database
  --tracker-url URL     the tracker's address, e.g. https://maintenance.example.org
  --planner-url URL     the planner's address, e.g. https://planner.example.org
                        (needed only to register an app that isn't registered
                        here yet; its redirect URI is URL/auth/callback)
  --prefer tracker|planner
                        when someone's passwords differ between the apps,
                        keep this app's one
  --dry-run             show what would happen without changing anything

People are matched across the two apps by username, ignoring case. Each
becomes one user here with their existing password (the bcrypt hash is
copied, so nothing needs resetting) and access to each app they were in:
admin if they were an admin there, otherwise user.

If someone's passwords differ, the one from the app they used most recently
is kept (the later of the user's created_at and their newest session there),
unless --prefer says otherwise. The choice is printed.

The apps are registered as "tracker" and "planner" if they aren't already,
and each new client secret is printed once. An app that's already
registered keeps its secret.

User admin: if this service has no users yet, one imported person becomes a
user admin here: an admin of both apps if there is one, otherwise an admin
of either, alphabetically by username. If nobody imported is an admin, no
one is; add one with create-user --admin.

Safe to run again: people who already have an account here are left as
they are (password, name and admin flag untouched); they're only given
access to an app they don't have a row for yet. Existing access is never
changed.
`

// ParseArgs parses the arguments after "import-users". Messages about bad
// flags are returned; -h prints Usage to errOut and returns flag.ErrHelp.
func ParseArgs(args []string, errOut io.Writer) (Options, error) {
	var o Options
	fs := flag.NewFlagSet("import-users", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are returned, and printed once by the caller
	fs.Usage = func() {}
	fs.StringVar(&o.TrackerDB, "tracker", "", "")
	fs.StringVar(&o.PlannerDB, "planner", "", "")
	fs.StringVar(&o.TrackerURL, "tracker-url", "", "")
	fs.StringVar(&o.PlannerURL, "planner-url", "", "")
	fs.StringVar(&o.Prefer, "prefer", "", "")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(errOut, Usage)
		return o, err
	} else if err != nil {
		return o, fmt.Errorf("import-users: %w (see import-users -h)", err)
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("import-users: unexpected argument %q (see import-users -h)", fs.Arg(0))
	}
	if o.TrackerDB == "" && o.PlannerDB == "" {
		return o, errors.New("import-users: give --tracker, --planner or both (see import-users -h)")
	}
	if o.Prefer != "" && o.Prefer != "tracker" && o.Prefer != "planner" {
		return o, fmt.Errorf("import-users: --prefer must be tracker or planner, not %q", o.Prefer)
	}
	for _, src := range sources {
		u := strings.TrimRight(strings.TrimSpace(o.baseURL(src.Key)), "/")
		if u == "" {
			continue
		}
		if o.dbPath(src.Key) == "" {
			return o, fmt.Errorf("import-users: --%s-url needs --%s", src.Key, src.Key)
		}
		if !webURL(u) {
			return o, fmt.Errorf("import-users: --%s-url must be a full web address like https://%s.example.org", src.Key, src.Key)
		}
		if src.Key == "tracker" {
			o.TrackerURL = u
		} else {
			o.PlannerURL = u
		}
	}
	return o, nil
}

func webURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == ""
}

// sourceUser is a row from a sibling app's users table.
type sourceUser struct {
	App         string // source key
	Username    string
	DisplayName string
	Hash        string
	IsAdmin     bool
	LastSeen    string // later of created_at and newest session, "" if unknown
}

func (u *sourceUser) role() string {
	if u.IsAdmin {
		return "admin"
	}
	return "user"
}

// readSource reads a sibling app's users, opening the database read-only.
func readSource(app, path string) ([]sourceUser, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%s database: %w", app, err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	users, err := columns(db, "users")
	if err != nil {
		return nil, fmt.Errorf("%s database: %w", app, err)
	}
	for _, c := range []string{"id", "username", "password_hash", "is_admin"} {
		if !users[c] {
			return nil, fmt.Errorf("%s database %s: users table has no %s column; is this the right file?", app, path, c)
		}
	}
	display, created, lastSession := "''", "''", "''"
	if users["display_name"] {
		display = "COALESCE(u.display_name, '')"
	}
	if users["created_at"] {
		created = "COALESCE(u.created_at, '')"
	}
	if sess, _ := columns(db, "sessions"); sess["user_id"] && sess["created_at"] {
		lastSession = "COALESCE((SELECT MAX(s.created_at) FROM sessions s WHERE s.user_id = u.id), '')"
	}
	rows, err := db.Query(`SELECT u.username, ` + display + `, COALESCE(u.password_hash, ''), u.is_admin, ` +
		created + `, ` + lastSession + ` FROM users u ORDER BY u.id`)
	if err != nil {
		return nil, fmt.Errorf("%s database: %w", app, err)
	}
	defer rows.Close()
	var out []sourceUser
	for rows.Next() {
		u := sourceUser{App: app}
		var created, session string
		if err := rows.Scan(&u.Username, &u.DisplayName, &u.Hash, &u.IsAdmin, &created, &session); err != nil {
			return nil, fmt.Errorf("%s database: %w", app, err)
		}
		u.Username, u.DisplayName = strings.TrimSpace(u.Username), strings.TrimSpace(u.DisplayName)
		u.LastSeen = max(created, session) // UTC "YYYY-MM-DD HH:MM:SS" compares as text
		out = append(out, u)
	}
	return out, rows.Err()
}

// columns returns the column names of table (none if it doesn't exist).
func columns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		cols[strings.ToLower(name)] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("no %s table", table)
	}
	return cols, nil
}

// person is everyone with one username, across both apps.
type person struct {
	From      map[string]*sourceUser // by source key
	Chosen    *sourceUser            // whose password (and spelling) to use
	Note      string                 // why, when the passwords differed
	UserAdmin bool
}

func (p *person) adminCount() int {
	n := 0
	for _, u := range p.From {
		if u.IsAdmin {
			n++
		}
	}
	return n
}

// foldASCII lowercases ASCII letters only, the way SQLite's NOCASE does.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

func validHash(h string) bool {
	_, err := bcrypt.Cost([]byte(h))
	return err == nil
}

// choose picks whose password to keep for p.
func (p *person) choose(prefer string) {
	var cands []*sourceUser
	for _, src := range sources {
		if u := p.From[src.Key]; u != nil && validHash(u.Hash) {
			cands = append(cands, u)
		}
	}
	switch {
	case len(cands) == 0:
		return
	case len(cands) == 1 || cands[0].Hash == cands[1].Hash:
		p.Chosen = cands[0]
		return
	}
	t, pl := cands[0], cands[1]
	switch {
	case prefer != "":
		p.Chosen = p.From[prefer]
		p.Note = "passwords differ: using the " + prefer + "'s (--prefer)"
	case t.LastSeen == pl.LastSeen:
		p.Chosen = t
		p.Note = "passwords differ and it's unclear which is newer: using the tracker's (use --prefer to choose)"
	default:
		newer, older := t, pl
		if pl.LastSeen > t.LastSeen {
			newer, older = pl, t
		}
		p.Chosen = newer
		p.Note = fmt.Sprintf("passwords differ: using the %s's, used more recently (%s, vs %s in the %s)",
			newer.App, orUnknown(newer.LastSeen), orUnknown(older.LastSeen), older.App)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Run does the import (or, with DryRun, only reports what it would do),
// writing a report to out.
func Run(st *store.Store, o Options, out io.Writer) error {
	if o.DryRun {
		fmt.Fprintln(out, "Dry run: nothing will be changed.")
	}
	would := func(done, planned string) string {
		if o.DryRun {
			return planned
		}
		return done
	}

	// Read everything and check the apps first, so a mistake stops the
	// import before anything is written.
	people := map[string]*person{}
	var order []string
	for _, src := range sources {
		path := o.dbPath(src.Key)
		if path == "" {
			continue
		}
		users, err := readSource(src.Key, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Read %d user(s) from the %s: %s\n", len(users), src.Key, path)
		for i := range users {
			key := foldASCII(users[i].Username)
			if key == "" {
				continue
			}
			p := people[key]
			if p == nil {
				p = &person{From: map[string]*sourceUser{}}
				people[key] = p
				order = append(order, key)
			}
			p.From[src.Key] = &users[i]
		}
	}
	slices.Sort(order)

	apps := map[string]*store.App{} // registered apps, by source key
	var toRegister []source
	for _, src := range sources {
		if o.dbPath(src.Key) == "" {
			continue
		}
		a, err := st.GetAppByClientID(src.ClientID)
		switch {
		case err == nil:
			apps[src.Key] = a
		case errors.Is(err, store.ErrNotFound):
			if o.baseURL(src.Key) == "" {
				return fmt.Errorf("the %s isn't registered here yet: give --%s-url so it can be", src.Key, src.Key)
			}
			toRegister = append(toRegister, src)
		default:
			return err
		}
	}

	for _, key := range order {
		people[key].choose(o.Prefer)
	}

	// User admin: only when this service is empty, so an import never
	// changes who runs an existing one.
	if n, err := st.CountUsers(); err != nil {
		return err
	} else if n == 0 {
		var best *person
		for _, key := range order {
			p := people[key]
			if p.Chosen != nil && p.adminCount() > 0 && (best == nil || p.adminCount() > best.adminCount()) {
				best = p
			}
		}
		if best != nil {
			best.UserAdmin = true
		}
	}

	// Apps.
	fmt.Fprintln(out, "\nApps")
	for _, src := range sources {
		if a := apps[src.Key]; a != nil {
			fmt.Fprintf(out, "  %s: already registered as %q; its secret is unchanged\n", src.ClientID, a.Name)
		}
	}
	for _, src := range toRegister {
		base := o.baseURL(src.Key)
		a := &store.App{ClientID: src.ClientID, Name: src.Name, BaseURL: base,
			RedirectURIs: []string{base + "/auth/callback"}, Roles: []string{"user", "admin"}}
		fmt.Fprintf(out, "  %s: %s %q at %s\n", src.ClientID, would("registered", "would register"), src.Name, base)
		if o.DryRun {
			apps[src.Key] = a
			continue
		}
		secret, err := st.CreateApp(a)
		if err != nil {
			return fmt.Errorf("register the %s: %w", src.Key, err)
		}
		st.Audit(store.AuditEvent{Action: "app.create", App: a.ID, Detail: "import-users"})
		apps[src.Key] = a
		fmt.Fprintf(out, "    SSO_CLIENT_ID=%s\n    SSO_CLIENT_SECRET=%s\n", a.ClientID, secret)
		fmt.Fprintf(out, "    Save the secret now, e.g. as UM_%s_SECRET in the environment for the %s's deploy: it isn't shown again.\n",
			strings.ToUpper(src.Key), src.Key)
	}

	// People.
	fmt.Fprintln(out, "\nUsers")
	var created, skipped, failed, granted int
	for _, key := range order {
		p := people[key]
		if p.Chosen == nil {
			name := ""
			for _, u := range p.From {
				name = u.Username
			}
			fmt.Fprintf(out, "  %s: skipped, no usable password hash in either app\n", name)
			failed++
			continue
		}
		u := p.Chosen
		display := u.DisplayName
		for _, src := range sources {
			if other := p.From[src.Key]; display == "" && other != nil {
				display = other.DisplayName
			}
		}

		existing, err := st.GetUserByUsername(u.Username)
		var userID int64
		switch {
		case err == nil:
			userID = existing.ID
			fmt.Fprintf(out, "  %s: already here, left as is (password, name and admin unchanged)\n", existing.Username)
			skipped++
		case errors.Is(err, store.ErrNotFound):
			msg := would("created", "would create")
			if p.UserAdmin {
				msg += ", user admin here"
			}
			fmt.Fprintf(out, "  %s: %s\n", u.Username, msg)
			if p.Note != "" {
				fmt.Fprintf(out, "    %s\n", p.Note)
			}
			created++
			if !o.DryRun {
				userID, err = st.ImportUser(&store.User{Username: u.Username, DisplayName: display, IsAdmin: p.UserAdmin}, u.Hash)
				if err != nil {
					return fmt.Errorf("create %s: %w", u.Username, err)
				}
				detail := "import-users: password from the " + u.App
				if p.UserAdmin {
					detail += "; user admin"
				}
				st.Audit(store.AuditEvent{Action: "user.import", Target: userID, Detail: detail})
			}
		default:
			return err
		}

		for _, src := range sources {
			su := p.From[src.Key]
			app := apps[src.Key]
			if su == nil || app == nil {
				continue
			}
			if userID != 0 && app.ID != 0 {
				if _, err := st.GetAccess(userID, app.ID); err == nil {
					continue // already has a row: never change it
				} else if !errors.Is(err, store.ErrNotFound) {
					return err
				}
			}
			fmt.Fprintf(out, "    %s %s: %s\n", would("gave", "would give"), src.ClientID, su.role())
			granted++
			if o.DryRun {
				continue
			}
			if err := st.SetAccess(userID, app.ID, su.role(), false, false, 0); err != nil {
				return fmt.Errorf("give %s access to the %s: %w", u.Username, src.Key, err)
			}
			st.Audit(store.AuditEvent{Action: "access.grant", Target: userID, App: app.ID, Detail: "import-users: role " + su.role()})
		}
	}

	if o.DryRun {
		fmt.Fprintf(out, "\nDry run: would create %d user(s), skip %d already here, give %d app access(es)", created, skipped, granted)
	} else {
		fmt.Fprintf(out, "\nDone: created %d user(s), skipped %d already here, gave %d app access(es)", created, skipped, granted)
	}
	if failed > 0 {
		fmt.Fprintf(out, ", %d without a usable password", failed)
	}
	fmt.Fprintln(out, ".")
	if n, _ := st.CountActiveAdmins(); n == 0 && !anyUserAdmin(people) {
		fmt.Fprintln(out, "No user admin here yet: add one with create-user NAME --admin.")
	}
	return nil
}

func anyUserAdmin(people map[string]*person) bool {
	for _, p := range people {
		if p.UserAdmin {
			return true
		}
	}
	return false
}
