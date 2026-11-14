// Package registerapp implements the register-app command: register an app
// (an SSO client) from the command line, optionally copying another app's
// access list to it. It does the same thing as the Apps page, so a deploy
// can script it.
package registerapp

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/tylergoza/user-management/internal/store"
)

var (
	clientIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	roleRe     = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
)

// Options is the parsed command line.
type Options struct {
	ClientID   string
	Name       string
	URL        string
	Roles      []string
	RolesSet   bool        // --roles was given (otherwise Roles is the default for a new app)
	Renames    [][2]string // --rename-role old=new, in order
	CopyAccess string      // client ID of the app to copy access from, or ""
	DryRun     bool
	Rotate     bool // make a new secret for an app that's already registered

	// Per-app tokens and new users' role. Each is only changed on an
	// existing app when its flag is given (the *Set fields).
	ActsIn         []string // --acts-in: client IDs this app may act for users in
	ActsInSet      bool
	AcceptsFrom    []string // --accepts-from: client IDs whose tokens this app takes
	AcceptsFromSet bool
	DefaultRole    string // --default-role; "" for none
	DefaultRoleSet bool
}

// Usage is the command's help text.
const Usage = `usage: user-management [-db FILE] register-app CLIENT_ID --name NAME --url URL [flags]

Registers an app that signs people in through this service, like the Apps
page does. Its redirect URI is URL/auth/callback and its address is URL.

  --name NAME             the app's name, e.g. "Event Planner"
  --url URL               the app's address, e.g. https://events.example.org
  --roles a,b             the app's roles (default user,admin; must include admin).
                          For an app that's already registered, only given
                          explicitly: replaces its roles list (in this order).
                          Adding roles is fine; removing one that people still
                          have is refused (rename it first)
  --rename-role old=new   (repeatable) for the app, give everyone with role old
                          the role new, and swap old for new in its roles list.
                          Done before the --roles check. Safe to run again
  --copy-access-from ID   give everyone with access to the app ID the same
                          role here, unless they already have a row here
                          (a role this app doesn't have becomes user if it
                          has that role, else its first role other than admin;
                          suspended access is copied as suspended)
  --rotate-secret         for an app that's already registered, make a new
                          secret and print it once. The old secret stops
                          working at once, so the app can't sign anyone in
                          until it's redeployed with the new one. Does
                          nothing for a new app (it gets a secret anyway)
  --acts-in a,b           "May act for users in": client IDs of other registered
                          apps this app may get per-app (umd_) tokens for, to act
                          for a signed-in person. "" clears it
  --accepts-from a,b      "Accepts tokens from": client IDs of other registered
                          apps whose per-app tokens this app takes. "" clears it
  --default-role ROLE     the role people a user admin adds from now on get in
                          this app; one of its roles, never admin. "" for none
                          (the default). Renaming it with --rename-role carries
                          it along; removing it from --roles is refused unless
                          --default-role changes it too
                          For an app that's already registered, these three
                          change it only when given
  --dry-run               show what would happen without changing anything

A new app's SSO_CLIENT_ID and SSO_CLIENT_SECRET are printed once; save the
secret now. If the app is already registered nothing about it changes (the
secret stays as it is unless --rotate-secret, none is printed), so this is safe to run again;
--copy-access-from still runs, and only ever adds missing rows.
`

// ParseArgs parses the arguments after "register-app". -h prints Usage to
// errOut and returns flag.ErrHelp.
func ParseArgs(args []string, errOut io.Writer) (Options, error) {
	// The client ID comes first, but allow flags before it too.
	var o Options
	var positional []string
	var roles string
	var renames multiFlag
	fs := flag.NewFlagSet("register-app", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&o.Name, "name", "", "")
	fs.StringVar(&o.URL, "url", "", "")
	fs.StringVar(&roles, "roles", "user,admin", "")
	fs.Var(&renames, "rename-role", "")
	fs.StringVar(&o.CopyAccess, "copy-access-from", "", "")
	fs.BoolVar(&o.DryRun, "dry-run", false, "")
	fs.BoolVar(&o.Rotate, "rotate-secret", false, "")
	var actsIn, acceptsFrom string
	fs.StringVar(&actsIn, "acts-in", "", "")
	fs.StringVar(&acceptsFrom, "accepts-from", "", "")
	fs.StringVar(&o.DefaultRole, "default-role", "", "")
	rest := args
	for {
		if err := fs.Parse(rest); errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(errOut, Usage)
			return o, err
		} else if err != nil {
			return o, fmt.Errorf("register-app: %w (see register-app -h)", err)
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(positional) != 1 {
		return o, errors.New("usage: register-app CLIENT_ID --name NAME --url URL (see register-app -h)")
	}
	o.ClientID = positional[0]
	if !clientIDRe.MatchString(o.ClientID) {
		return o, errors.New("register-app: client ID must be 2 to 32 lowercase letters, numbers or dashes, starting with a letter")
	}
	o.Name = strings.TrimSpace(o.Name)
	if o.Name == "" || len(o.Name) > 100 {
		return o, errors.New("register-app: --name is required, up to 100 characters")
	}
	o.URL = strings.TrimRight(strings.TrimSpace(o.URL), "/")
	if !webURL(o.URL) {
		return o, errors.New("register-app: --url must be a full web address like https://events.example.org")
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "roles":
			o.RolesSet = true
		case "acts-in":
			o.ActsInSet = true
		case "accepts-from":
			o.AcceptsFromSet = true
		case "default-role":
			o.DefaultRoleSet = true
		}
	})
	for _, l := range []struct {
		flag string
		in   string
		out  *[]string
	}{{"--acts-in", actsIn, &o.ActsIn}, {"--accepts-from", acceptsFrom, &o.AcceptsFrom}} {
		for _, id := range strings.Split(l.in, ",") {
			if id = strings.TrimSpace(id); id == "" || slices.Contains(*l.out, id) {
				continue
			} else if !clientIDRe.MatchString(id) {
				return o, fmt.Errorf("register-app: %s: %q isn't a client ID", l.flag, id)
			} else if id == o.ClientID {
				return o, fmt.Errorf("register-app: %s can't name the app itself", l.flag)
			}
			*l.out = append(*l.out, id)
		}
	}
	o.DefaultRole = strings.ToLower(strings.TrimSpace(o.DefaultRole))
	if o.DefaultRole == "admin" {
		return o, errors.New("register-app: --default-role can't be admin: new users get it without anyone choosing")
	}
	for _, r := range strings.Split(roles, ",") {
		if r = strings.ToLower(strings.TrimSpace(r)); r == "" || slices.Contains(o.Roles, r) {
			continue
		} else if !roleRe.MatchString(r) {
			return o, fmt.Errorf("register-app: role %q must be lowercase letters, numbers, - or _", r)
		}
		o.Roles = append(o.Roles, r)
	}
	if !slices.Contains(o.Roles, "admin") {
		return o, errors.New("register-app: --roles must include admin: app admins manage people's access from inside the app")
	}
	if o.DefaultRole != "" && o.RolesSet && !slices.Contains(o.Roles, o.DefaultRole) {
		return o, fmt.Errorf("register-app: --default-role %s must be in --roles", o.DefaultRole)
	}
	for _, rn := range renames {
		old, nw, ok := strings.Cut(rn, "=")
		old, nw = strings.ToLower(strings.TrimSpace(old)), strings.ToLower(strings.TrimSpace(nw))
		if !ok || !roleRe.MatchString(old) || !roleRe.MatchString(nw) || old == nw {
			return o, fmt.Errorf("register-app: --rename-role %q must look like old=new, two different role names", rn)
		}
		if o.RolesSet && !slices.Contains(o.Roles, nw) {
			return o, fmt.Errorf("register-app: --rename-role %s=%s: %s must be in --roles", old, nw, nw)
		}
		o.Renames = append(o.Renames, [2]string{old, nw})
	}
	if o.CopyAccess == o.ClientID {
		return o, errors.New("register-app: --copy-access-from can't be the app itself")
	}
	return o, nil
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func webURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == ""
}

// Run registers the app if needed and copies access, writing a report to
// out. With DryRun it changes nothing.
func Run(st *store.Store, o Options, out io.Writer) error {
	// Check the source first, so a typo doesn't leave a half-done run.
	var src *store.App
	if o.CopyAccess != "" {
		var err error
		if src, err = st.GetAppByClientID(o.CopyAccess); errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("--copy-access-from: no app is registered as %q", o.CopyAccess)
		} else if err != nil {
			return err
		}
	}

	for _, l := range []struct {
		flag string
		ids  []string
	}{{"--acts-in", o.ActsIn}, {"--accepts-from", o.AcceptsFrom}} {
		for _, id := range l.ids {
			if _, err := st.GetAppByClientID(id); errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("%s: no app is registered as %q", l.flag, id)
			} else if err != nil {
				return err
			}
		}
	}

	app, err := st.GetAppByClientID(o.ClientID)
	exists := true
	if errors.Is(err, store.ErrNotFound) {
		exists = false
	} else if err != nil {
		return err
	}

	switch {
	case exists && o.Rotate && o.DryRun:
		fmt.Fprintf(out, "%s (%s) is already registered. Would make a new secret for it; the old one would stop working at once.\n", app.Name, app.ClientID)
	case exists && o.Rotate:
		secret, err := st.RotateAppSecret(app.ID)
		if err != nil {
			return fmt.Errorf("make a new secret for %s: %w", app.ClientID, err)
		}
		st.Audit(store.AuditEvent{Action: "app.secret", App: app.ID, Detail: "register-app: " + app.ClientID})
		fmt.Fprintf(out, "Made a new secret for %s.\n\nSSO_CLIENT_ID=%s\nSSO_CLIENT_SECRET=%s\n\nSave the secret now, e.g. as UM_%s_SECRET: it isn't shown again.\n"+
			"WARNING: the old secret no longer works, so %s can't sign anyone in until it's redeployed with the new secret.\n",
			app.Name, app.ClientID, secret, strings.ToUpper(strings.ReplaceAll(app.ClientID, "-", "_")), app.Name)
	case exists:
		fmt.Fprintf(out, "%s (%s) is already registered; its secret is unchanged.\n", app.Name, app.ClientID)
		if o.RolesSet || len(o.Renames) > 0 {
			if err := changeRoles(st, app, o, out); err != nil {
				return err
			}
		}
		if err := changeDelegation(st, app, o, out); err != nil {
			return err
		}
	case o.DryRun:
		if o.DefaultRole != "" && !slices.Contains(o.Roles, o.DefaultRole) {
			return fmt.Errorf("--default-role %s must be one of the app's roles (%s)", o.DefaultRole, strings.Join(o.Roles, ", "))
		}
		fmt.Fprintf(out, "Would register %s as %q: address %s, redirect URI %s/auth/callback, roles %s%s.\n",
			o.Name, o.ClientID, o.URL, o.URL, strings.Join(o.Roles, ", "), delegationSummary(o.ActsIn, o.AcceptsFrom, o.DefaultRole))
		app = &store.App{Name: o.Name, ClientID: o.ClientID, Roles: o.Roles}
	default:
		if o.DefaultRole != "" && !slices.Contains(o.Roles, o.DefaultRole) {
			return fmt.Errorf("--default-role %s must be one of the app's roles (%s)", o.DefaultRole, strings.Join(o.Roles, ", "))
		}
		app = &store.App{ClientID: o.ClientID, Name: o.Name, BaseURL: o.URL,
			RedirectURIs: []string{o.URL + "/auth/callback"}, Roles: o.Roles,
			ActsIn: o.ActsIn, AcceptsFrom: o.AcceptsFrom, DefaultRole: o.DefaultRole}
		secret, err := st.CreateApp(app)
		if err != nil {
			return fmt.Errorf("register %s: %w", o.ClientID, err)
		}
		st.Audit(store.AuditEvent{Action: "app.create", App: app.ID,
			Detail: "register-app: " + app.ClientID + delegationSummary(o.ActsIn, o.AcceptsFrom, o.DefaultRole)})
		fmt.Fprintf(out, "Registered %s.\n\nSSO_CLIENT_ID=%s\nSSO_CLIENT_SECRET=%s\n\nSave the secret now, e.g. as UM_%s_SECRET: it isn't shown again.\n",
			app.Name, app.ClientID, secret, strings.ToUpper(strings.ReplaceAll(app.ClientID, "-", "_")))
	}

	if src == nil {
		if o.DryRun {
			fmt.Fprintln(out, "\nDry run: nothing was changed.")
		}
		return nil
	}
	return copyAccess(st, src, app, exists, o.DryRun, out)
}

// changeRoles renames roles and/or replaces the roles list of an existing
// app, in one transaction. app is updated to the new roles.
func changeRoles(st *store.Store, app *store.App, o Options, out io.Writer) error {
	roles := o.Roles
	if !o.RolesSet {
		roles = nil
		for _, r := range app.Roles {
			for _, rn := range o.Renames {
				if r == rn[0] {
					r = rn[1]
				}
			}
			if !slices.Contains(roles, r) {
				roles = append(roles, r)
			}
		}
	}
	if !slices.Contains(roles, "admin") {
		return errors.New("roles must include admin: app admins manage people's access from inside the app")
	}
	for _, rn := range o.Renames {
		if !slices.Contains(roles, rn[1]) {
			return fmt.Errorf("--rename-role %s=%s: %s must be in the app's roles", rn[0], rn[1], rn[1])
		}
	}
	var newDefault *string
	def := app.DefaultRole
	for _, rn := range o.Renames {
		if def == rn[0] {
			def = rn[1]
		}
	}
	if o.DefaultRoleSet {
		newDefault, def = &o.DefaultRole, o.DefaultRole
	}
	moves, err := st.ChangeAppRoles(app.ID, o.Renames, roles, newDefault, o.DryRun)
	if err != nil {
		return fmt.Errorf("change roles of %s: %w", app.ClientID, err)
	}
	verb := "Renamed"
	if o.DryRun {
		verb = "Would rename"
	}
	for _, rn := range o.Renames {
		n := 0
		for _, m := range moves {
			if m.From == rn[0] && m.To == rn[1] {
				n++
			}
		}
		if n > 0 || app.HasRole(rn[0]) {
			fmt.Fprintf(out, "%s role %s to %s for %d person(s).\n", verb, rn[0], rn[1], n)
		}
	}
	if slices.Equal(app.Roles, roles) {
		fmt.Fprintf(out, "Roles are already %s.\n", strings.Join(roles, ", "))
	} else if o.DryRun {
		fmt.Fprintf(out, "Would change roles from %s to %s.\n", strings.Join(app.Roles, ", "), strings.Join(roles, ", "))
	} else {
		fmt.Fprintf(out, "Changed roles from %s to %s.\n", strings.Join(app.Roles, ", "), strings.Join(roles, ", "))
	}
	if !o.DryRun {
		for _, m := range moves {
			st.Audit(store.AuditEvent{Action: "access.update", Target: m.UserID, App: app.ID,
				Detail: "register-app: role " + m.From + " → " + m.To})
		}
		if !slices.Equal(app.Roles, roles) {
			st.Audit(store.AuditEvent{Action: "app.update", App: app.ID,
				Detail: "register-app: roles " + strings.Join(roles, ", ")})
		}
	}
	if def != app.DefaultRole {
		if o.DryRun {
			fmt.Fprintf(out, "Would set: new users get %s.\n", listOrNone([]string{def}))
		} else {
			fmt.Fprintf(out, "Set: new users get %s.\n", listOrNone([]string{def}))
			st.Audit(store.AuditEvent{Action: "app.update", App: app.ID, Detail: "register-app: new users get " + listOrNone([]string{def})})
		}
	}
	app.Roles, app.DefaultRole = roles, def
	return nil
}

// delegationSummary describes the per-app token lists and default role,
// for output and the audit log ("" when none is set).
func delegationSummary(actsIn, acceptsFrom []string, defaultRole string) string {
	var c []string
	if len(actsIn) > 0 {
		c = append(c, "may act for users in "+strings.Join(actsIn, ", "))
	}
	if len(acceptsFrom) > 0 {
		c = append(c, "accepts tokens from "+strings.Join(acceptsFrom, ", "))
	}
	if defaultRole != "" {
		c = append(c, "new users get "+defaultRole)
	}
	if len(c) == 0 {
		return ""
	}
	return "; " + strings.Join(c, "; ")
}

func listOrNone(l []string) string {
	if len(l) == 0 {
		return "(none)"
	}
	return strings.Join(l, ", ")
}

// changeDelegation sets an existing app's per-app token lists and default
// role, for the flags that were given. Run after changeRoles, so app.Roles
// and app.DefaultRole are already the new ones (changeRoles saves the
// default when it runs).
func changeDelegation(st *store.Store, app *store.App, o Options, out io.Writer) error {
	actsIn, acceptsFrom, def := app.ActsIn, app.AcceptsFrom, app.DefaultRole
	if o.ActsInSet {
		actsIn = o.ActsIn
	}
	if o.AcceptsFromSet {
		acceptsFrom = o.AcceptsFrom
	}
	if o.DefaultRoleSet {
		def = o.DefaultRole
	}
	if def != "" && !app.HasRole(def) {
		return fmt.Errorf("--default-role %s must be one of the app's roles (%s)", def, strings.Join(app.Roles, ", "))
	}
	var c []string
	if !slices.Equal(actsIn, app.ActsIn) {
		c = append(c, "may act for users in "+listOrNone(actsIn))
	}
	if !slices.Equal(acceptsFrom, app.AcceptsFrom) {
		c = append(c, "accepts tokens from "+listOrNone(acceptsFrom))
	}
	if def != app.DefaultRole {
		c = append(c, "new users get "+listOrNone([]string{def}))
	}
	if len(c) == 0 {
		return nil
	}
	if o.DryRun {
		fmt.Fprintf(out, "Would set: %s.\n", strings.Join(c, "; "))
		return nil
	}
	if err := st.SetAppDelegation(app.ID, actsIn, acceptsFrom, def); err != nil {
		return fmt.Errorf("change %s: %w", app.ClientID, err)
	}
	st.Audit(store.AuditEvent{Action: "app.update", App: app.ID, Detail: "register-app: " + strings.Join(c, "; ")})
	fmt.Fprintf(out, "Set: %s.\n", strings.Join(c, "; "))
	app.ActsIn, app.AcceptsFrom, app.DefaultRole = actsIn, acceptsFrom, def
	return nil
}

// fallbackRole is the role for someone whose role the app doesn't have:
// user if the app has it, else its first role other than admin.
func fallbackRole(a *store.App) string {
	if a.HasRole("user") {
		return "user"
	}
	for _, r := range a.Roles {
		if r != "admin" {
			return r
		}
	}
	return "admin"
}

func copyAccess(st *store.Store, src, dst *store.App, dstExists, dry bool, out io.Writer) error {
	people, err := st.ListAppUsers(src.ID)
	if err != nil {
		return err
	}
	var granted, suspended, fallback, skipped int
	for _, p := range people {
		if dstExists {
			if cur, err := st.GetAccess(p.User.ID, dst.ID); err == nil && cur.Has {
				skipped++
				continue
			} else if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		role := p.Access.Role
		if !dst.HasRole(role) {
			role = fallbackRole(dst)
			fallback++
		}
		if p.Access.Suspended {
			suspended++
		}
		granted++
		if dry {
			continue
		}
		if err := st.SetAccess(p.User.ID, dst.ID, role, p.Access.Suspended, false, 0); err != nil {
			return fmt.Errorf("give %s access to %s: %w", p.User.Username, dst.ClientID, err)
		}
		detail := "register-app: copied from " + src.ClientID + ", role " + role
		if p.Access.Suspended {
			detail += ", suspended"
		}
		st.Audit(store.AuditEvent{Action: "access.grant", Target: p.User.ID, App: dst.ID, Detail: detail})
	}
	verb := "Gave"
	if dry {
		verb = "Would give"
	}
	fmt.Fprintf(out, "\nCopy access from %s: %s %d person(s) access to %s (%d suspended, %d with a fallback role); skipped %d who already had a row.\n",
		src.ClientID, verb, granted, dst.ClientID, suspended, fallback, skipped)
	if dry {
		fmt.Fprintln(out, "\nDry run: nothing was changed.")
	}
	return nil
}
