package server

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/tylergoza/user-management/internal/store"
)

// Apps -------------------------------------------------------------------

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListApps()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "admin/apps/index", map[string]any{"Title": "Apps", "Apps": apps})
}

func (s *Server) handleAppNew(w http.ResponseWriter, r *http.Request) {
	s.renderAppForm(w, r, http.StatusOK, map[string]any{"Title": "Register an app", "Form": appForm{Roles: "user, admin"}})
}

// renderAppForm shows the app form, with the other registered apps for
// the two per-app token lists.
func (s *Server) renderAppForm(w http.ResponseWriter, r *http.Request, status int, data map[string]any) {
	apps, err := s.store.ListApps()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	self := data["Form"].(appForm).ID
	var others []store.App
	for _, a := range apps {
		if a.ID != self {
			others = append(others, a)
		}
	}
	data["OtherApps"] = others
	s.render(w, r, status, "admin/apps/form", data)
}

// appForm is the app form as typed, so it can be shown again with errors.
type appForm struct {
	ID           int64
	ClientID     string
	Name         string
	BaseURL      string
	RedirectURIs string
	Roles        string
	ActsIn       []string // client IDs
	AcceptsFrom  []string // client IDs
	DefaultRole  string
}

func appFormOf(a *store.App) appForm {
	return appForm{ID: a.ID, ClientID: a.ClientID, Name: a.Name, BaseURL: a.BaseURL,
		RedirectURIs: strings.Join(a.RedirectURIs, "\n"), Roles: strings.Join(a.Roles, ", "),
		ActsIn: a.ActsIn, AcceptsFrom: a.AcceptsFrom, DefaultRole: a.DefaultRole}
}

func readAppForm(r *http.Request) appForm {
	return appForm{ClientID: formStr(r, "client_id"), Name: formStr(r, "name"), BaseURL: formStr(r, "base_url"),
		RedirectURIs: formStr(r, "redirect_uris"), Roles: formStr(r, "roles"),
		ActsIn: formList(r, "acts_in"), AcceptsFrom: formList(r, "accepts_from"), DefaultRole: formStr(r, "default_role")}
}

// RoleList is the roles as typed, for the default role select.
func (f appForm) RoleList() []string {
	var out []string
	for _, r := range strings.Split(f.Roles, ",") {
		if r = strings.ToLower(strings.TrimSpace(r)); r != "" && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// formList is a form field sent several times (checkboxes), trimmed,
// without blanks or repeats.
func formList(r *http.Request, key string) []string {
	r.ParseForm()
	var out []string
	for _, v := range r.PostForm[key] {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

var (
	clientIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	roleRe     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
)

// validate checks the form and fills in a (all but the client ID, which
// only a new app sets). clientIDs are the registered apps', for the two
// per-app token lists; selfID is the app's own client ID.
func (f *appForm) validate(a *store.App, clientIDs []string, selfID string) []string {
	var errs []string
	a.Name, a.BaseURL = f.Name, f.BaseURL
	if f.Name == "" || len(f.Name) > 100 {
		errs = append(errs, "Name is required, up to 100 characters.")
	}
	if f.BaseURL != "" && !webURL(f.BaseURL) {
		errs = append(errs, "Address must be a full web address, like https://planner.example.org.")
	}
	a.RedirectURIs = nil
	for _, line := range strings.Split(f.RedirectURIs, "\n") {
		if line = strings.TrimSpace(line); line == "" || slices.Contains(a.RedirectURIs, line) {
			continue
		}
		if !webURL(line) || strings.Contains(line, "#") {
			errs = append(errs, "Redirect URI "+quoteOrNone(line)+" must be a full web address with no #fragment.")
		}
		a.RedirectURIs = append(a.RedirectURIs, line)
	}
	if len(a.RedirectURIs) == 0 {
		errs = append(errs, "Add at least one redirect URI: the app's sign-in callback, like https://planner.example.org/auth/callback.")
	}
	a.Roles = nil
	for _, role := range strings.Split(f.Roles, ",") {
		if role = strings.ToLower(strings.TrimSpace(role)); role == "" || slices.Contains(a.Roles, role) {
			continue
		}
		if !roleRe.MatchString(role) {
			errs = append(errs, "Role "+quoteOrNone(role)+" must be lowercase letters, numbers, - or _.")
		}
		a.Roles = append(a.Roles, role)
	}
	if !slices.Contains(a.Roles, "admin") {
		errs = append(errs, "Roles must include admin: app admins manage people's access from inside the app.")
	}
	a.ActsIn, a.AcceptsFrom, a.DefaultRole = f.ActsIn, f.AcceptsFrom, f.DefaultRole
	for _, list := range []struct {
		label string
		ids   []string
	}{{"May act for users in", f.ActsIn}, {"Accepts tokens from", f.AcceptsFrom}} {
		for _, id := range list.ids {
			if id == selfID || !slices.Contains(clientIDs, id) {
				errs = append(errs, list.label+": "+quoteOrNone(id)+" isn't another registered app.")
			}
		}
	}
	if f.DefaultRole != "" {
		if f.DefaultRole == "admin" {
			errs = append(errs, "New users can't get admin by default: pick another role, or no default.")
		} else if !slices.Contains(a.Roles, f.DefaultRole) {
			errs = append(errs, "New users' role "+quoteOrNone(f.DefaultRole)+" must be one of the app's roles.")
		}
	}
	return errs
}

// clientIDs lists every registered app's client ID.
func (s *Server) clientIDs() ([]string, error) {
	apps, err := s.store.ListApps()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(apps))
	for _, a := range apps {
		ids = append(ids, a.ClientID)
	}
	return ids, nil
}

// webURL reports whether s is an absolute http(s) address.
func webURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}

func (s *Server) handleAppCreate(w http.ResponseWriter, r *http.Request) {
	f := readAppForm(r)
	a := store.App{ClientID: f.ClientID}
	ids, err := s.clientIDs()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	errs := f.validate(&a, ids, f.ClientID)
	if !clientIDRe.MatchString(f.ClientID) {
		errs = append(errs, "Client ID must be 2 to 32 lowercase letters, numbers or dashes, starting with a letter.")
	}
	var secret string
	if len(errs) == 0 {
		var err error
		secret, err = s.store.CreateApp(&a)
		if isUnique(err) {
			errs = append(errs, "Another app already has that client ID.")
		} else if err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if len(errs) > 0 {
		s.renderAppForm(w, r, http.StatusUnprocessableEntity, map[string]any{"Title": "Register an app", "Form": f, "Errors": errs})
		return
	}
	detail := a.ClientID
	if changes := appChanges(&store.App{Name: a.Name, BaseURL: a.BaseURL, RedirectURIs: a.RedirectURIs, Roles: a.Roles}, &a); changes != "" {
		detail += "; " + changes
	}
	s.audit(r, store.AuditEvent{Action: "app.create", App: a.ID, Detail: detail})
	s.renderSecret(w, r, &a, secret, true)
}

// renderSecret shows a new client secret, the only time it's ever shown.
// It isn't put in a flash cookie or a redirect. Alongside it are the other
// two values the app's Connections page asks for.
func (s *Server) renderSecret(w http.ResponseWriter, r *http.Request, a *store.App, secret string, isNew bool) {
	s.render(w, r, http.StatusOK, "admin/apps/secret", map[string]any{
		"Title": a.Name + " secret", "App": a, "Secret": secret, "New": isNew, "Address": s.ownAddress(r),
	})
}

// ownAddress is this service's address as the browser reached it, which
// is the one the apps send people to for signing in.
func (s *Server) ownAddress(r *http.Request) string {
	if s.isHTTPS(r) {
		return "https://" + r.Host
	}
	return "http://" + r.Host
}

func (s *Server) handleAppEdit(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetApp(pathID(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderAppForm(w, r, http.StatusOK, map[string]any{"Title": "Edit " + a.Name, "Form": appFormOf(a), "App": a})
}

func (s *Server) handleAppUpdate(w http.ResponseWriter, r *http.Request) {
	old, err := s.store.GetApp(pathID(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	f := readAppForm(r)
	f.ID, f.ClientID = old.ID, old.ClientID
	a := *old
	ids, err := s.clientIDs()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	errs := f.validate(&a, ids, old.ClientID)
	for _, role := range old.Roles {
		if slices.Contains(a.Roles, role) {
			continue
		}
		if n, err := s.store.RoleInUse(a.ID, role); err != nil {
			s.serverError(w, r, err)
			return
		} else if n > 0 {
			errs = append(errs, "Can't remove the "+role+" role: "+peopleAre(n)+" using it. Change their role first.")
		}
	}
	if len(errs) > 0 {
		s.renderAppForm(w, r, http.StatusUnprocessableEntity, map[string]any{"Title": "Edit " + old.Name, "Form": f, "App": old, "Errors": errs})
		return
	}
	if err := s.store.UpdateApp(&a); err != nil {
		s.serverError(w, r, err)
		return
	}
	if changes := appChanges(old, &a); changes != "" {
		s.audit(r, store.AuditEvent{Action: "app.update", App: a.ID, Detail: changes})
	}
	s.redirect(w, r, "/admin/apps", a.Name+" saved.")
}

func peopleAre(n int) string {
	if n == 1 {
		return "1 person is"
	}
	return strconv.Itoa(n) + " people are"
}

// appChanges describes an app edit for the audit log.
func appChanges(old, a *store.App) string {
	var c []string
	if old.Name != a.Name {
		c = append(c, "name "+quoteOrNone(old.Name)+" → "+quoteOrNone(a.Name))
	}
	if old.BaseURL != a.BaseURL {
		c = append(c, "address "+quoteOrNone(old.BaseURL)+" → "+quoteOrNone(a.BaseURL))
	}
	if !slices.Equal(old.RedirectURIs, a.RedirectURIs) {
		c = append(c, "redirect URIs "+strings.Join(a.RedirectURIs, " "))
	}
	if !slices.Equal(old.Roles, a.Roles) {
		c = append(c, "roles "+strings.Join(a.Roles, ", "))
	}
	if !slices.Equal(old.ActsIn, a.ActsIn) {
		c = append(c, "may act for users in "+listOrNone(a.ActsIn))
	}
	if !slices.Equal(old.AcceptsFrom, a.AcceptsFrom) {
		c = append(c, "accepts tokens from "+listOrNone(a.AcceptsFrom))
	}
	if old.DefaultRole != a.DefaultRole {
		c = append(c, "new users get "+quoteOrNone(old.DefaultRole)+" → "+quoteOrNone(a.DefaultRole))
	}
	return strings.Join(c, "; ")
}

func listOrNone(l []string) string {
	if len(l) == 0 {
		return "(none)"
	}
	return strings.Join(l, ", ")
}

func (s *Server) handleAppSecret(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetApp(pathID(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	secret, err := s.store.RotateAppSecret(a.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{Action: "app.secret", App: a.ID})
	s.renderSecret(w, r, a, secret, false)
}

// App access -------------------------------------------------------------

// appAccess pairs an app with someone's access to it, for their page.
type appAccess struct {
	App    store.App
	Access store.Access
}

// handleUserAccess is a user admin granting, changing or removing
// someone's access to an app. User admins can change anything, including
// rows they or another user admin locked.
func (s *Server) handleUserAccess(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUser(pathID(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	appID, _ := strconv.ParseInt(r.PathValue("app"), 10, 64)
	app, err := s.store.GetApp(appID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	back := "/admin/users/" + itoa(u.ID)
	role := formStr(r, "role")
	if role != "" && !app.HasRole(role) {
		s.setFlash(w, r, "error", app.Name+" has no "+role+" role.")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	old, err := s.store.GetAccess(u.ID, app.ID)
	if errors.Is(err, store.ErrNotFound) {
		old = &store.Access{}
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	next := store.Access{Has: role != "", Role: role,
		Suspended: role != "" && r.PostFormValue("suspended") == "1",
		Locked:    role != "" && r.PostFormValue("locked") == "1"}
	if err := s.store.SetAccess(u.ID, app.ID, next.Role, next.Suspended, next.Locked, currentUser(r).ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	action := "access.update"
	switch {
	case !old.Has && next.Has:
		action = "access.grant"
	case old.Has && !next.Has:
		action = "access.remove"
	}
	if detail := accessChange(old, &next); detail != "" || action != "access.update" {
		s.audit(r, store.AuditEvent{Action: action, Target: u.ID, App: app.ID, Detail: detail})
	}
	s.redirect(w, r, back, u.Username+"'s access to "+app.Name+" saved.")
}

// accessChange describes a change to someone's app access for the audit
// log, e.g. "role user → admin; suspended".
func accessChange(old, next *store.Access) string {
	if !next.Has {
		return ""
	}
	var c []string
	switch {
	case !old.Has:
		c = append(c, "as "+next.Role)
	case old.Role != next.Role:
		c = append(c, "role "+old.Role+" → "+next.Role)
	}
	if old.Suspended != next.Suspended {
		if next.Suspended {
			c = append(c, "suspended")
		} else if old.Has {
			c = append(c, "restored")
		}
	}
	if old.Locked != next.Locked {
		if next.Locked {
			c = append(c, "locked")
		} else if old.Has {
			c = append(c, "unlocked")
		}
	}
	return strings.Join(c, "; ")
}
