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
	s.render(w, r, http.StatusOK, "admin/apps/form", map[string]any{
		"Title": "Register an app", "Form": appForm{Roles: "user, admin"},
	})
}

// appForm is the app form as typed, so it can be shown again with errors.
type appForm struct {
	ID           int64
	ClientID     string
	Name         string
	BaseURL      string
	RedirectURIs string
	Roles        string
}

func appFormOf(a *store.App) appForm {
	return appForm{ID: a.ID, ClientID: a.ClientID, Name: a.Name, BaseURL: a.BaseURL,
		RedirectURIs: strings.Join(a.RedirectURIs, "\n"), Roles: strings.Join(a.Roles, ", ")}
}

func readAppForm(r *http.Request) appForm {
	return appForm{ClientID: formStr(r, "client_id"), Name: formStr(r, "name"), BaseURL: formStr(r, "base_url"),
		RedirectURIs: formStr(r, "redirect_uris"), Roles: formStr(r, "roles")}
}

var (
	clientIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	roleRe     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
)

// validate checks the form and fills in a (all but the client ID, which
// only a new app sets).
func (f *appForm) validate(a *store.App) []string {
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
	return errs
}

// webURL reports whether s is an absolute http(s) address.
func webURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}

func (s *Server) handleAppCreate(w http.ResponseWriter, r *http.Request) {
	f := readAppForm(r)
	a := store.App{ClientID: f.ClientID}
	errs := f.validate(&a)
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
		s.render(w, r, http.StatusUnprocessableEntity, "admin/apps/form", map[string]any{"Title": "Register an app", "Form": f, "Errors": errs})
		return
	}
	s.audit(r, store.AuditEvent{Action: "app.create", App: a.ID, Detail: a.ClientID})
	s.renderSecret(w, r, &a, secret, true)
}

// renderSecret shows a new client secret, the only time it's ever shown.
// It isn't put in a flash cookie or a redirect.
func (s *Server) renderSecret(w http.ResponseWriter, r *http.Request, a *store.App, secret string, isNew bool) {
	s.render(w, r, http.StatusOK, "admin/apps/secret", map[string]any{
		"Title": a.Name + " secret", "App": a, "Secret": secret, "New": isNew,
	})
}

func (s *Server) handleAppEdit(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.GetApp(pathID(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "admin/apps/form", map[string]any{"Title": "Edit " + a.Name, "Form": appFormOf(a), "App": a})
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
	errs := f.validate(&a)
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
		s.render(w, r, http.StatusUnprocessableEntity, "admin/apps/form", map[string]any{"Title": "Edit " + old.Name, "Form": f, "App": old, "Errors": errs})
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
	return strings.Join(c, "; ")
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
