package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/tylergoza/user-management/internal/store"
)

// The API is for the apps' servers, never browsers. Every call sends the
// app's client ID and secret with HTTP Basic auth, so the API needs no
// CSRF protection, and an app can only ever see or change its own people.
// Errors are JSON: {"error": "code", "error_description": "..."}.
//
//	GET   /api/v1/grant                        X-Grant: is this sign-in still good?
//	POST  /api/v1/logout                       X-Grant: sign out here, and so from every app
//	GET   /api/v1/apps/{client_id}/users       everyone with access to the app
//	PATCH /api/v1/apps/{client_id}/users/{id}  {"role": ...} and/or {"suspended": ...}
//	                                           X-Acting-Grant: the app admin making the change
//
// Grant IDs go in headers rather than the path, so they don't end up in
// request logs.

func (s *Server) apiRoutes(mux *http.ServeMux) {
	api := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireClient(h)) }
	api("GET /api/v1/grant", s.apiGrant)
	api("POST /api/v1/logout", s.apiLogout)
	api("GET /api/v1/apps/{client_id}/users", s.apiAppUsers)
	api("PATCH /api/v1/apps/{client_id}/users/{id}", s.apiAppUserUpdate)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})
}

func currentApp(r *http.Request) *store.App {
	a, _ := r.Context().Value(ctxApp).(*store.App)
	return a
}

// requireClient checks the app's client ID and secret (HTTP Basic auth),
// for /token and the API.
func (s *Server) requireClient(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		id, secret, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="apps"`)
			apiError(w, http.StatusUnauthorized, "invalid_client", "send the app's client ID and secret with HTTP Basic auth")
			return
		}
		app, err := s.store.AuthenticateApp(id, secret)
		if errors.Is(err, store.ErrBadClient) {
			s.log.Warn("app auth failed", "client_id", id, "ip", s.clientIP(r))
			w.Header().Set("WWW-Authenticate", `Basic realm="apps"`)
			apiError(w, http.StatusUnauthorized, "invalid_client", "unknown client ID or wrong secret")
			return
		} else if err != nil {
			s.apiServerError(w, r, err)
			return
		}
		next(w, withValue(r, ctxApp, app))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": msg})
}

func (s *Server) apiServerError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	s.log.Error("api", "path", r.URL.Path, "err", err)
	apiError(w, http.StatusInternalServerError, "server_error", "something went wrong")
}

// apiUser is a person as the apps see them. Sub is this service's user ID,
// which the apps keep as sso_subject.
type apiUser struct {
	Sub       string `json:"sub"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	UserAdmin bool   `json:"user_admin"` // can manage accounts here, for a "Manage in User Management" link
}

func apiUserOf(u *store.User, role string) apiUser {
	return apiUser{Sub: itoa(u.ID), Username: u.Username, Name: u.DisplayName, Email: u.Email, Role: role, UserAdmin: u.IsAdmin}
}

// apiAppUser is a row on an app's Users page.
type apiAppUser struct {
	apiUser
	Suspended bool   `json:"suspended"` // an admin turned their access to this app off
	Locked    bool   `json:"locked"`    // a user admin pinned it; show read-only
	Disabled  bool   `json:"disabled"`  // their whole account is turned off
	Active    bool   `json:"active"`    // can sign in to this app now
	UpdatedBy string `json:"updated_by"`
	UpdatedAt string `json:"updated_at"`
}

func apiAppUserOf(au *store.AppUser) apiAppUser {
	return apiAppUser{
		apiUser:   apiUserOf(&au.User, au.Access.Role),
		Suspended: au.Access.Suspended, Locked: au.Access.Locked, Disabled: au.User.Disabled,
		Active:    au.Access.Active() && !au.User.Disabled,
		UpdatedBy: au.Access.UpdatedByName, UpdatedAt: au.Access.UpdatedAt,
	}
}

// apiGrant tells an app whether a sign-in is still good, and who it is
// now. 401 means the session here ended, the account was turned off, the
// password changed, or their access was removed or suspended: the app
// should sign them out.
func (s *Server) apiGrant(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.CheckGrant(r.Header.Get("X-Grant"), currentApp(r).ID, s.cfg.SessionTTL)
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusUnauthorized, "invalid_grant", "signed out, or no longer allowed in this app")
		return
	} else if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": apiUserOf(&g.User, g.Role)})
}

// apiLogout ends the session here that a grant came from. Every app
// signed in from it notices at its next grant check. It always answers
// 204, so signing out twice is fine.
func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	app := currentApp(r)
	userID, err := s.store.EndGrantSession(r.Header.Get("X-Grant"), app.ID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	if userID != 0 {
		s.audit(r, store.AuditEvent{Actor: userID, Action: "app.signout", App: app.ID})
	}
	w.WriteHeader(http.StatusNoContent)
}

// ownApp checks the {client_id} in the path is the app that's calling.
func ownApp(w http.ResponseWriter, r *http.Request) (*store.App, bool) {
	app := currentApp(r)
	if r.PathValue("client_id") != app.ClientID {
		apiError(w, http.StatusForbidden, "forbidden", "an app can only see its own people")
		return nil, false
	}
	return app, true
}

// apiAppUsers lists everyone with access to the app, suspended and turned
// off included, so the app's people pickers and Users page can show
// people who haven't signed in to it yet. It needs only the app's secret:
// it's the app's own list, and it says nothing an app wouldn't learn when
// each of them signs in.
func (s *Server) apiAppUsers(w http.ResponseWriter, r *http.Request) {
	app, ok := ownApp(w, r)
	if !ok {
		return
	}
	list, err := s.store.ListAppUsers(app.ID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	users := make([]apiAppUser, 0, len(list))
	for i := range list {
		users = append(users, apiAppUserOf(&list[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": app.Roles, "users": users})
}

// apiAppUserUpdate is an app admin changing someone's role or suspending
// them, from the app's own Users page. Who's acting comes from their
// grant, and whether they're an admin of the app is checked against this
// service's records, not the app's.
func (s *Server) apiAppUserUpdate(w http.ResponseWriter, r *http.Request) {
	app, ok := ownApp(w, r)
	if !ok {
		return
	}
	actor, err := s.store.CheckGrant(r.Header.Get("X-Acting-Grant"), app.ID, s.cfg.SessionTTL)
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusUnauthorized, "invalid_grant", "send the acting admin's grant in X-Acting-Grant; theirs isn't valid")
		return
	} else if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	if actor.Role != "admin" {
		apiError(w, http.StatusForbidden, "forbidden", "only this app's admins can change people's access")
		return
	}
	targetID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var body struct {
		Role      *string `json:"role"`
		Suspended *bool   `json:"suspended"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Role == nil && body.Suspended == nil) {
		apiError(w, http.StatusBadRequest, "invalid_request", `send JSON with "role" and/or "suspended"`)
		return
	}
	old, err := s.store.AppAdminChange(app.ID, actor.User.ID, targetID, body.Role, body.Suspended)
	switch {
	case errors.Is(err, store.ErrNoAccess):
		apiError(w, http.StatusNotFound, "no_access", err.Error())
		return
	case errors.Is(err, store.ErrLocked):
		apiError(w, http.StatusForbidden, "locked", err.Error())
		return
	case errors.Is(err, store.ErrLastAdmin):
		apiError(w, http.StatusConflict, "last_admin", err.Error())
		return
	case errors.Is(err, store.ErrBadRole):
		apiError(w, http.StatusUnprocessableEntity, "bad_role", "roles for this app: "+strings.Join(app.Roles, ", "))
		return
	case err != nil:
		s.apiServerError(w, r, err)
		return
	}
	au, err := s.store.GetAppUser(app.ID, targetID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	if detail := accessChange(old, &au.Access); detail != "" {
		s.audit(r, store.AuditEvent{Actor: actor.User.ID, Action: "access.update", Target: targetID, App: app.ID, Detail: detail})
	}
	writeJSON(w, http.StatusOK, apiAppUserOf(au))
}
