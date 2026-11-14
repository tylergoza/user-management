package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/tylergoza/user-management/internal/store"
)

// Per-app tokens: an app holding a person's grant (first, the MCP server)
// gets a short umd_ token to act for them in another app, which checks it
// here. Both apps opt in on the Apps page. See MEMBERS_PLAN.md.
//
// Today the acting app is always a confidential one (Basic auth plus
// X-Grant). Browser (public) grants will come in through actingGrant too.

// actingGrant checks the calling app's grant for the person it's acting
// for (X-Grant). It answers 401 invalid_grant itself when it isn't good.
// Using it counts as using the grant, like a grant check.
func (s *Server) actingGrant(w http.ResponseWriter, r *http.Request) (*store.Grant, string, bool) {
	grantID := r.Header.Get("X-Grant")
	g, err := s.store.CheckGrant(grantID, currentApp(r).ID, s.cfg.SessionTTL)
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusUnauthorized, "invalid_grant", "signed out, or no longer allowed in this app")
		return nil, "", false
	} else if err != nil {
		s.apiServerError(w, r, err)
		return nil, "", false
	}
	return g, grantID, true
}

// apiMeApps lists the apps the person has a role in that the calling app
// may act in for them (both apps opt in), so it knows which it can offer.
func (s *Server) apiMeApps(w http.ResponseWriter, r *http.Request) {
	g, _, ok := s.actingGrant(w, r)
	if !ok {
		return
	}
	list, err := s.store.DelegableApps(currentApp(r).ID, g.User.ID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	type meApp struct {
		Audience string `json:"audience"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		URL      string `json:"url"`
	}
	apps := make([]meApp, 0, len(list))
	for _, d := range list {
		apps = append(apps, meApp{Audience: d.App.ClientID, Name: d.App.Name, Role: d.Role, URL: d.App.BaseURL})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
}

// delegateAuditEvery limits token.delegate entries in the audit log to one
// per person, acting app and audience in this time.
const delegateAuditEvery = time.Hour

// apiDelegate gives the calling app a umd_ token to act for the person
// whose grant it sends, in one other app (the audience). Checks, in
// order: the grant (401 invalid_grant), the audience exists (404
// unknown_audience), both apps opt in (403 not_accepted), the person has
// unsuspended access there (403 no_access).
func (s *Server) apiDelegate(w http.ResponseWriter, r *http.Request) {
	app := currentApp(r)
	g, grantID, ok := s.actingGrant(w, r)
	if !ok {
		return
	}
	var body struct {
		Audience string `json:"audience"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Audience) == "" {
		apiError(w, http.StatusBadRequest, "invalid_request", `send JSON with "audience": the client ID of the app to act in`)
		return
	}
	audience, err := s.store.GetAppByClientID(strings.TrimSpace(body.Audience))
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusNotFound, "unknown_audience", "no app is registered with that client ID")
		return
	} else if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	if !app.MayActIn(audience) {
		apiError(w, http.StatusForbidden, "not_accepted", "this app may not act for people in "+audience.ClientID+
			` (it needs "May act for users in" and that app needs "Accepts tokens from")`)
		return
	}
	role, err := s.store.AppRole(g.User.ID, audience.ID)
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusForbidden, "no_access", "they have no access to "+audience.ClientID)
		return
	} else if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	token, err := s.store.CreateDelegatedToken(grantID, audience.ID, g.User.ID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	ev := store.AuditEvent{Actor: g.User.ID, Action: "token.delegate", App: audience.ID, Detail: "via " + app.ClientID}
	if seen, err := s.store.AuditedSince(ev, time.Now().Add(-delegateAuditEvery)); err != nil {
		s.log.Error("audit log", "action", ev.Action, "err", err)
	} else if !seen {
		s.audit(r, ev)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token, "expires_in": int(store.DelegatedTTL.Seconds()), "role": role,
	})
}

// apiToken is the audience app checking a umd_ token it was sent. Every
// failure is the same 401 invalid_token, so a caller can't tell a token
// for another app from an expired one; the acting app should ask for a
// new token. A check doesn't count as using the grant.
func (s *Server) apiToken(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.CheckDelegatedToken(r.Header.Get("X-Token"), currentApp(r).ID)
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusUnauthorized, "invalid_token", "the token is expired, revoked or not for this app; ask for a new one")
		return
	} else if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": apiUserOf(&d.User, d.Role), "via": d.Via})
}
