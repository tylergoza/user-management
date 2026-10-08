package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/tylergoza/user-management/internal/store"
)

// Single sign-on is the OAuth 2 authorization code flow with PKCE, kept
// small:
//
//  1. The app sends the browser to /authorize with its client_id, a
//     registered redirect_uri, a state and a PKCE S256 code_challenge.
//  2. Once signed in here (straight away, if they already were), the
//     browser goes back to redirect_uri with a code that works once, for
//     60 seconds.
//  3. The app POSTs the code, the redirect_uri and its code_verifier to
//     /token with its client ID and secret, and gets back a grant ID and
//     who signed in, with their role in that app.
//
// The app then keeps its own session, and checks the grant every few
// minutes at /api/v1/grant (see api.go).

// handleAuthorize starts an app's sign-in. Until the app and redirect URI
// check out, problems are shown here: redirecting to an unchecked address
// would make this an open redirect. After that they go back to the app as
// OAuth errors.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	app, err := s.store.GetAppByClientID(q.Get("client_id"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if app == nil || !app.RedirectAllowed(redirectURI) {
		s.render(w, r, http.StatusBadRequest, "error", map[string]any{
			"Title":   "This sign-in link isn't right",
			"Message": "The app that sent you here isn't set up to sign in this way. Let a user admin know which app it was.",
		})
		return
	}
	state := q.Get("state")
	back := func(params url.Values) {
		if state != "" {
			params.Set("state", state)
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, addQuery(redirectURI, params), http.StatusFound)
	}
	switch {
	case q.Get("response_type") != "code":
		back(url.Values{"error": {"unsupported_response_type"}})
		return
	case state == "" || len(state) > 512:
		back(url.Values{"error": {"invalid_request"}, "error_description": {"state is required"}})
		return
	case q.Get("code_challenge_method") != "S256" || !validChallenge(q.Get("code_challenge")):
		back(url.Values{"error": {"invalid_request"}, "error_description": {"a PKCE S256 code_challenge is required"}})
		return
	}

	user := currentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login?next="+urlEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	if _, err := s.store.AppRole(user.ID, app.ID); errors.Is(err, store.ErrNotFound) {
		w.Header().Set("Cache-Control", "private, no-store")
		s.render(w, r, http.StatusForbidden, "no_access", map[string]any{
			"Title": "No access to " + app.Name, "App": app, "Return": r.URL.RequestURI(),
		})
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	code, err := s.store.CreateAuthCode(store.AuthCode{
		AppID: app.ID, UserID: user.ID, SessionID: currentSession(r).ID,
		RedirectURI: redirectURI, Challenge: q.Get("code_challenge"),
	})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	back(url.Values{"code": {code}})
}

// handleToken swaps a sign-in code for a grant. The app has already been
// checked by requireClient.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	app := currentApp(r)
	if r.PostFormValue("grant_type") != "authorization_code" {
		apiError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	bad := func(why string) {
		s.log.Warn("token refused", "app", app.ClientID, "why", why, "ip", s.clientIP(r))
		apiError(w, http.StatusBadRequest, "invalid_grant", why)
	}
	code, err := s.store.ConsumeAuthCode(r.PostFormValue("code"))
	if errors.Is(err, store.ErrNotFound) {
		bad("the code is unknown, already used or expired")
		return
	} else if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	switch {
	case code.AppID != app.ID:
		bad("the code was issued to another app")
		return
	case code.RedirectURI != r.PostFormValue("redirect_uri"):
		bad("redirect_uri doesn't match the one the code was issued for")
		return
	case !pkceMatches(r.PostFormValue("code_verifier"), code.Challenge):
		bad("code_verifier doesn't match the code_challenge")
		return
	}
	// Access could have been taken away in the seconds since /authorize.
	// (Signing out or turning the account off deletes the code itself.)
	role, err := s.store.AppRole(code.UserID, app.ID)
	if errors.Is(err, store.ErrNotFound) {
		bad("they no longer have access to this app")
		return
	} else if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	user, err := s.store.GetUser(code.UserID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	grant, err := s.store.CreateGrant(app.ID, user.ID, code.SessionID)
	if err != nil {
		s.apiServerError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{Actor: user.ID, Action: "app.signin", App: app.ID})
	writeJSON(w, http.StatusOK, map[string]any{"grant": grant, "user": apiUserOf(user, role)})
}

// validChallenge checks a PKCE S256 challenge looks like one: an unpadded
// base64url SHA-256, so 43 characters.
func validChallenge(c string) bool {
	b, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil && len(b) == sha256.Size
}

// pkceMatches checks a code_verifier (43 to 128 characters, RFC 7636)
// against the S256 challenge it was made into.
func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 || strings.Trim(verifier,
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") != "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// addQuery adds params to a URL that may already have a query string.
func addQuery(to string, params url.Values) string {
	u, err := url.Parse(to)
	if err != nil {
		return to
	}
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// appForNext names the app someone is signing in to, when the page after
// signing in is /authorize, so the sign-in page can say so.
func (s *Server) appForNext(next string) string {
	u, err := url.Parse(safeRedirect(next))
	if err != nil || u.Path != "/authorize" {
		return ""
	}
	app, err := s.store.GetAppByClientID(u.Query().Get("client_id"))
	if err != nil {
		return ""
	}
	return app.Name
}

// handleLogoutForm asks before signing out, so a link or an image on
// another site can't sign anyone out. Apps sign people out through the
// API instead.
func (s *Server) handleLogoutForm(w http.ResponseWriter, r *http.Request) {
	if currentUser(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "logout", map[string]any{"Title": "Sign out"})
}
