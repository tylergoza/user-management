package server

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/tylergoza/user-management/internal/store"
)

const (
	minPasswordLen = 10
	// bcrypt only looks at the first 72 bytes; refuse longer rather than
	// quietly ignoring the rest.
	maxPasswordLen = 72
)

func randomToken() string       { return store.RandomToken() }
func urlEscape(s string) string { return url.QueryEscape(s) }

// Login ------------------------------------------------------------------

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.store.CountUsers(); n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if currentUser(r) != nil {
		http.Redirect(w, r, safeRedirect(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", map[string]any{"Title": "Sign in", "Next": r.URL.Query().Get("next")})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	username, password, next := formStr(r, "username"), r.PostFormValue("password"), r.PostFormValue("next")
	ip := s.clientIP(r)
	// Attempts are limited per address and per username, so guessing one
	// person's password from many addresses is slowed down too.
	userKey := "user:" + strings.ToLower(username)
	fail := func(status int, msg string) {
		s.render(w, r, status, "login", map[string]any{
			"Title": "Sign in", "Next": next, "Username": username, "Error": msg,
		})
	}
	if !s.limiter.allow(ip) || !s.limiter.allow(userKey) {
		fail(http.StatusTooManyRequests, "Too many sign-in attempts. Please wait a few minutes and try again.")
		return
	}
	user, err := s.store.Authenticate(username, password)
	switch {
	case errors.Is(err, store.ErrBadLogin):
		s.limiter.fail(ip)
		s.limiter.fail(userKey)
		var target int64
		if u, err := s.store.GetUserByUsername(username); err == nil {
			target = u.ID
		}
		s.audit(r, store.AuditEvent{Action: "login.failed", Target: target, Detail: "username: " + username})
		fail(http.StatusUnauthorized, "Incorrect username or password.")
		return
	case errors.Is(err, store.ErrDisabled):
		s.audit(r, store.AuditEvent{Action: "login.disabled", Target: user.ID})
		fail(http.StatusForbidden, "This account has been turned off. Ask a user admin if you need it back.")
		return
	case err != nil:
		s.serverError(w, r, err)
		return
	}
	s.limiter.reset(ip)
	s.limiter.reset(userKey)
	if err := s.startSession(w, r, user.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.store.RecordLogin(user.ID)
	s.audit(r, store.AuditEvent{Actor: user.ID, Action: "login"})
	dest := safeRedirect(next)
	if dest == "/" {
		s.setFlash(w, r, "success", "Welcome back, "+user.Name()+".")
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64) error {
	// Drop any existing session so a fresh token is issued on login.
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.store.DeleteSession(c.Value)
	}
	sess, err := s.store.CreateSession(userID, s.clientIP(r), r.UserAgent(), s.cfg.SessionTTL)
	if err != nil {
		return err
	}
	s.setSessionCookie(w, r, sess.Token)
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.store.DeleteSession(c.Value)
	}
	if currentUser(r) != nil {
		s.audit(r, store.AuditEvent{Action: "logout"})
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1})
	s.redirect(w, r, "/login", "You have been signed out.")
}

// First-run setup ----------------------------------------------------------

func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.store.CountUsers(); n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "setup", map[string]any{"Title": "Welcome", "SiteNameValue": s.SiteName()})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.store.CountUsers(); n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u := store.User{Username: formStr(r, "username"), DisplayName: formStr(r, "display_name"), Email: formStr(r, "email"), IsAdmin: true}
	siteName := formStr(r, "site_name")
	password := r.PostFormValue("password")
	errs := validateUser(&u)
	errs = append(errs, validatePassword(password, r.PostFormValue("password_confirm"))...)
	if len(errs) > 0 {
		s.render(w, r, http.StatusUnprocessableEntity, "setup", map[string]any{
			"Title": "Welcome", "Errors": errs, "Form": u, "SiteNameValue": siteName,
		})
		return
	}
	if siteName != "" {
		s.store.SetSetting("site_name", siteName)
		s.reloadSettings()
	}
	id, err := s.store.CreateUser(&u, password)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.startSession(w, r, id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{Actor: id, Action: "setup", Target: id})
	s.redirect(w, r, "/admin/users", "Your user admin account is ready. Next, add the people who use the church apps.")
}

// validateUser checks the fields a user admin fills in for a person.
func validateUser(u *store.User) []string {
	var errs []string
	if len(u.Username) < 2 || len(u.Username) > 64 || strings.IndexFunc(u.Username, unicode.IsSpace) >= 0 {
		errs = append(errs, "Username must be 2 to 64 characters with no spaces.")
	}
	if len(u.DisplayName) > 100 {
		errs = append(errs, "Name must be at most 100 characters.")
	}
	if u.Email != "" && (len(u.Email) > 254 || !strings.Contains(u.Email, "@") || strings.IndexFunc(u.Email, unicode.IsSpace) >= 0) {
		errs = append(errs, "Email doesn't look right. Leave it blank if they don't have one.")
	}
	return errs
}

func validatePassword(password, confirm string) []string {
	var errs []string
	if len(password) < minPasswordLen {
		errs = append(errs, "Password must be at least 10 characters.")
	}
	if len(password) > maxPasswordLen {
		errs = append(errs, "Password must be at most 72 characters.")
	}
	if password != confirm {
		errs = append(errs, "Passwords do not match.")
	}
	return errs
}

// Home -------------------------------------------------------------------

// handleHome is the app launcher: a tile for each app the person can use.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	apps, err := s.store.ListUserApps(currentUser(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "home", map[string]any{"Title": "", "Apps": apps})
}

// Account ----------------------------------------------------------------

func (s *Server) accountData(r *http.Request, data map[string]any) (map[string]any, error) {
	u := currentUser(r)
	apps, err := s.store.ListUserApps(u.ID)
	if err != nil {
		return nil, err
	}
	sessions, err := s.store.ListSessions(u.ID)
	if err != nil {
		return nil, err
	}
	data["Title"] = "My account"
	data["Apps"] = apps
	data["Sessions"] = sessions
	data["SessionID"] = currentSession(r).ID
	return data, nil
}

func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, status int, errs []string) {
	data, err := s.accountData(r, map[string]any{"Errors": errs})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, status, "account", data)
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	s.renderAccount(w, r, http.StatusOK, nil)
}

func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	// Someone at an unlocked computer shouldn't get unlimited guesses at
	// the current password either.
	key := "user:" + strings.ToLower(u.Username)
	if !s.limiter.allow(key) {
		s.renderAccount(w, r, http.StatusTooManyRequests, []string{"Too many wrong passwords. Please wait a few minutes and try again."})
		return
	}
	if _, err := s.store.Authenticate(u.Username, r.PostFormValue("current_password")); err != nil {
		if !errors.Is(err, store.ErrBadLogin) {
			s.serverError(w, r, err)
			return
		}
		s.limiter.fail(key)
		s.renderAccount(w, r, http.StatusUnprocessableEntity, []string{"Current password is incorrect."})
		return
	}
	if errs := validatePassword(r.PostFormValue("password"), r.PostFormValue("password_confirm")); len(errs) > 0 {
		s.renderAccount(w, r, http.StatusUnprocessableEntity, errs)
		return
	}
	if err := s.store.SetPassword(u.ID, r.PostFormValue("password")); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, store.AuditEvent{Action: "password.change", Target: u.ID})
	// SetPassword ends all sessions; start a fresh one for this device.
	if err := s.startSession(w, r, u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.redirect(w, r, "/account", "Password updated. Your other devices have been signed out.")
}

func (s *Server) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if id == currentSession(r).ID {
		s.setFlash(w, r, "error", "That's this device. Use Sign out instead.")
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	ok, err := s.store.DeleteUserSession(currentUser(r).ID, id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if ok {
		s.audit(r, store.AuditEvent{Action: "session.revoke", Target: currentUser(r).ID})
	}
	s.redirect(w, r, "/account", "That device has been signed out.")
}

func (s *Server) handleSessionDeleteOthers(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.DeleteOtherSessions(currentUser(r).ID, currentSession(r).ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if n > 0 {
		s.audit(r, store.AuditEvent{Action: "session.revoke_other", Target: currentUser(r).ID})
	}
	s.redirect(w, r, "/account", "Your other devices have been signed out.")
}

// Login rate limiting ------------------------------------------------------

type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *loginLimiter) prune(key string, now time.Time) []time.Time {
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.hits, key)
		return nil
	}
	l.hits[key] = kept
	return kept
}

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, time.Now())) < l.max
}

func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	// Usernames are made up by whoever is guessing, so clear out stale
	// keys now and then rather than letting the map grow.
	if len(l.hits) > 10000 {
		for k := range l.hits {
			l.prune(k, now)
		}
	}
	l.hits[key] = append(l.prune(key, now), now)
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}
