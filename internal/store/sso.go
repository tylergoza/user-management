package store

import (
	"database/sql"
	"errors"
	"time"
)

// codeTTL is how long a sign-in code works. The browser carries it
// straight to the app, which exchanges it at once.
const codeTTL = 60 * time.Second

// AuthCode is a one-time sign-in code, bound to the app, the redirect URI
// and the PKCE challenge it was issued for.
type AuthCode struct {
	AppID       int64
	UserID      int64
	SessionID   int64
	RedirectURI string
	Challenge   string // PKCE S256 code challenge
}

// CreateAuthCode stores a new sign-in code and returns it.
func (s *Store) CreateAuthCode(c AuthCode) (string, error) {
	code := RandomToken()
	_, err := s.DB.Exec(`INSERT INTO auth_codes (code_hash, app_id, user_id, session_id, redirect_uri, pkce_challenge, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		HashToken(code), c.AppID, c.UserID, c.SessionID, c.RedirectURI, c.Challenge, sqlTime(time.Now().Add(codeTTL)))
	if err != nil {
		return "", err
	}
	return code, nil
}

// ConsumeAuthCode looks up a sign-in code and deletes it in the same
// step, so it works only once, even if two requests race. An expired code
// isn't found.
func (s *Store) ConsumeAuthCode(code string) (*AuthCode, error) {
	var c AuthCode
	var expires string
	err := s.DB.QueryRow(`DELETE FROM auth_codes WHERE code_hash = ?
		RETURNING app_id, user_id, session_id, redirect_uri, pkce_challenge, expires_at`, HashToken(code)).
		Scan(&c.AppID, &c.UserID, &c.SessionID, &c.RedirectURI, &c.Challenge, &expires)
	if err != nil {
		return nil, notFound(err)
	}
	if expires <= sqlTime(time.Now()) {
		return nil, ErrNotFound
	}
	return &c, nil
}

// AppRole is the role a user has in an app, if they may use it: the
// account is on and their access isn't suspended. Otherwise ErrNotFound.
func (s *Store) AppRole(userID, appID int64) (string, error) {
	var role string
	err := s.DB.QueryRow(`SELECT ua.role FROM user_apps ua JOIN users u ON u.id = ua.user_id
		WHERE ua.user_id = ? AND ua.app_id = ? AND ua.suspended = 0 AND u.disabled = 0`, userID, appID).Scan(&role)
	return role, notFound(err)
}

// CreateGrant records an app's sign-in, tied to the session here that
// made it, and returns the grant ID the app keeps.
func (s *Store) CreateGrant(appID, userID, sessionID int64) (string, error) {
	id := RandomToken()
	_, err := s.DB.Exec(`INSERT INTO grants (id_hash, app_id, user_id, session_id) VALUES (?, ?, ?, ?)`,
		HashToken(id), appID, userID, sessionID)
	if err != nil {
		return "", err
	}
	return id, nil
}

// Grant is a live app sign-in: who it is and their role in that app now.
type Grant struct {
	User      User
	Role      string
	SessionID int64
}

// CheckGrant finds an app's grant if it's still good: its session here
// hasn't ended or expired, the account is on, and the person still has
// unsuspended access to that app. Otherwise ErrNotFound.
//
// An app checking counts as using the session, so its expiry slides
// forward to ttl from now, as browsing here would. Someone who only uses
// the apps stays signed in.
func (s *Store) CheckGrant(grantID string, appID int64, ttl time.Duration) (*Grant, error) {
	var g Grant
	var expires, lastSeen string
	err := scanUser(s.DB.QueryRow(`
		SELECT `+userColsOf("u.")+`, ua.role, s.id, s.expires_at, s.last_seen_at
		FROM grants g
		JOIN sessions s ON s.id = g.session_id
		JOIN users u ON u.id = g.user_id
		JOIN user_apps ua ON ua.user_id = g.user_id AND ua.app_id = g.app_id
		WHERE g.id_hash = ? AND g.app_id = ? AND u.disabled = 0 AND ua.suspended = 0`, HashToken(grantID), appID),
		&g.User, &g.Role, &g.SessionID, &expires, &lastSeen)
	if err != nil {
		return nil, notFound(err)
	}
	now := time.Now()
	if expires <= sqlTime(now) {
		return nil, ErrNotFound
	}
	if lastSeen <= sqlTime(now.Add(-slideEvery)) {
		if _, err := s.DB.Exec(`UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE id = ?`,
			sqlTime(now.Add(ttl)), sqlTime(now), g.SessionID); err != nil {
			return nil, err
		}
	}
	if _, err := s.DB.Exec(`UPDATE grants SET last_checked_at = ? WHERE id_hash = ?`, sqlTime(now), HashToken(grantID)); err != nil {
		return nil, err
	}
	return &g, nil
}

// EndGrantSession signs out the session an app's grant came from, which
// ends every grant from that session, in every app. It returns the user it
// signed out, or 0 if the grant wasn't found.
func (s *Store) EndGrantSession(grantID string, appID int64) (int64, error) {
	var sessionID, userID int64
	err := s.DB.QueryRow(`SELECT session_id, user_id FROM grants WHERE id_hash = ? AND app_id = ?`,
		HashToken(grantID), appID).Scan(&sessionID, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	if _, err := s.DB.Exec(`DELETE FROM sessions WHERE id = ?`, sessionID); err != nil {
		return 0, err
	}
	return userID, nil
}
