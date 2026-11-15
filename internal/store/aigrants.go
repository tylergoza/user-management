package store

import (
	"errors"
	"time"
)

// AI grants: a person's sign-in held by an app that acts for them over
// long periods without a browser (the MCP server, for AI connections).
// Unlike a normal grant it isn't tied to a browser session here, so
// signing out of this site doesn't end it. It ends when the password is
// changed or reset, the account is disabled, the person loses (or has
// suspended) their role in the app, the app stops being allowed to act
// for users, or someone revokes it. Only the hash is stored.

// AIGrantPrefix starts every AI grant ID, so it can be told from a
// browser-session grant.
const AIGrantPrefix = "umai_"

// ErrNotActing: the app has no "May act for users in" list, so it may
// not hold AI grants.
var ErrNotActing = errors.New("app may not act for users")

// CreateAIGrant makes an AI grant for userID in app and returns its ID.
// The caller has already checked the person's current grant.
func (s *Store) CreateAIGrant(app *App, userID int64) (string, error) {
	if len(app.ActsIn) == 0 {
		return "", ErrNotActing
	}
	id := AIGrantPrefix + RandomToken()
	_, err := s.DB.Exec(`INSERT INTO ai_grants (id_hash, app_id, user_id) VALUES (?, ?, ?)`,
		HashToken(id), app.ID, userID)
	if err != nil {
		return "", err
	}
	return id, nil
}

// checkAIGrant is CheckGrant for an AI grant: the grant belongs to this
// app, the app may still act for users, the account is on and the person
// still has unsuspended access to the app. Otherwise ErrNotFound.
func (s *Store) checkAIGrant(grantID string, appID int64) (*Grant, error) {
	var g Grant
	var actsIn string
	err := scanUser(s.DB.QueryRow(`
		SELECT `+userColsOf("u.")+`, ua.role, a.acts_in
		FROM ai_grants g
		JOIN apps a ON a.id = g.app_id
		JOIN users u ON u.id = g.user_id
		JOIN user_apps ua ON ua.user_id = g.user_id AND ua.app_id = g.app_id
		WHERE g.id_hash = ? AND g.app_id = ? AND u.disabled = 0 AND ua.suspended = 0`, HashToken(grantID), appID),
		&g.User, &g.Role, &actsIn)
	if err != nil {
		return nil, notFound(err)
	}
	if actsIn == "" {
		return nil, ErrNotFound
	}
	if _, err := s.DB.Exec(`UPDATE ai_grants SET last_checked_at = ? WHERE id_hash = ?`,
		sqlTime(time.Now()), HashToken(grantID)); err != nil {
		return nil, err
	}
	return &g, nil
}

// RevokeAIGrant deletes an app's AI grant (and with it its umd_ tokens).
// It returns the user it belonged to, or 0 if there was no such grant:
// revoking twice is fine.
func (s *Store) RevokeAIGrant(grantID string, appID int64) (int64, error) {
	var userID int64
	err := s.DB.QueryRow(`DELETE FROM ai_grants WHERE id_hash = ? AND app_id = ? RETURNING user_id`,
		HashToken(grantID), appID).Scan(&userID)
	if errors.Is(notFound(err), ErrNotFound) {
		return 0, nil
	}
	return userID, err
}

// AIGrantInfo is one AI grant as shown to the person: no ID, which is
// secret.
type AIGrantInfo struct {
	ID            string // hash prefix, safe to show and to use to revoke
	AppName       string
	CreatedAt     string
	LastCheckedAt string
}

// ListAIGrants lists a person's AI grants, newest first.
func (s *Store) ListAIGrants(userID int64) ([]AIGrantInfo, error) {
	rows, err := s.DB.Query(`SELECT g.id_hash, a.name, g.created_at, g.last_checked_at
		FROM ai_grants g JOIN apps a ON a.id = g.app_id WHERE g.user_id = ? ORDER BY g.created_at DESC, g.id_hash`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AIGrantInfo
	for rows.Next() {
		var i AIGrantInfo
		if err := rows.Scan(&i.ID, &i.AppName, &i.CreatedAt, &i.LastCheckedAt); err != nil {
			return nil, err
		}
		i.ID = i.ID[:16]
		out = append(out, i)
	}
	return out, rows.Err()
}

// RevokeUserAIGrant revokes one of a person's AI grants by the ID
// ListAIGrants showed. It reports whether there was one.
func (s *Store) RevokeUserAIGrant(userID int64, shownID string) (bool, error) {
	if len(shownID) != 16 {
		return false, nil
	}
	res, err := s.DB.Exec(`DELETE FROM ai_grants WHERE user_id = ? AND substr(id_hash, 1, 16) = ?`, userID, shownID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
