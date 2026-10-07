package store

import (
	"time"
)

// Session is a signed-in browser. Token is only set on a new session; the
// database keeps just its hash.
type Session struct {
	ID         int64
	Token      string
	IP         string
	UserAgent  string
	ExpiresAt  string
	LastSeenAt string
	CreatedAt  string
	User       User
	// Extended is set by GetSession when it slid the expiry forward, so
	// the caller can refresh the cookie too.
	Extended bool
}

// slideEvery limits how often a busy session's expiry is pushed forward,
// so every request isn't a database write.
const slideEvery = time.Hour

func (s *Store) CreateSession(userID int64, ip, userAgent string, ttl time.Duration) (*Session, error) {
	sess := &Session{Token: RandomToken(), IP: ip, UserAgent: truncate(userAgent, 300)}
	now := time.Now()
	res, err := s.DB.Exec(`INSERT INTO sessions (token_hash, user_id, ip, user_agent, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)`,
		HashToken(sess.Token), userID, sess.IP, sess.UserAgent, sqlTime(now.Add(ttl)), sqlTime(now))
	if err != nil {
		return nil, err
	}
	sess.ID, _ = res.LastInsertId()
	return sess, nil
}

// GetSession finds the session for a cookie token. Sessions of disabled
// users and expired ones aren't found. An active session's expiry slides
// forward to ttl from now (at most once per slideEvery).
func (s *Store) GetSession(token string, ttl time.Duration) (*Session, error) {
	var sess Session
	err := scanUser(s.DB.QueryRow(`
		SELECT `+userColsOf("u.")+`, s.id, s.ip, s.user_agent, s.expires_at, s.last_seen_at, s.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND u.disabled = 0`, HashToken(token)),
		&sess.User, &sess.ID, &sess.IP, &sess.UserAgent, &sess.ExpiresAt, &sess.LastSeenAt, &sess.CreatedAt)
	if err != nil {
		return nil, notFound(err)
	}
	now := time.Now()
	if sess.ExpiresAt <= sqlTime(now) {
		s.DB.Exec(`DELETE FROM sessions WHERE id = ?`, sess.ID)
		return nil, ErrNotFound
	}
	if sess.LastSeenAt <= sqlTime(now.Add(-slideEvery)) {
		sess.ExpiresAt, sess.LastSeenAt = sqlTime(now.Add(ttl)), sqlTime(now)
		if _, err := s.DB.Exec(`UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE id = ?`,
			sess.ExpiresAt, sess.LastSeenAt, sess.ID); err != nil {
			return nil, err
		}
		sess.Extended = true
	}
	return &sess, nil
}

// ListSessions is where a user is signed in, most recently used first.
func (s *Store) ListSessions(userID int64) ([]Session, error) {
	rows, err := s.DB.Query(`SELECT id, ip, user_agent, expires_at, last_seen_at, created_at FROM sessions
		WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC, id DESC`, userID, sqlTime(time.Now()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.IP, &sess.UserAgent, &sess.ExpiresAt, &sess.LastSeenAt, &sess.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE token_hash = ?`, HashToken(token))
	return err
}

// DeleteUserSession signs one of a user's sessions out. It reports
// whether there was such a session.
func (s *Store) DeleteUserSession(userID, sessionID int64) (bool, error) {
	res, err := s.DB.Exec(`DELETE FROM sessions WHERE id = ? AND user_id = ?`, sessionID, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteOtherSessions signs a user out everywhere except keepID.
func (s *Store) DeleteOtherSessions(userID, keepID int64) (int64, error) {
	res, err := s.DB.Exec(`DELETE FROM sessions WHERE user_id = ? AND id != ?`, userID, keepID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PurgeExpired clears out expired sessions and sign-in codes.
func (s *Store) PurgeExpired() error {
	now := sqlTime(time.Now())
	if _, err := s.DB.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, now); err != nil {
		return err
	}
	_, err := s.DB.Exec(`DELETE FROM auth_codes WHERE expires_at <= ?`, now)
	return err
}
