package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrBadLogin is a wrong username or password.
	ErrBadLogin = errors.New("incorrect username or password")
	// ErrDisabled is a correct password for an account a user admin has
	// turned off.
	ErrDisabled = errors.New("account disabled")
)

type User struct {
	ID                int64
	Username          string
	DisplayName       string
	Email             string
	Disabled          bool
	IsAdmin           bool
	PasswordChangedAt string
	LastLoginAt       string
	CreatedAt         string
}

// Name returns the display name, falling back to the username.
func (u *User) Name() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}

func RandomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken is how tokens are stored: they're long and random, so a plain
// SHA-256 is enough (no bcrypt needed).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// userColsOf lists the columns scanUser reads, with a table alias prefix
// such as "u." (or "" for none).
func userColsOf(p string) string {
	return p + "id, " + p + "username, " + p + "display_name, " + p + "email, " + p + "disabled, " + p + "is_admin, " +
		p + "password_changed_at, COALESCE(" + p + "last_login_at, ''), " + p + "created_at"
}

var userCols = userColsOf("")

type scanner interface{ Scan(...any) error }

func scanUser(row scanner, u *User, extra ...any) error {
	return row.Scan(append([]any{&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Disabled, &u.IsAdmin,
		&u.PasswordChangedAt, &u.LastLoginAt, &u.CreatedAt}, extra...)...)
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// ListUsers returns everyone, active accounts first.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.DB.Query(`SELECT ` + userCols + ` FROM users ORDER BY disabled, username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := scanUser(rows, &u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) GetUser(id int64) (*User, error) {
	var u User
	if err := scanUser(s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id), &u); err != nil {
		return nil, notFound(err)
	}
	return &u, nil
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	var u User
	if err := scanUser(s.DB.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, strings.TrimSpace(username)), &u); err != nil {
		return nil, notFound(err)
	}
	return &u, nil
}

// CreateUser adds a person with a password. Username, DisplayName, Email
// and IsAdmin are taken from u.
func (s *Store) CreateUser(u *User, password string) (int64, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	res, err := s.DB.Exec(`INSERT INTO users (username, display_name, email, password_hash, is_admin) VALUES (?, ?, ?, ?, ?)`,
		strings.TrimSpace(u.Username), strings.TrimSpace(u.DisplayName), strings.TrimSpace(u.Email), string(hash), u.IsAdmin)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ImportUser adds a person with a bcrypt hash taken from another app, as
// is, so their current password keeps working. Username, DisplayName,
// Email and IsAdmin are taken from u.
func (s *Store) ImportUser(u *User, passwordHash string) (int64, error) {
	if _, err := bcrypt.Cost([]byte(passwordHash)); err != nil {
		return 0, errors.New("not a bcrypt hash")
	}
	res, err := s.DB.Exec(`INSERT INTO users (username, display_name, email, password_hash, is_admin) VALUES (?, ?, ?, ?, ?)`,
		strings.TrimSpace(u.Username), strings.TrimSpace(u.DisplayName), strings.TrimSpace(u.Email), passwordHash, u.IsAdmin)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateUser saves username, display name, email and admin.
func (s *Store) UpdateUser(u *User) error {
	_, err := s.DB.Exec(`UPDATE users SET username = ?, display_name = ?, email = ?, is_admin = ? WHERE id = ?`,
		strings.TrimSpace(u.Username), strings.TrimSpace(u.DisplayName), strings.TrimSpace(u.Email), u.IsAdmin, u.ID)
	return err
}

// SetPassword changes a password and signs the user out everywhere, which
// also ends every app sign-in that came from those sessions.
func (s *Store) SetPassword(id int64, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE users SET password_hash = ?, password_changed_at = datetime('now') WHERE id = ?`, string(hash), id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetDisabled turns an account off or back on. Turning it off signs the
// user out everywhere.
func (s *Store) SetDisabled(id int64, disabled bool) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE users SET disabled = ? WHERE id = ?`, disabled, id); err != nil {
		return err
	}
	if disabled {
		if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CountActiveAdmins counts user admins who can still sign in.
func (s *Store) CountActiveAdmins() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE is_admin = 1 AND disabled = 0`).Scan(&n)
	return n, err
}

// Authenticate checks a username/password pair. It always runs a bcrypt
// comparison so response timing does not reveal whether a username exists.
// A disabled account only gets ErrDisabled when the password is right, so
// that doesn't reveal anything either.
func (s *Store) Authenticate(username, password string) (*User, error) {
	var u User
	var hash string
	err := scanUser(s.DB.QueryRow(`SELECT `+userCols+`, password_hash FROM users WHERE username = ?`,
		strings.TrimSpace(username)), &u, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		hash = string(dummyHash())
	} else if err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || u.ID == 0 {
		return nil, ErrBadLogin
	}
	if u.Disabled {
		return &u, ErrDisabled
	}
	return &u, nil
}

var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
	return h
})

func (s *Store) RecordLogin(id int64) error {
	_, err := s.DB.Exec(`UPDATE users SET last_login_at = ? WHERE id = ?`, sqlTime(time.Now()), id)
	return err
}
