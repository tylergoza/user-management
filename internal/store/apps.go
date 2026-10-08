package store

import (
	"crypto/subtle"
	"errors"
	"slices"
	"strings"
)

// ErrBadClient is an unknown client ID or a wrong client secret.
var ErrBadClient = errors.New("unknown app or wrong secret")

// App is an app that signs people in through this service (an OAuth
// "client").
type App struct {
	ID           int64
	ClientID     string
	Name         string
	BaseURL      string
	RedirectURIs []string // matched exactly
	Roles        []string // the roles the app understands, e.g. user, admin
	CreatedAt    string
}

// RedirectAllowed reports whether uri is one of the app's registered
// redirect URIs, compared exactly.
func (a *App) RedirectAllowed(uri string) bool {
	return uri != "" && slices.Contains(a.RedirectURIs, uri)
}

func (a *App) HasRole(role string) bool { return role != "" && slices.Contains(a.Roles, role) }

const appCols = `id, client_id, name, base_url, redirect_uris, roles, created_at`

func scanApp(row scanner, a *App) error {
	var uris, roles string
	if err := row.Scan(&a.ID, &a.ClientID, &a.Name, &a.BaseURL, &uris, &roles, &a.CreatedAt); err != nil {
		return err
	}
	a.RedirectURIs = splitList(uris, "\n")
	a.Roles = splitList(roles, ",")
	return nil
}

func splitList(s, sep string) []string {
	var out []string
	for _, v := range strings.Split(s, sep) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *Store) ListApps() ([]App, error) {
	rows, err := s.DB.Query(`SELECT ` + appCols + ` FROM apps ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		var a App
		if err := scanApp(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetApp(id int64) (*App, error) {
	var a App
	if err := scanApp(s.DB.QueryRow(`SELECT `+appCols+` FROM apps WHERE id = ?`, id), &a); err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

func (s *Store) GetAppByClientID(clientID string) (*App, error) {
	var a App
	if err := scanApp(s.DB.QueryRow(`SELECT `+appCols+` FROM apps WHERE client_id = ?`, clientID), &a); err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

// newSecret makes a client secret. The prefix makes one easy to spot if
// it's ever pasted somewhere it shouldn't be.
func newSecret() string { return "um_" + RandomToken() }

// CreateApp registers an app and returns its client secret, which is only
// ever shown this once.
func (s *Store) CreateApp(a *App) (string, error) {
	secret := newSecret()
	res, err := s.DB.Exec(`INSERT INTO apps (client_id, name, base_url, redirect_uris, roles, secret_hash) VALUES (?, ?, ?, ?, ?, ?)`,
		a.ClientID, a.Name, a.BaseURL, strings.Join(a.RedirectURIs, "\n"), strings.Join(a.Roles, ","), HashToken(secret))
	if err != nil {
		return "", err
	}
	a.ID, _ = res.LastInsertId()
	return secret, nil
}

// UpdateApp saves name, base URL, redirect URIs and roles. The client ID
// can't change: each app has it in its configuration.
func (s *Store) UpdateApp(a *App) error {
	_, err := s.DB.Exec(`UPDATE apps SET name = ?, base_url = ?, redirect_uris = ?, roles = ? WHERE id = ?`,
		a.Name, a.BaseURL, strings.Join(a.RedirectURIs, "\n"), strings.Join(a.Roles, ","), a.ID)
	return err
}

// RotateAppSecret replaces an app's secret. The old one stops working at
// once.
func (s *Store) RotateAppSecret(id int64) (string, error) {
	secret := newSecret()
	res, err := s.DB.Exec(`UPDATE apps SET secret_hash = ? WHERE id = ?`, HashToken(secret), id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return secret, nil
}

// AuthenticateApp checks a client ID and secret.
func (s *Store) AuthenticateApp(clientID, secret string) (*App, error) {
	var id int64
	var hash string
	err := s.DB.QueryRow(`SELECT id, secret_hash FROM apps WHERE client_id = ?`, clientID).Scan(&id, &hash)
	if errors.Is(notFound(err), ErrNotFound) {
		return nil, ErrBadClient
	} else if err != nil {
		return nil, err
	}
	if hash == "" || secret == "" || subtle.ConstantTimeCompare([]byte(HashToken(secret)), []byte(hash)) != 1 {
		return nil, ErrBadClient
	}
	return s.GetApp(id)
}

// RoleInUse counts the people who have role in an app.
func (s *Store) RoleInUse(appID int64, role string) (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM user_apps WHERE app_id = ? AND role = ?`, appID, role).Scan(&n)
	return n, err
}

// UserApp is one app a person has access to, as shown on their launcher
// and account page.
type UserApp struct {
	AppID     int64
	ClientID  string
	Name      string
	BaseURL   string
	Role      string
	Suspended bool
}

// ListUserApps returns the apps a user has a row for, suspended ones
// included, by name.
func (s *Store) ListUserApps(userID int64) ([]UserApp, error) {
	rows, err := s.DB.Query(`SELECT a.id, a.client_id, a.name, a.base_url, ua.role, ua.suspended
		FROM user_apps ua JOIN apps a ON a.id = ua.app_id
		WHERE ua.user_id = ? ORDER BY a.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserApp
	for rows.Next() {
		var a UserApp
		if err := rows.Scan(&a.AppID, &a.ClientID, &a.Name, &a.BaseURL, &a.Role, &a.Suspended); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
