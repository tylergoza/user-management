package store

import (
	"database/sql"
	"errors"
	"time"
)

// Why an app admin's change was refused.
var (
	ErrNoAccess  = errors.New("they don't have access to this app yet; a user admin has to add them")
	ErrLocked    = errors.New("a user admin has locked their access; ask a user admin to change it")
	ErrLastAdmin = errors.New("this app needs at least one active admin")
	ErrBadRole   = errors.New("this app has no such role")
)

// Access is one person's row for one app. Has is false when there's no
// row, meaning no access.
type Access struct {
	UserID        int64
	AppID         int64
	Has           bool
	Role          string
	Suspended     bool
	Locked        bool
	UpdatedByName string
	UpdatedAt     string
}

// Active reports whether the access lets them sign in to the app (not
// counting whether the account itself is on).
func (a Access) Active() bool { return a.Has && !a.Suspended }

const accessCols = `ua.user_id, ua.app_id, ua.role, ua.suspended, ua.locked,
	COALESCE(NULLIF(ub.display_name, ''), ub.username, ''), ua.updated_at`

const accessJoin = ` LEFT JOIN users ub ON ub.id = ua.updated_by`

func scanAccess(row scanner, a *Access, extra ...any) error {
	a.Has = true
	return row.Scan(append([]any{&a.UserID, &a.AppID, &a.Role, &a.Suspended, &a.Locked, &a.UpdatedByName, &a.UpdatedAt}, extra...)...)
}

func getAccess(q interface {
	QueryRow(string, ...any) *sql.Row
}, userID, appID int64) (*Access, error) {
	var a Access
	err := scanAccess(q.QueryRow(`SELECT `+accessCols+` FROM user_apps ua`+accessJoin+
		` WHERE ua.user_id = ? AND ua.app_id = ?`, userID, appID), &a)
	if err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

func (s *Store) GetAccess(userID, appID int64) (*Access, error) {
	return getAccess(s.DB, userID, appID)
}

// SetAccess is a user admin's change: grant, change or (with role "")
// remove someone's access to an app. User admins can change anything,
// locked rows included.
func (s *Store) SetAccess(userID, appID int64, role string, suspended, locked bool, by int64) error {
	if role == "" {
		_, err := s.DB.Exec(`DELETE FROM user_apps WHERE user_id = ? AND app_id = ?`, userID, appID)
		return err
	}
	_, err := s.DB.Exec(`INSERT INTO user_apps (user_id, app_id, role, suspended, locked, granted_by, updated_by, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id, app_id) DO UPDATE SET role = excluded.role, suspended = excluded.suspended,
			locked = excluded.locked, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		userID, appID, role, suspended, locked, nullInt(by), nullInt(by), sqlTime(time.Now()))
	return err
}

// AccessGrid is everyone's access to every app, by user ID then app ID,
// for the users page.
func (s *Store) AccessGrid() (map[int64]map[int64]Access, error) {
	rows, err := s.DB.Query(`SELECT ` + accessCols + ` FROM user_apps ua` + accessJoin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grid := map[int64]map[int64]Access{}
	for rows.Next() {
		var a Access
		if err := scanAccess(rows, &a); err != nil {
			return nil, err
		}
		if grid[a.UserID] == nil {
			grid[a.UserID] = map[int64]Access{}
		}
		grid[a.UserID][a.AppID] = a
	}
	return grid, rows.Err()
}

// AppUser is someone with access to an app, as the app's API lists them.
type AppUser struct {
	User   User
	Access Access
}

// ListAppUsers is everyone with a row for an app, suspended and turned-off
// accounts included, by username.
func (s *Store) ListAppUsers(appID int64) ([]AppUser, error) {
	rows, err := s.DB.Query(`SELECT `+userColsOf("u.")+`, `+accessCols+`
		FROM user_apps ua JOIN users u ON u.id = ua.user_id`+accessJoin+`
		WHERE ua.app_id = ? ORDER BY u.username`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppUser
	for rows.Next() {
		var au AppUser
		au.Access.Has = true
		if err := scanUser(rows, &au.User, &au.Access.UserID, &au.Access.AppID, &au.Access.Role, &au.Access.Suspended,
			&au.Access.Locked, &au.Access.UpdatedByName, &au.Access.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, au)
	}
	return out, rows.Err()
}

// GetAppUser is one person with access to an app.
func (s *Store) GetAppUser(appID, userID int64) (*AppUser, error) {
	u, err := s.GetUser(userID)
	if err != nil {
		return nil, err
	}
	a, err := s.GetAccess(userID, appID)
	if err != nil {
		return nil, err
	}
	return &AppUser{User: *u, Access: *a}, nil
}

// AppAdminChange is an app admin changing someone's role and/or
// suspension in their own app (nil leaves that part alone). The rules are
// checked here, in the same transaction as the change:
//   - they must already have access (ErrNoAccess); only user admins grant it
//   - the row mustn't be locked by a user admin (ErrLocked)
//   - the role must be one the app has (ErrBadRole)
//   - the app must keep at least one active admin (ErrLastAdmin)
//
// It returns the row as it was before the change.
func (s *Store) AppAdminChange(appID, actorID, targetID int64, role *string, suspended *bool) (*Access, error) {
	app, err := s.GetApp(appID)
	if err != nil {
		return nil, err
	}
	if role != nil && !app.HasRole(*role) {
		return nil, ErrBadRole
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	old, err := getAccess(tx, targetID, appID)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoAccess
	} else if err != nil {
		return nil, err
	}
	if old.Locked {
		return nil, ErrLocked
	}
	next := *old
	if role != nil {
		next.Role = *role
	}
	if suspended != nil {
		next.Suspended = *suspended
	}
	if next == *old {
		return old, nil
	}
	// Taking away an active admin needs another one left.
	if old.Role == "admin" && old.Active() && (next.Role != "admin" || !next.Active()) {
		var others int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM user_apps ua JOIN users u ON u.id = ua.user_id
			WHERE ua.app_id = ? AND ua.role = 'admin' AND ua.suspended = 0 AND u.disabled = 0 AND ua.user_id != ?`,
			appID, targetID).Scan(&others); err != nil {
			return nil, err
		}
		if others == 0 {
			return nil, ErrLastAdmin
		}
	}
	if _, err := tx.Exec(`UPDATE user_apps SET role = ?, suspended = ?, updated_by = ?, updated_at = ? WHERE user_id = ? AND app_id = ?`,
		next.Role, next.Suspended, actorID, sqlTime(time.Now()), targetID, appID); err != nil {
		return nil, err
	}
	return old, tx.Commit()
}
