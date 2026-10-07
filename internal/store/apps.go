package store

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
