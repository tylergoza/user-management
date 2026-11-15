package store

import (
	"strings"
	"time"
)

// Per-app tokens ("delegation", MEMBERS_PLAN.md): an app holding a
// person's grant gets a short umd_ token to act for them in one other app
// (the audience). The audience checks it here. Both apps must opt in: the
// grant's app lists the audience in ActsIn, and the audience lists the
// grant's app in AcceptsFrom.

// DelegatedTTL is how long a umd_ token works. There's no refresh: the
// app asks again, which re-checks the grant and access.
const DelegatedTTL = 15 * time.Minute

// DelegatedPrefix starts every per-app token, so one is easy to spot.
const DelegatedPrefix = "umd_"

// CreateDelegatedToken makes a umd_ token for userID in the audience app,
// bound to the grant (by its ID as the app holds it). Only the hash is
// stored. The caller has already checked the grant, the opt-ins and the
// person's role.
func (s *Store) CreateDelegatedToken(grantID string, audienceAppID, userID int64) (string, error) {
	token := DelegatedPrefix + RandomToken()
	col := "grant_hash"
	if strings.HasPrefix(grantID, AIGrantPrefix) {
		col = "ai_grant_hash"
	}
	_, err := s.DB.Exec(`INSERT INTO delegated_tokens (token_hash, `+col+`, audience_app_id, user_id, expires_at) VALUES (?, ?, ?, ?, ?)`,
		HashToken(token), HashToken(grantID), audienceAppID, userID, sqlTime(time.Now().Add(DelegatedTTL)))
	if err != nil {
		return "", err
	}
	return token, nil
}

// Delegated is who a good per-app token is for.
type Delegated struct {
	User User
	Role string // their role in the audience app
	Via  string // client ID of the app acting for them (the grant's app)
}

// CheckDelegatedToken finds a per-app token presented by the audience app
// and requires, all at once: it hasn't expired; it was made for this app;
// its grant still exists, from a session here that hasn't ended or
// expired; the account is on; the person still has unsuspended access to
// both the acting app and this one; and both apps still opt in. Anything
// else is ErrNotFound. It doesn't count as using the grant.
func (s *Store) CheckDelegatedToken(token string, audienceAppID int64) (*Delegated, error) {
	if !strings.HasPrefix(token, DelegatedPrefix) {
		return nil, ErrNotFound
	}
	var d Delegated
	var viaID int64
	now := sqlTime(time.Now())
	// Either kind of grant: a session grant needs its session to be live;
	// an AI grant has none. Both need the account on and the person
	// unsuspended in the grant's app and the audience.
	err := scanUser(s.DB.QueryRow(`
		SELECT `+userColsOf("u.")+`, ua.role, COALESCE(g.app_id, ag.app_id)
		FROM delegated_tokens d
		LEFT JOIN grants g ON g.id_hash = d.grant_hash AND g.user_id = d.user_id
		LEFT JOIN sessions s ON s.id = g.session_id
		LEFT JOIN ai_grants ag ON ag.id_hash = d.ai_grant_hash AND ag.user_id = d.user_id
		JOIN users u ON u.id = d.user_id
		JOIN user_apps ua ON ua.user_id = d.user_id AND ua.app_id = d.audience_app_id
		JOIN user_apps ga ON ga.user_id = d.user_id AND ga.app_id = COALESCE(g.app_id, ag.app_id)
		WHERE d.token_hash = ? AND d.audience_app_id = ? AND d.expires_at > ?
			AND ((g.id_hash IS NOT NULL AND s.expires_at > ?) OR ag.id_hash IS NOT NULL)
			AND u.disabled = 0 AND ua.suspended = 0 AND ga.suspended = 0`,
		HashToken(token), audienceAppID, now, now), &d.User, &d.Role, &viaID)
	if err != nil {
		return nil, notFound(err)
	}
	via, err := s.GetApp(viaID)
	if err != nil {
		return nil, err
	}
	audience, err := s.GetApp(audienceAppID)
	if err != nil {
		return nil, err
	}
	if !via.MayActIn(audience) {
		return nil, ErrNotFound
	}
	d.Via = via.ClientID
	return &d, nil
}

// DelegableApp is an app someone can be acted for in, with their role.
type DelegableApp struct {
	App  App
	Role string
}

// DelegableApps lists the apps, by name, where userID has unsuspended
// access and the app with ID actingAppID may act for them (both opt in).
// The acting app itself is left out.
func (s *Store) DelegableApps(actingAppID, userID int64) ([]DelegableApp, error) {
	acting, err := s.GetApp(actingAppID)
	if err != nil {
		return nil, err
	}
	apps, err := s.ListApps()
	if err != nil {
		return nil, err
	}
	mine, err := s.ListUserApps(userID)
	if err != nil {
		return nil, err
	}
	roles := map[int64]string{}
	for _, ua := range mine {
		if !ua.Suspended {
			roles[ua.AppID] = ua.Role
		}
	}
	var out []DelegableApp
	for _, a := range apps {
		if role, ok := roles[a.ID]; ok && acting.MayActIn(&a) {
			out = append(out, DelegableApp{App: a, Role: role})
		}
	}
	return out, nil
}

// DefaultRoles lists "App name: role" for every app with a default role,
// by app name: what a new user will get.
func (s *Store) DefaultRoles() ([]string, error) {
	apps, err := s.ListApps()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range apps {
		if a.DefaultRole != "" {
			out = append(out, a.Name+": "+a.DefaultRole)
		}
	}
	return out, nil
}

// ApplyDefaultRoles gives a new user each app's default role, in one
// transaction, and returns what was given ("App name: role"). Rows they
// already have are left alone. Only a user admin creating someone calls
// this, not /setup or import-users.
func (s *Store) ApplyDefaultRoles(userID, by int64) ([]string, error) {
	apps, err := s.ListApps()
	if err != nil {
		return nil, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var given []string
	now := sqlTime(time.Now())
	for _, a := range apps {
		if a.DefaultRole == "" || !a.HasRole(a.DefaultRole) {
			continue
		}
		res, err := tx.Exec(`INSERT INTO user_apps (user_id, app_id, role, granted_by, updated_by, updated_at)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (user_id, app_id) DO NOTHING`,
			userID, a.ID, a.DefaultRole, nullInt(by), nullInt(by), now)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			given = append(given, a.Name+": "+a.DefaultRole)
		}
	}
	return given, tx.Commit()
}
