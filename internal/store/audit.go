package store

import (
	"strings"
)

// AuditEvent is something to record in the audit log. Zero IDs are stored
// as NULL.
type AuditEvent struct {
	Actor  int64 // who did it (0: nobody signed in, e.g. a failed sign-in)
	Action string
	Target int64 // the user it was done to, if any
	App    int64 // the app it was done in or through, if any
	Detail string
	IP     string
}

// AuditEntry is a logged event with names filled in for display.
type AuditEntry struct {
	ID         int64
	At         string
	ActorID    int64
	ActorName  string
	Action     string
	TargetID   int64
	TargetName string
	AppName    string
	Detail     string
	IP         string
}

// auditLabels describes each action for the audit log page.
var auditLabels = map[string]string{
	"login":                "Signed in",
	"login.failed":         "Sign-in failed",
	"login.disabled":       "Sign-in refused: account disabled",
	"logout":               "Signed out",
	"setup":                "Set up User Management",
	"password.change":      "Changed their password",
	"password.reset":       "Reset password",
	"user.create":          "Added user",
	"user.update":          "Edited user",
	"user.disable":         "Disabled user",
	"user.enable":          "Re-enabled user",
	"session.revoke":       "Signed out a device",
	"session.revoke_other": "Signed out all other devices",
	"settings.update":      "Changed settings",
	"backup.download":      "Downloaded a backup",
}

// AuditLabel is the readable name of an action.
func AuditLabel(action string) string {
	if l, ok := auditLabels[action]; ok {
		return l
	}
	return action
}

func (s *Store) Audit(e AuditEvent) error {
	_, err := s.DB.Exec(`INSERT INTO audit_log (actor_user_id, action, target_user_id, app_id, detail, ip) VALUES (?, ?, ?, ?, ?, ?)`,
		nullInt(e.Actor), e.Action, nullInt(e.Target), nullInt(e.App), truncate(e.Detail, 1000), e.IP)
	return err
}

type AuditFilter struct {
	UserID int64 // entries done by or to this user
	Before int64 // only entries older than this ID, for paging
	Limit  int
}

// ListAudit returns entries newest first.
func (s *Store) ListAudit(f AuditFilter) ([]AuditEntry, error) {
	var where []string
	var args []any
	if f.UserID != 0 {
		where = append(where, `(a.actor_user_id = ? OR a.target_user_id = ?)`)
		args = append(args, f.UserID, f.UserID)
	}
	if f.Before != 0 {
		where = append(where, `a.id < ?`)
		args = append(args, f.Before)
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	q := `SELECT a.id, a.at, COALESCE(a.actor_user_id, 0), COALESCE(NULLIF(ac.display_name, ''), ac.username, ''),
		a.action, COALESCE(a.target_user_id, 0), COALESCE(NULLIF(t.display_name, ''), t.username, ''),
		COALESCE(ap.name, ''), a.detail, a.ip
		FROM audit_log a
		LEFT JOIN users ac ON ac.id = a.actor_user_id
		LEFT JOIN users t ON t.id = a.target_user_id
		LEFT JOIN apps ap ON ap.id = a.app_id`
	if where != nil {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	q += ` ORDER BY a.id DESC LIMIT ?`
	rows, err := s.DB.Query(q, append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.ActorID, &e.ActorName, &e.Action, &e.TargetID, &e.TargetName,
			&e.AppName, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullInt(i int64) any {
	if i == 0 {
		return nil
	}
	return i
}
