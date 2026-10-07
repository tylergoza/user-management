package server

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tylergoza/user-management/internal/store"
)

// Users ------------------------------------------------------------------

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "admin/users/index", map[string]any{"Title": "Users", "Users": users})
}

func (s *Server) handleUserNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "admin/users/form", map[string]any{"Title": "Add user", "Form": store.User{}})
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	u := store.User{Username: formStr(r, "username"), DisplayName: formStr(r, "display_name"), Email: formStr(r, "email"),
		IsAdmin: r.PostFormValue("is_admin") == "1"}
	password := r.PostFormValue("password")
	errs := validateUser(&u)
	errs = append(errs, validatePassword(password, r.PostFormValue("password_confirm"))...)
	if len(errs) == 0 {
		id, err := s.store.CreateUser(&u, password)
		if isUnique(err) {
			errs = append(errs, "That username is already taken.")
		} else if err != nil {
			s.serverError(w, r, err)
			return
		}
		u.ID = id
	}
	if len(errs) > 0 {
		s.render(w, r, http.StatusUnprocessableEntity, "admin/users/form", map[string]any{"Title": "Add user", "Form": u, "Errors": errs})
		return
	}
	detail := ""
	if u.IsAdmin {
		detail = "as a user admin"
	}
	s.audit(r, store.AuditEvent{Action: "user.create", Target: u.ID, Detail: detail})
	s.redirect(w, r, "/admin/users", "User "+u.Username+" added.")
}

// userPage renders a person's edit form with their recent activity.
func (s *Server) userPage(w http.ResponseWriter, r *http.Request, status int, u *store.User, data map[string]any) {
	activity, err := s.store.ListAudit(store.AuditFilter{UserID: u.ID, Limit: 15})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	apps, err := s.store.ListUserApps(u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	saved, err := s.store.GetUser(u.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	data["Title"] = "Edit " + saved.Username
	data["Form"] = *u
	data["Saved"] = saved
	data["Activity"] = activity
	data["Apps"] = apps
	s.render(w, r, status, "admin/users/form", data)
}

func (s *Server) handleUserEdit(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUser(pathID(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.userPage(w, r, http.StatusOK, u, map[string]any{})
}

func (s *Server) handleUserUpdate(w http.ResponseWriter, r *http.Request) {
	old, err := s.store.GetUser(pathID(r))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	u := *old
	u.Username, u.DisplayName, u.Email = formStr(r, "username"), formStr(r, "display_name"), formStr(r, "email")
	u.IsAdmin = r.PostFormValue("is_admin") == "1"
	errs := validateUser(&u)
	if old.IsAdmin && !u.IsAdmin && !old.Disabled {
		if n, _ := s.store.CountActiveAdmins(); n <= 1 {
			errs = append(errs, "At least one active user admin is required.")
		}
	}
	password := r.PostFormValue("password")
	if password != "" {
		errs = append(errs, validatePassword(password, r.PostFormValue("password_confirm"))...)
	}
	if len(errs) == 0 {
		if err := s.store.UpdateUser(&u); isUnique(err) {
			errs = append(errs, "That username is already taken.")
		} else if err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	if len(errs) > 0 {
		s.userPage(w, r, http.StatusUnprocessableEntity, &u, map[string]any{"Errors": errs})
		return
	}
	if changes := userChanges(old, &u); changes != "" {
		s.audit(r, store.AuditEvent{Action: "user.update", Target: u.ID, Detail: changes})
	}
	msg := "User " + u.Username + " updated."
	if password != "" {
		if err := s.store.SetPassword(u.ID, password); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, store.AuditEvent{Action: "password.reset", Target: u.ID})
		msg = "User " + u.Username + " updated, with a new password. They've been signed out everywhere."
		if u.ID == currentUser(r).ID {
			if err := s.startSession(w, r, u.ID); err != nil {
				s.serverError(w, r, err)
				return
			}
			msg = "User " + u.Username + " updated, with a new password. Your other devices have been signed out."
		}
	}
	back := "/admin/users"
	if u.ID == currentUser(r).ID && !u.IsAdmin {
		back = "/" // they can't see the users page any more
	}
	s.redirect(w, r, back, msg)
}

// userChanges describes an edit for the audit log.
func userChanges(old, u *store.User) string {
	var c []string
	if old.Username != u.Username {
		c = append(c, "username "+old.Username+" → "+u.Username)
	}
	if old.DisplayName != u.DisplayName {
		c = append(c, "name "+quoteOrNone(old.DisplayName)+" → "+quoteOrNone(u.DisplayName))
	}
	if old.Email != u.Email {
		c = append(c, "email "+quoteOrNone(old.Email)+" → "+quoteOrNone(u.Email))
	}
	if old.IsAdmin != u.IsAdmin {
		if u.IsAdmin {
			c = append(c, "made a user admin")
		} else {
			c = append(c, "no longer a user admin")
		}
	}
	return strings.Join(c, "; ")
}

func quoteOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return `"` + s + `"`
}

func (s *Server) handleUserDisable(disable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.store.GetUser(pathID(r))
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		back := "/admin/users/" + r.PathValue("id")
		if disable {
			if u.ID == currentUser(r).ID {
				s.setFlash(w, r, "error", "You can't turn off your own account.")
				http.Redirect(w, r, back, http.StatusSeeOther)
				return
			}
			if u.IsAdmin && !u.Disabled {
				if n, _ := s.store.CountActiveAdmins(); n <= 1 {
					s.setFlash(w, r, "error", "At least one active user admin is required.")
					http.Redirect(w, r, back, http.StatusSeeOther)
					return
				}
			}
		}
		if u.Disabled == disable {
			http.Redirect(w, r, back, http.StatusSeeOther)
			return
		}
		if err := s.store.SetDisabled(u.ID, disable); err != nil {
			s.serverError(w, r, err)
			return
		}
		if disable {
			s.audit(r, store.AuditEvent{Action: "user.disable", Target: u.ID})
			s.redirect(w, r, back, u.Username+" has been turned off and signed out everywhere.")
		} else {
			s.audit(r, store.AuditEvent{Action: "user.enable", Target: u.ID})
			s.redirect(w, r, back, u.Username+" can sign in again.")
		}
	}
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE")
}

// Audit log --------------------------------------------------------------

const auditPageSize = 100

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	f := store.AuditFilter{UserID: queryInt(r, "user"), Before: queryInt(r, "before"), Limit: auditPageSize}
	entries, err := s.store.ListAudit(f)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	data := map[string]any{"Title": "Audit log", "Entries": entries}
	if f.UserID != 0 {
		u, err := s.store.GetUser(f.UserID)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Filter"] = u
	}
	if len(entries) == auditPageSize {
		older := "/admin/audit?before=" + itoa(entries[len(entries)-1].ID)
		if f.UserID != 0 {
			older += "&user=" + itoa(f.UserID)
		}
		data["Older"] = older
	}
	s.render(w, r, http.StatusOK, "admin/audit", data)
}

// Settings & backup ------------------------------------------------------

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "admin/settings", map[string]any{"Title": "Settings", "SiteNameValue": s.SiteName()})
}

func (s *Server) handleSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	name := formStr(r, "site_name")
	if name == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "admin/settings", map[string]any{
			"Title": "Settings", "Errors": []string{"Site name is required."}, "SiteNameValue": name,
		})
		return
	}
	if name != s.SiteName() {
		if err := s.store.SetSetting("site_name", name); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, store.AuditEvent{Action: "settings.update", Detail: "site name " + quoteOrNone(s.SiteName()) + " → " + quoteOrNone(name)})
		s.reloadSettings()
	}
	s.redirect(w, r, "/admin/settings", "Settings saved.")
}

// handleBackup streams a consistent snapshot of the database. Restoring is
// just replacing the .db file on the target host while the app is stopped.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	dir, err := os.MkdirTemp("", "um-backup-")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer os.RemoveAll(dir)
	dest := filepath.Join(dir, "backup.db")
	if err := s.store.Backup(r.Context(), dest); err != nil {
		s.serverError(w, r, err)
		return
	}
	f, err := os.Open(dest)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer f.Close()
	s.audit(r, store.AuditEvent{Action: "backup.download"})
	name := "users-" + time.Now().Format("2006-01-02-1504") + ".db"
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	io.Copy(w, f)
}
