package main

import (
	"path/filepath"
	"testing"

	"github.com/tylergoza/user-management/internal/store"
)

// The deploy playbooks rely on `backup` for pre-deploy and on-demand copies.
func TestBackupCommand(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateUser(&store.User{Username: "alice", IsAdmin: true}, "a long password"); err != nil {
		t.Fatal(err)
	}

	if err := checkCommand([]string{"backup"}); err == nil {
		t.Error("backup with no destination should be refused")
	}
	dest := filepath.Join(dir, "copy.db")
	if err := checkCommand([]string{"backup", dest}); err != nil {
		t.Fatal(err)
	}
	if err := runCommand(st, []string{"backup", dest}); err != nil {
		t.Fatal(err)
	}

	cp, err := store.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.Close()
	if n, err := cp.CountUsers(); err != nil || n != 1 {
		t.Errorf("copy has %d users (err %v), want 1", n, err)
	}

	if err := runCommand(st, []string{"backup", dest}); err == nil {
		t.Error("backup over an existing file should be refused")
	}
}
