// Command user-management runs the church's central accounts and sign-in
// service.
//
//	user-management                       start the web server
//	user-management create-user NAME      create a user (prompts for password)
//	user-management reset-password NAME   set a new password for a user
//	user-management backup FILE           write a consistent copy of the database
//	user-management import-users ...      copy people in from the tracker and planner
//
// Flags such as -db go before the command. Configuration comes from flags
// or environment variables (see README.md).
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // lets TZ work in minimal containers with no zoneinfo

	"golang.org/x/term"

	"github.com/tylergoza/user-management/internal/importer"
	"github.com/tylergoza/user-management/internal/server"
	"github.com/tylergoza/user-management/internal/store"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	addr := flag.String("addr", env("ADDR", ":8100"), "listen address (env ADDR)")
	dbPath := flag.String("db", env("DB_PATH", "data/users.db"), "SQLite database path (env DB_PATH)")
	dev := flag.Bool("dev", env("DEV", "") == "1", "serve templates/static from ./web and reload on each request (env DEV=1)")
	trustProxy := flag.Bool("trust-proxy", env("TRUST_PROXY", "") == "1", "trust X-Forwarded-* headers from a reverse proxy (env TRUST_PROXY=1)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Check the command before opening the database, so a typo or a
	// misplaced flag doesn't quietly create an empty database somewhere.
	args := flag.Args()
	if err := checkCommand(args); errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		logger.Error("open database", "path", *dbPath, "err", err,
			"hint", fmt.Sprintf("make sure the folder exists and user id %d can write to it", os.Getuid()))
		os.Exit(1)
	}
	defer st.Close()

	if len(args) > 0 {
		if err := runCommand(st, args); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	srv, err := server.New(server.Config{Dev: *dev, TrustProxy: *trustProxy}, st, logger)
	if err != nil {
		logger.Error("init server", "err", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodically clear out expired sessions and sign-in codes.
	go func() {
		t := time.NewTicker(6 * time.Hour)
		defer t.Stop()
		for {
			if err := st.PurgeExpired(); err != nil {
				logger.Error("purge expired", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	go func() {
		logger.Info("listening", "addr", *addr, "db", *dbPath, "dev", *dev, "tz", time.Local.String())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpSrv.Shutdown(shutdownCtx)
}

var commandUsage = map[string]string{
	"create-user":    "create-user USERNAME [--admin]",
	"reset-password": "reset-password USERNAME",
	"backup":         "backup DEST_FILE",
	"import-users":   "import-users --tracker FILE --planner FILE [--tracker-url URL] [--planner-url URL] [--prefer tracker|planner] [--dry-run]",
}

const commandList = "create-user, reset-password, backup, import-users"

// checkCommand validates a command line before anything touches the
// database. Flags belong before the command; after it they'd be ignored.
func checkCommand(args []string) error {
	if len(args) == 0 {
		return nil
	}
	usage, ok := commandUsage[args[0]]
	if !ok {
		return fmt.Errorf("unknown command %q (commands: %s)", args[0], commandList)
	}
	if args[0] == "import-users" {
		// This one has its own flags, after the command.
		_, err := importer.ParseArgs(args[1:], os.Stderr)
		return err
	}
	rest := args[1:]
	if args[0] == "create-user" {
		rest = slices.DeleteFunc(slices.Clone(rest), func(a string) bool { return a == "--admin" })
	}
	if len(rest) < 1 {
		return errors.New("usage: " + usage)
	}
	for _, a := range rest {
		if strings.HasPrefix(a, "-") {
			return fmt.Errorf("%s: flags like %s go before the command, e.g. user-management -db /path/to/users.db %s", args[0], a, usage)
		}
	}
	return nil
}

func runCommand(st *store.Store, args []string) error {
	switch args[0] {
	case "create-user":
		// --admin may come before or after the username.
		admin := slices.Contains(args[1:], "--admin")
		username := slices.DeleteFunc(slices.Clone(args[1:]), func(a string) bool { return a == "--admin" })[0]
		if n, _ := st.CountUsers(); n == 0 {
			admin = true // the first user is always an admin
		}
		pw, err := promptPassword()
		if err != nil {
			return err
		}
		id, err := st.CreateUser(&store.User{Username: username, IsAdmin: admin}, pw)
		if err != nil {
			return err
		}
		st.Audit(store.AuditEvent{Action: "user.create", Target: id, Detail: "from the command line"})
		fmt.Printf("Created user %q (admin: %v)\n", username, admin)
	case "reset-password":
		u, err := st.GetUserByUsername(args[1])
		if err != nil {
			return fmt.Errorf("no user %q", args[1])
		}
		pw, err := promptPassword()
		if err != nil {
			return err
		}
		if err := st.SetPassword(u.ID, pw); err != nil {
			return err
		}
		st.Audit(store.AuditEvent{Action: "password.reset", Target: u.ID, Detail: "from the command line"})
		fmt.Printf("Password updated for %q\n", args[1])
	case "backup":
		if _, err := os.Stat(args[1]); err == nil {
			return fmt.Errorf("%s already exists", args[1])
		}
		if err := st.Backup(context.Background(), args[1]); err != nil {
			return err
		}
		fmt.Println("Backup written to", args[1])
	case "import-users":
		opts, err := importer.ParseArgs(args[1:], os.Stderr)
		if err != nil {
			return err
		}
		return importer.Run(st, opts, os.Stdout)
	default:
		return fmt.Errorf("unknown command %q (commands: %s)", args[0], commandList)
	}
	return nil
}

func promptPassword() (string, error) {
	read := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		if term.IsTerminal(int(os.Stdin.Fd())) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(b), err
		}
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	pw, err := read("Password: ")
	if err != nil {
		return "", err
	}
	if len(pw) < 10 || len(pw) > 72 {
		return "", errors.New("password must be 10 to 72 characters")
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		confirm, err := read("Confirm password: ")
		if err != nil {
			return "", err
		}
		if confirm != pw {
			return "", errors.New("passwords do not match")
		}
	}
	return pw, nil
}
