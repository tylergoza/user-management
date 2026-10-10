// Package server implements the HTTP interface: routing, sessions, HTML
// rendering and request handlers.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tylergoza/user-management/internal/store"
	"github.com/tylergoza/user-management/web"
)

type Config struct {
	// Dev serves templates and static files from ./web on disk and
	// re-parses templates on every request, so edits show up on refresh.
	Dev bool
	// TrustProxy uses X-Forwarded-For / X-Forwarded-Proto from a reverse
	// proxy (Caddy, nginx, a DO load balancer) for client IP and HTTPS.
	TrustProxy bool
	// SessionTTL is how long a sign-in lasts without being used. Each use
	// pushes it forward again.
	SessionTTL time.Duration
}

type Server struct {
	cfg    Config
	store  *store.Store
	log    *slog.Logger
	webFS  fs.FS
	static fs.FS

	// Hash of all static assets, used for cache busting and the service
	// worker cache name.
	assetVersion string
	importMap    template.HTML
	csp          string

	tmplMu sync.Mutex
	tmpls  map[string]*template.Template

	siteName atomic.Value

	limiter *loginLimiter
	handler http.Handler
}

func New(cfg Config, st *store.Store, logger *slog.Logger) (*Server, error) {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 30 * 24 * time.Hour
	}
	s := &Server{cfg: cfg, store: st, log: logger, limiter: newLoginLimiter(10, 15*time.Minute)}
	if cfg.Dev {
		s.webFS = os.DirFS("web")
	} else {
		s.webFS = web.FS
	}
	var err error
	if s.static, err = fs.Sub(s.webFS, "static"); err != nil {
		return nil, err
	}
	if err := s.computeAssets(); err != nil {
		return nil, err
	}
	s.reloadSettings()
	if !cfg.Dev {
		if err := s.parseTemplates(); err != nil {
			return nil, err
		}
	}
	s.handler = s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) reloadSettings() {
	s.siteName.Store(s.store.Setting("site_name", "User Management"))
}

func (s *Server) SiteName() string { return s.siteName.Load().(string) }

// cspHeader adds form-action to the CSP: this site plus the origin of
// every registered redirect URI. Browsers apply form-action to the
// redirects after a form is sent, and signing in on the way to an app ends
// in a redirect to that app. It's read fresh each time, so an app added
// from the command line works without a restart.
func (s *Server) cspHeader() string {
	list := []string{"'self'"}
	apps, err := s.store.ListApps()
	if err != nil {
		s.log.Error("csp: list apps", "err", err)
	}
	for _, a := range apps {
		for _, uri := range a.RedirectURIs {
			if u, err := url.Parse(uri); err == nil && u.Host != "" {
				if o := u.Scheme + "://" + u.Host; !slices.Contains(list, o) {
					list = append(list, o)
				}
			}
		}
	}
	return s.csp + "; form-action " + strings.Join(list, " ")
}

// computeAssets hashes the static tree and builds the import map. The
// import map is an inline script, so its hash goes into the CSP.
func (s *Server) computeAssets() error {
	h := sha256.New()
	var files []string
	err := fs.WalkDir(s.static, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		b, err := fs.ReadFile(s.static, f)
		if err != nil {
			return err
		}
		h.Write([]byte(f))
		h.Write(b)
	}
	s.assetVersion = hex.EncodeToString(h.Sum(nil))[:12]

	im, err := json.MarshalIndent(map[string]any{
		"imports": map[string]string{
			"@hotwired/stimulus":  s.asset("js/vendor/stimulus.js"),
			"stimulus-autoloader": s.asset("js/stimulus_autoloader.js"),
		},
	}, "", "  ")
	if err != nil {
		return err
	}
	// Emitted verbatim as a whole tag: html/template would otherwise
	// JS-escape it inside the <script> element.
	s.importMap = template.HTML(`<script type="importmap">` + string(im) + `</script>`)
	sum := sha256.Sum256(im)
	s.csp = strings.Join([]string{
		"default-src 'self'",
		"script-src 'self' 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'",
		"style-src 'self'",
		"img-src 'self' data:",
		"connect-src 'self'",
		"manifest-src 'self'",
		"worker-src 'self'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
	}, "; ")
	return nil
}

// asset returns the versioned URL for a file under web/static.
func (s *Server) asset(p string) string {
	return "/static/" + strings.TrimPrefix(p, "/") + "?v=" + s.assetVersion
}

// Templates --------------------------------------------------------------

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"asset":      s.asset,
		"fmtTime":    fmtTime,
		"ago":        ago,
		"dict":       dict,
		"auditLabel": store.AuditLabel,
		"device":     device,
	}
}

func (s *Server) parseTemplates() error {
	pages, err := fs.Glob(s.webFS, "templates/pages/*.html")
	if err != nil {
		return err
	}
	for _, pattern := range []string{"templates/pages/*/*.html", "templates/pages/*/*/*.html"} {
		sub, _ := fs.Glob(s.webFS, pattern)
		pages = append(pages, sub...)
	}
	shared := []string{"templates/layout.html", "templates/partials/*.html"}
	tmpls := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/pages/"), ".html")
		t, err := template.New("layout.html").Funcs(s.funcs()).ParseFS(s.webFS, append(shared, p)...)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		tmpls[name] = t
	}
	s.tmplMu.Lock()
	s.tmpls = tmpls
	s.tmplMu.Unlock()
	return nil
}

func (s *Server) template(name string) (*template.Template, error) {
	if s.cfg.Dev {
		if err := s.parseTemplates(); err != nil {
			return nil, err
		}
	}
	s.tmplMu.Lock()
	defer s.tmplMu.Unlock()
	t, ok := s.tmpls[name]
	if !ok {
		return nil, fmt.Errorf("no template %q", name)
	}
	return t, nil
}

type flash struct {
	Kind    string // "success" | "error" | "info"
	Message string
}

// render executes a page inside the layout. Every page gets the common
// keys (User, CSRF, Flash, SiteName, ...) merged into data.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["User"] = currentUser(r)
	data["CSRF"] = csrfToken(r)
	data["SiteName"] = s.SiteName()
	data["ImportMap"] = s.importMap
	data["AssetVersion"] = s.assetVersion
	data["Path"] = r.URL.Path
	data["URI"] = r.URL.RequestURI()
	if f := s.popFlash(w, r); f != nil {
		data["Flash"] = f
	}
	if _, ok := data["Title"]; !ok {
		data["Title"] = ""
	}
	t, err := s.template(page)
	if err != nil {
		s.log.Error("template lookup", "page", page, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	// Render into a buffer so a template error doesn't produce half a page.
	var buf strings.Builder
	if err := t.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		s.log.Error("template exec", "page", page, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(buf.String()))
}

const flashCookie = "um_flash"

func (s *Server) setFlash(w http.ResponseWriter, r *http.Request, kind, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(kind + "|" + msg)),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.isHTTPS(r), MaxAge: 60,
	})
}

func (s *Server) popFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Path: "/", MaxAge: -1})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	kind, msg, ok := strings.Cut(string(b), "|")
	if !ok {
		return nil
	}
	return &flash{Kind: kind, Message: msg}
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, to, flashMsg string) {
	if flashMsg != "" {
		s.setFlash(w, r, "success", flashMsg)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// audit records an event, filling in the signed-in user as the actor (when
// not set) and the client's IP. A failure is logged, not shown.
func (s *Server) audit(r *http.Request, e store.AuditEvent) {
	if e.Actor == 0 {
		if u := currentUser(r); u != nil {
			e.Actor = u.ID
		}
	}
	e.IP = s.clientIP(r)
	if err := s.store.Audit(e); err != nil {
		s.log.Error("audit log", "action", e.Action, "err", err)
	}
}

// Errors -----------------------------------------------------------------

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, r)
		return
	}
	s.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	s.render(w, r, http.StatusInternalServerError, "error", map[string]any{
		"Title": "Something went wrong", "Message": "An unexpected error occurred. It has been logged.",
	})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusNotFound, "error", map[string]any{
		"Title": "Not found", "Message": "We couldn't find what you were looking for.",
	})
}

// Times ------------------------------------------------------------------

// fmtTime renders a stored UTC timestamp ("YYYY-MM-DD HH:MM:SS") in local time.
func fmtTime(ts string) string {
	t, err := time.ParseInLocation(store.TimeLayout, ts, time.UTC)
	if err != nil {
		return ts
	}
	return t.Local().Format("Jan 2, 2006 3:04 PM")
}

// ago renders a stored timestamp as "5 minutes ago", "3 days ago", ...
func ago(ts string) string {
	t, err := time.ParseInLocation(store.TimeLayout, ts, time.UTC)
	if err != nil {
		return ts
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return pluralize(int(d/time.Minute), "minute") + " ago"
	case d < 24*time.Hour:
		return pluralize(int(d/time.Hour), "hour") + " ago"
	case d < 60*24*time.Hour:
		return pluralize(int(d/(24*time.Hour)), "day") + " ago"
	default:
		return fmtTime(ts)
	}
}

func pluralize(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// device names a browser from its user agent, roughly: "Safari on iPhone".
func device(ua string) string {
	var browser, osName string
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Firefox/"), strings.Contains(ua, "FxiOS/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	switch {
	case strings.Contains(ua, "iPhone"):
		osName = "iPhone"
	case strings.Contains(ua, "iPad"):
		osName = "iPad"
	case strings.Contains(ua, "Android"):
		osName = "Android"
	case strings.Contains(ua, "Mac OS X"):
		osName = "Mac"
	case strings.Contains(ua, "Windows"):
		osName = "Windows"
	case strings.Contains(ua, "CrOS"):
		osName = "Chromebook"
	case strings.Contains(ua, "Linux"):
		osName = "Linux"
	}
	switch {
	case browser != "" && osName != "":
		return browser + " on " + osName
	case browser != "":
		return browser
	case osName != "":
		return osName
	}
	return "Unknown browser"
}

func dict(kv ...any) (map[string]any, error) {
	if len(kv)%2 != 0 {
		return nil, errors.New("dict needs key/value pairs")
	}
	m := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			return nil, errors.New("dict keys must be strings")
		}
		m[k] = kv[i+1]
	}
	return m, nil
}

// Form helpers -----------------------------------------------------------

func formStr(r *http.Request, key string) string { return strings.TrimSpace(r.PostFormValue(key)) }

func queryInt(r *http.Request, key string) int64 {
	n, _ := strconv.ParseInt(r.URL.Query().Get(key), 10, 64)
	return n
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func pathID(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return n
}

// Context ----------------------------------------------------------------

type ctxKey int

const (
	ctxUser ctxKey = iota
	ctxSession
	ctxCSRF
	ctxApp // the app calling /token or the API
)

func currentUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

func currentSession(r *http.Request) *store.Session {
	sess, _ := r.Context().Value(ctxSession).(*store.Session)
	return sess
}

func csrfToken(r *http.Request) string {
	t, _ := r.Context().Value(ctxCSRF).(string)
	return t
}

func withValue(r *http.Request, k ctxKey, v any) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), k, v))
}

// safeRedirect only allows local paths, preventing open redirects. The
// query string is kept, since signing in on the way to /authorize needs it.
func safeRedirect(to string) string {
	if to == "" || !strings.HasPrefix(to, "/") || strings.HasPrefix(to, "//") || strings.HasPrefix(to, "/\\") {
		return "/"
	}
	u, err := url.Parse(to)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	p := path.Clean(u.EscapedPath())
	if strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || !strings.HasPrefix(p, "/") {
		return "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}
