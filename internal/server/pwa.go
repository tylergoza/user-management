package server

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
)

// staticHandler serves web/static. Versioned URLs (?v=hash) are cached
// forever; the hash changes whenever any asset changes.
func (s *Server) staticHandler() http.Handler {
	files := http.StripPrefix("/static/", http.FileServer(http.FS(s.static)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("v") != "" && !s.cfg.Dev {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// handleServiceWorker serves the worker from the site root so its scope
// covers the whole app. The asset version is injected so a deploy with
// changed assets installs a fresh cache.
func (s *Server) handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	src, err := fs.ReadFile(s.webFS, "templates/sw.js")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	precache, _ := json.Marshal([]string{
		"/offline",
		s.asset("css/app.css"),
		s.asset("js/application.js"),
		s.asset("js/stimulus_autoloader.js"),
		s.asset("js/vendor/stimulus.js"),
		s.asset("icons/icon.svg"),
		s.asset("icons/icon-192.png"),
	})
	body := strings.NewReplacer(
		"__VERSION__", s.assetVersion,
		"__PRECACHE__", string(precache),
	).Replace(string(src))
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Service-Worker-Allowed", "/")
	w.Write([]byte(body))
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	name := s.SiteName()
	short := name
	if len(short) > 12 {
		short = "Accounts"
	}
	m := map[string]any{
		"name":             name,
		"short_name":       short,
		"description":      "Church accounts: sign in once for every app, and manage who can use what",
		"start_url":        "/",
		"scope":            "/",
		"display":          "standalone",
		"background_color": "#f6f7f9",
		"theme_color":      "#1f5f8b",
		"icons": []map[string]string{
			{"src": s.asset("icons/icon-192.png"), "sizes": "192x192", "type": "image/png"},
			{"src": s.asset("icons/icon-512.png"), "sizes": "512x512", "type": "image/png"},
			{"src": s.asset("icons/icon-maskable-512.png"), "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
			{"src": s.asset("icons/icon.svg"), "sizes": "any", "type": "image/svg+xml"},
		},
		"shortcuts": []map[string]string{
			{"name": "My apps", "url": "/"},
			{"name": "My account", "url": "/account"},
		},
	}
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(m)
}

func (s *Server) handleOffline(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "offline", map[string]any{"Title": "Offline"})
}
