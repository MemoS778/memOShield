package personal

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type session struct{ expires time.Time }
type API struct {
	engine   *Engine
	token    string
	mu       sync.Mutex
	sessions map[string]session
	attempts []time.Time
	streams  chan struct{}
}

// NewLocalAPI serves authenticated JSON over the private Unix socket.
// "localhost" is the protocol authority, not a TCP listener address.
func NewLocalAPI(e *Engine, token string) http.Handler {
	w := &API{engine: e, token: token, sessions: make(map[string]session), streams: make(chan struct{}, 8)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", w.login)
	mux.HandleFunc("POST /api/logout", w.auth(w.logout))
	mux.HandleFunc("GET /api/status", w.auth(w.status))
	mux.HandleFunc("GET /api/events", w.auth(w.events))
	mux.HandleFunc("GET /api/bans", w.auth(w.bans))
	mux.HandleFunc("POST /api/ban", w.auth(w.ban))
	mux.HandleFunc("POST /api/unban", w.auth(w.unban))
	mux.HandleFunc("GET /api/allowlist", w.auth(w.allowlist))
	mux.HandleFunc("POST /api/allowlist", w.auth(w.allow))
	mux.HandleFunc("GET /api/stream", w.auth(w.stream))
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Host != "localhost" {
			http.Error(rw, "invalid host", 403)
			return
		}
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Exact Origin validation protects all mutations, including login/logout.
			if r.Header.Get("Origin") != "http://"+r.Host {
				http.Error(rw, "invalid origin", 403)
				return
			}
			if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
				http.Error(rw, "application/json required", 415)
				return
			}
			r.Body = http.MaxBytesReader(rw, r.Body, 4096)
		}
		mux.ServeHTTP(rw, r)
	})
}

func reply(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func fail(w http.ResponseWriter, status int, err error) {
	reply(w, status, map[string]string{"error": err.Error()})
}
func decode(r *http.Request, v interface{}) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := d.Decode(new(interface{})); err != io.EOF {
		return fmt.Errorf("exactly one JSON object is required")
	}
	return nil
}

func (w *API) loggedIn(r *http.Request) bool {
	c, err := r.Cookie("memoshield_session")
	if err != nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.sessions[c.Value]
	if !ok || time.Now().After(s.expires) {
		delete(w.sessions, c.Value)
		return false
	}
	return true
}
func (w *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if !w.loggedIn(r) {
			fail(rw, 401, fmt.Errorf("authentication required"))
			return
		}
		next(rw, r)
	}
}

func (w *API) login(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	now := time.Now()
	valid := w.attempts[:0]
	for _, t := range w.attempts {
		if now.Sub(t) < time.Minute {
			valid = append(valid, t)
		}
	}
	w.attempts = valid
	if len(valid) >= 10 {
		w.mu.Unlock()
		rw.Header().Set("Retry-After", "60")
		fail(rw, 429, fmt.Errorf("too many login attempts"))
		return
	}
	w.attempts = append(w.attempts, now)
	w.mu.Unlock()
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(r, &body); err != nil {
		fail(rw, 400, err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Token), []byte(w.token)) != 1 {
		fail(rw, 401, fmt.Errorf("invalid access token"))
		return
	}
	id, err := randomToken()
	if err != nil {
		fail(rw, 500, err)
		return
	}
	w.mu.Lock()
	for k, s := range w.sessions {
		if now.After(s.expires) {
			delete(w.sessions, k)
		}
	}
	if len(w.sessions) >= 10 {
		w.mu.Unlock()
		fail(rw, 429, fmt.Errorf("session limit reached"))
		return
	}
	w.sessions[id] = session{expires: now.Add(8 * time.Hour)}
	w.mu.Unlock()
	// HTTP is an IPC protocol over the private Unix socket; no TLS/TCP is used.
	http.SetCookie(rw, &http.Cookie{Name: "memoshield_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600})
	reply(rw, 200, map[string]bool{"ok": true})
}
func (w *API) logout(rw http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("memoshield_session")
	w.mu.Lock()
	delete(w.sessions, c.Value)
	w.mu.Unlock()
	http.SetCookie(rw, &http.Cookie{Name: "memoshield_session", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	reply(rw, 200, map[string]bool{"ok": true})
}
func (w *API) status(rw http.ResponseWriter, r *http.Request) {
	reply(rw, 200, map[string]interface{}{"mode": w.engine.config.Mode, "sensors": w.engine.Statuses(), "scope": "Bu bilgisayar ve yapılandırılmış sensörün görebildiği trafik; tüm Wi-Fi ağı değil."})
}
func (w *API) events(rw http.ResponseWriter, r *http.Request) {
	rows, err := w.engine.store.Events(0, true)
	if err != nil {
		fail(rw, 500, err)
		return
	}
	reply(rw, 200, map[string]interface{}{"events": rows})
}
func (w *API) bans(rw http.ResponseWriter, r *http.Request) {
	rows, err := w.engine.store.Bans()
	if err != nil {
		fail(rw, 500, err)
		return
	}
	reply(rw, 200, map[string]interface{}{"bans": rows})
}
func (w *API) allowlist(rw http.ResponseWriter, r *http.Request) {
	rows, err := w.engine.store.Allowlist()
	if err != nil {
		fail(rw, 500, err)
		return
	}
	reply(rw, 200, map[string]interface{}{"prefixes": rows})
}
func (w *API) ban(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		IP      string `json:"ip"`
		Reason  string `json:"reason"`
		Minutes int    `json:"minutes"`
	}
	if err := decode(r, &b); err != nil {
		fail(rw, 400, err)
		return
	}
	if b.Minutes < 1 || b.Minutes > 60 {
		fail(rw, 400, fmt.Errorf("minutes must be between 1 and 60"))
		return
	}
	if err := w.engine.Ban(r.Context(), b.IP, b.Reason, time.Duration(b.Minutes)*time.Minute); err != nil {
		fail(rw, 409, err)
		return
	}
	reply(rw, 200, map[string]bool{"ok": true})
}
func (w *API) unban(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		IP string `json:"ip"`
	}
	if err := decode(r, &b); err != nil {
		fail(rw, 400, err)
		return
	}
	if err := w.engine.Unban(r.Context(), b.IP); err != nil {
		fail(rw, 409, err)
		return
	}
	reply(rw, 200, map[string]bool{"ok": true})
}
func (w *API) allow(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		Prefix string `json:"prefix"`
		Add    bool   `json:"add"`
	}
	if err := decode(r, &b); err != nil {
		fail(rw, 400, err)
		return
	}
	if err := w.engine.Allow(r.Context(), b.Prefix, b.Add); err != nil {
		fail(rw, 409, err)
		return
	}
	reply(rw, 200, map[string]bool{"ok": true})
}

func (w *API) stream(rw http.ResponseWriter, r *http.Request) {
	select {
	case w.streams <- struct{}{}:
		defer func() { <-w.streams }()
	default:
		fail(rw, 429, fmt.Errorf("stream limit reached"))
		return
	}
	raw := r.Header.Get("Last-Event-ID")
	if raw == "" {
		raw = r.URL.Query().Get("after")
	}
	if raw == "" {
		raw = "0"
	}
	after, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || after < 0 {
		fail(rw, 400, fmt.Errorf("invalid cursor"))
		return
	}
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("X-Accel-Buffering", "no")
	controller := http.NewResponseController(rw)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if !w.loggedIn(r) {
			return
		}
		rows, err := w.engine.store.Events(after, false)
		if err != nil {
			return
		}
		if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return
		}
		for _, event := range rows {
			data, err := json.Marshal(event)
			if err != nil {
				return
			}
			if _, err := fmt.Fprintf(rw, "id: %d\ndata: %s\n\n", event.ID, data); err != nil {
				return
			}
			after = event.ID
		}
		if _, err := io.WriteString(rw, ": heartbeat\n\n"); err != nil {
			return
		}
		if err := controller.Flush(); err != nil {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
