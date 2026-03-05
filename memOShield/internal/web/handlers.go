package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MemoS778/memOShield/internal/broadcaster"
	"github.com/MemoS778/memOShield/internal/config"
	"github.com/MemoS778/memOShield/internal/db"
	"github.com/MemoS778/memOShield/internal/firewall"
	"github.com/MemoS778/memOShield/internal/geoip"
	"github.com/MemoS778/memOShield/internal/ids"
	"github.com/MemoS778/memOShield/internal/notifier"
	"github.com/MemoS778/memOShield/internal/security"
	"github.com/MemoS778/memOShield/internal/whitelist"
)

// startTime tracks when the server started.
var startTime = time.Now()

// ==================== Global Security Components ====================

var (
	loginLimiter   = security.NewRateLimiter(30, 1*time.Minute)
	apiLimiter     = security.NewRateLimiter(300, 1*time.Minute)
	streamLimiter  = security.NewRateLimiter(30, 1*time.Minute) // SSE connection limiter
	loginProtector = security.NewLoginProtector(20, 10*time.Minute, 5*time.Minute)
	csrfManager    = security.NewCSRFManager(30 * time.Minute)
	auditLog       = security.NewAuditLog(2000)
	waf            = security.NewWAF()
	ipReputation   = security.NewIPReputation(config.IPReputationAutoBan)
	uaAnalyzer     = security.NewUAAnalyzer()
	sessionMgr     = security.NewSessionManager(config.MaxAdminSessions)
	geoBlocker     = security.NewGeoBlocker(config.GeoBlockCountries)
	adminAllowlist = security.NewAdminAllowlist(config.AdminAllowedIPs)
	totpManager    = security.NewTOTPManager()
)

func init() {
	// Load TOTP secret from config if set
	if config.TOTPSecret != "" {
		totpManager.SetSecret(config.TOTPSecret)
		log.Println("SECURITY: TOTP 2FA enabled from config")
	}
}

// ==================== Server ====================

type Server struct {
	fw       *firewall.Firewall
	geo      *geoip.Client
	ids      *ids.IDS
	notifier *notifier.Notifier
	mux      *http.ServeMux
	tmplDir  string
	handler  http.Handler
}

func NewServer(fw *firewall.Firewall, geo *geoip.Client, idsEngine *ids.IDS, n *notifier.Notifier) *Server {
	s := &Server{
		fw:       fw,
		geo:      geo,
		ids:      idsEngine,
		notifier: n,
		mux:      http.NewServeMux(),
		tmplDir:  "templates",
	}
	s.routes()

	// Build middleware chain (order matters — outermost first):
	// PanicRecovery → RequestID → RequestLogger → SecureHeaders →
	// ContentTypeCheck → BodyLimit → UA Blocker → WAF → Mux
	var h http.Handler = s.mux
	if config.WAFEnabled {
		h = waf.Middleware(h)
	}
	h = s.uaBlockMiddleware(h)
	h = security.MaxBodySize(h, 1<<20) // 1MB
	h = security.ContentTypeCheck(h)
	h = security.SecureHeaders(h)
	h = security.RequestLogger(h)
	h = security.RequestIDMiddleware(h)
	h = security.PanicRecovery(h)
	s.handler = h

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// uaBlockMiddleware blocks known attack tool User-Agents.
func (s *Server) uaBlockMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if !config.UABlockEnabled {
			next.ServeHTTP(w, r)
			return
		}
		ua := r.Header.Get("User-Agent")
		result := uaAnalyzer.Analyze(ua)

		ip := security.ClientIP(r)
		if result == "block" {
			auditLog.Record(ip, "UA_BLOCKED", fmt.Sprintf("Blocked UA: %s", security.SanitizeInput(ua, 100)), false)
			ipReputation.RecordEvent(ip, "bad_ua", 25)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		if result == "suspicious" {
			ipReputation.RecordEvent(ip, "suspicious_ua", 5)
		}
		next.ServeHTTP(w, r)
	})
}

// ==================== Routes ====================

func (s *Server) routes() {
	staticDir := filepath.Join(".", "static")
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	// Pages
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/dashboard", s.handleDashboard)
	s.mux.HandleFunc("/demo", s.handleDemo)
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/logout", s.handleLogout)

	// API — rate-limited
	s.mux.HandleFunc("/api/events", s.apiRateLimit(s.handleAPIEvents))
	s.mux.HandleFunc("/api/rules", s.apiRateLimit(s.handleAPIRules))
	s.mux.HandleFunc("/api/bans", s.apiRateLimit(s.handleAPIBans))
	s.mux.HandleFunc("/api/lookup/", s.apiRateLimit(s.handleAPILookup))
	s.mux.HandleFunc("/api/unban", s.apiRateLimit(s.requireAuth(s.handleAPIUnban)))
	s.mux.HandleFunc("/api/ban", s.apiRateLimit(s.requireAuth(s.handleAPIBan)))
	s.mux.HandleFunc("/api/record", s.apiRateLimit(s.handleAPIRecord))
	s.mux.HandleFunc("/api/whitelist", s.apiRateLimit(s.requireAuth(s.handleAPIWhitelist)))
	s.mux.HandleFunc("/api/whitelist/add", s.apiRateLimit(s.requireAuth(s.handleAPIWhitelistAdd)))
	s.mux.HandleFunc("/api/whitelist/remove", s.apiRateLimit(s.requireAuth(s.handleAPIWhitelistRemove)))
	s.mux.HandleFunc("/api/honeypot-status", s.apiRateLimit(s.handleAPIHoneypotStatus))
	s.mux.HandleFunc("/api/stats", s.apiRateLimit(s.requireAuth(s.handleAPIStats)))
	s.mux.HandleFunc("/api/health", s.apiRateLimit(s.handleAPIHealth))
	s.mux.HandleFunc("/api/events/clear", s.apiRateLimit(s.requireAuth(s.handleAPIEventsClear)))
	s.mux.HandleFunc("/api/audit", s.apiRateLimit(s.requireAuth(s.handleAPIAudit)))

	// New security endpoints
	s.mux.HandleFunc("/api/security/score", s.apiRateLimit(s.requireAuth(s.handleAPISecurityScore)))
	s.mux.HandleFunc("/api/security/waf", s.apiRateLimit(s.requireAuth(s.handleAPIWAFStats)))
	s.mux.HandleFunc("/api/security/waf/events", s.apiRateLimit(s.requireAuth(s.handleAPIWAFEvents)))
	s.mux.HandleFunc("/api/security/reputation", s.apiRateLimit(s.requireAuth(s.handleAPIReputation)))
	s.mux.HandleFunc("/api/security/reputation/lookup/", s.apiRateLimit(s.requireAuth(s.handleAPIReputationLookup)))
	s.mux.HandleFunc("/api/security/sessions", s.apiRateLimit(s.requireAuth(s.handleAPISessions)))
	s.mux.HandleFunc("/api/security/geoblock", s.apiRateLimit(s.requireAuth(s.handleAPIGeoBlock)))
	s.mux.HandleFunc("/api/security/geoblock/add", s.apiRateLimit(s.requireAuth(s.handleAPIGeoBlockAdd)))
	s.mux.HandleFunc("/api/security/geoblock/remove", s.apiRateLimit(s.requireAuth(s.handleAPIGeoBlockRemove)))
	s.mux.HandleFunc("/api/security/2fa/setup", s.apiRateLimit(s.requireAuth(s.handleAPI2FASetup)))
	s.mux.HandleFunc("/api/security/2fa/verify", s.apiRateLimit(s.requireAuth(s.handleAPI2FAVerify)))
	s.mux.HandleFunc("/api/security/2fa/disable", s.apiRateLimit(s.requireAuth(s.handleAPI2FADisable)))
	s.mux.HandleFunc("/api/security/2fa/status", s.apiRateLimit(s.requireAuth(s.handleAPI2FAStatus)))

	// SSE stream
	s.mux.HandleFunc("/stream", s.handleStream)
}

// ==================== Middleware Wrappers ====================

func (s *Server) apiRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := security.ClientIP(r)
		if !apiLimiter.Allow(ip) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set("X-RateLimit-Remaining", "0")
			jsonError(w, "rate limit exceeded — try again later", 429)
			auditLog.Record(ip, "RATE_LIMIT", r.URL.Path, false)
			ipReputation.RecordEvent(ip, "rate_limit", 10)
			return
		}
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(apiLimiter.Remaining(ip)))
		next(w, r)
	}
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isLoggedIn(r) {
			ip := security.ClientIP(r)
			auditLog.Record(ip, "UNAUTH_ACCESS", r.URL.Path, false)
			ipReputation.RecordEvent(ip, "unauth_access", 5)
			jsonError(w, "authentication required", 403)
			return
		}
		next(w, r)
	}
}

// requireAdminIP checks admin IP allowlist before allowing access.
func (s *Server) requireAdminIP(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := security.ClientIP(r)
		if !adminAllowlist.IsAllowed(ip) {
			auditLog.Record(ip, "ADMIN_IP_DENIED", fmt.Sprintf("IP %s not in admin allowlist", ip), false)
			jsonError(w, "access denied", 403)
			return
		}
		next(w, r)
	}
}

// ==================== Template ====================

type pageData struct {
	LoggedIn    bool
	Demo        bool
	Flash       string
	FlashCat    string
	CSRFToken   string
	TOTPEnabled bool
}

func (s *Server) renderTemplate(w http.ResponseWriter, base string, page string, data interface{}) {
	tmpl, err := template.ParseFiles(
		filepath.Join(s.tmplDir, base),
		filepath.Join(s.tmplDir, page),
	)
	if err != nil {
		log.Printf("Template parse error: %v", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		log.Printf("Template execute error: %v", err)
	}
}

func (s *Server) renderStandalone(w http.ResponseWriter, name string, data interface{}) {
	tmpl, err := template.ParseFiles(filepath.Join(s.tmplDir, name))
	if err != nil {
		log.Printf("Template parse error: %v", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Template execute error: %v", err)
	}
}

// ==================== Session (HMAC signed cookie + fingerprint) ====================

func (s *Server) isLoggedIn(r *http.Request) bool {
	c, err := r.Cookie("session")
	if err != nil {
		return false
	}
	if !verifySession(c.Value) {
		return false
	}

	// Validate session fingerprint
	sidCookie, err := r.Cookie("sid")
	if err != nil {
		return false
	}
	sessionID := sidCookie.Value
	ua := r.Header.Get("User-Agent")
	if !sessionMgr.ValidateSession(sessionID, ua) {
		return false
	}

	return true
}

func setLoggedIn(w http.ResponseWriter, r *http.Request) string {
	ts := time.Now().Unix()
	fp := security.SessionFingerprint(r)
	val := signSession(fmt.Sprintf("logged_in=1&ts=%d&fp=%s", ts, fp))
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   config.SessionMaxAge,
	})

	// Create managed session
	ip := security.ClientIP(r)
	ua := r.Header.Get("User-Agent")
	sessionID := sessionMgr.CreateSession(ip, ua)

	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   config.SessionMaxAge,
	})

	return sessionID
}

func clearSession(w http.ResponseWriter, r *http.Request) {
	// Destroy managed session
	if c, err := r.Cookie("sid"); err == nil {
		sessionMgr.DestroySession(c.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name: "session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "sid", Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
}

func signSession(data string) string {
	mac := hmac.New(sha256.New, []byte(config.SecretKey))
	mac.Write([]byte(data))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return base64.URLEncoding.EncodeToString([]byte(data)) + "." + sig
}

func verifySession(token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	data, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	expected := signSession(string(data))
	if !hmac.Equal([]byte(token), []byte(expected)) {
		return false
	}

	// Check session expiry (max 24 hours)
	dataStr := string(data)
	if idx := strings.Index(dataStr, "ts="); idx >= 0 {
		tsStr := dataStr[idx+3:]
		if ampIdx := strings.Index(tsStr, "&"); ampIdx >= 0 {
			tsStr = tsStr[:ampIdx]
		}
		if ts, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
			if time.Now().Unix()-ts > 86400 {
				return false
			}
		}
	}
	return true
}

// Flash message cookie
func setFlash(w http.ResponseWriter, msg, cat string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "flash",
		Value:    base64.URLEncoding.EncodeToString([]byte(cat + "|" + msg)),
		Path:     "/",
		HttpOnly: true,
	})
}

func getFlash(w http.ResponseWriter, r *http.Request) (string, string) {
	c, err := r.Cookie("flash")
	if err != nil {
		return "", ""
	}
	http.SetCookie(w, &http.Cookie{
		Name: "flash", Value: "", Path: "/", MaxAge: -1,
	})
	data, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", ""
	}
	parts := strings.SplitN(string(data), "|", 2)
	if len(parts) == 2 {
		return parts[1], parts[0]
	}
	return string(data), "info"
}

// ==================== Page Handlers ====================

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		// Track 404s — common in scanning attempts
		ip := security.ClientIP(r)
		ipReputation.RecordEvent(ip, "404_probe", 3)
		http.NotFound(w, r)
		return
	}
	s.renderStandalone(w, "index.html", nil)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	demo := r.URL.Query().Get("demo") == "1"
	if !demo && !s.isLoggedIn(r) {
		http.Redirect(w, r, "/login?next=/dashboard", http.StatusFound)
		return
	}
	data := pageData{
		LoggedIn: s.isLoggedIn(r),
		Demo:     demo,
	}
	s.renderTemplate(w, "base.html", "dashboard.html", data)
}

func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	data := pageData{Demo: true, LoggedIn: s.isLoggedIn(r)}
	s.renderTemplate(w, "base.html", "dashboard.html", data)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := security.ClientIP(r)

	// Check admin IP allowlist
	if !adminAllowlist.IsAllowed(ip) {
		auditLog.Record(ip, "ADMIN_IP_DENIED", "Login page access denied — IP not in allowlist", false)
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodPost {
		// Check honeypot field (bot detection)
		if config.LoginHoneypotEnabled && security.IsHoneypotTriggered(r) {
			auditLog.Record(ip, "HONEYPOT_BOT", "Bot detected via honeypot field on login", false)
			ipReputation.RecordEvent(ip, "honeypot_bot", 50)
			// Silently redirect as if success (confuse bot)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Check brute force lockout
		if config.LoginLockoutEnabled {
			if locked, remaining := loginProtector.IsLocked(ip); locked {
				auditLog.Record(ip, "LOGIN_LOCKED", fmt.Sprintf("IP locked for %v", remaining), false)
				setFlash(w, fmt.Sprintf("Cok fazla basarisiz deneme. %d dakika sonra tekrar deneyin.", int(remaining.Minutes())+1), "error")
				http.Redirect(w, r, r.URL.String(), http.StatusFound)
				return
			}
		}

		// Login rate limit
		if config.LoginRateLimitEnabled && !loginLimiter.Allow(ip) {
			auditLog.Record(ip, "LOGIN_RATE_LIMIT", "Too many login attempts", false)
			ipReputation.RecordEvent(ip, "login_flood", 15)
			setFlash(w, "Cok fazla istek. Lutfen bekleyin.", "error")
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
			return
		}

		// CSRF
		if config.LoginCSRFEnabled {
			r.ParseForm()
			csrfToken := r.FormValue("csrf_token")
			if !csrfManager.Validate(csrfToken) {
				auditLog.Record(ip, "CSRF_FAIL", "Invalid CSRF token on login", false)
				ipReputation.RecordEvent(ip, "csrf_fail", 20)
				setFlash(w, "Guvenlik dogrulamasi basarisiz. Tekrar deneyin.", "error")
				http.Redirect(w, r, r.URL.String(), http.StatusFound)
				return
			}
		}

		pw := r.FormValue("password")
		if security.VerifyPassword(pw, config.AdminPassword) {
			// Check TOTP if enabled
			if totpManager.IsEnabled() {
				totpCode := r.FormValue("totp_code")
				if !totpManager.Validate(totpCode) {
					auditLog.Record(ip, "TOTP_FAIL", "Invalid TOTP code", false)
					ipReputation.RecordEvent(ip, "totp_fail", 15)
					setFlash(w, "Gecersiz 2FA kodu.", "error")
					http.Redirect(w, r, r.URL.String(), http.StatusFound)
					return
				}
				auditLog.Record(ip, "TOTP_SUCCESS", "Valid TOTP code", true)
			}

			loginProtector.RecordSuccess(ip)
			auditLog.Record(ip, "LOGIN_SUCCESS", "Admin login", true)
			setLoggedIn(w, r)

			next := r.URL.Query().Get("next")
			if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
				next = "/dashboard"
			}

			// Notify on login
			s.notifier.SendTelegram(fmt.Sprintf("Admin login from IP: %s", ip))

			http.Redirect(w, r, next, http.StatusFound)
			return
		}

		// Failed login
		if config.LoginLockoutEnabled {
			loginProtector.RecordFailure(ip)
		}
		auditLog.Record(ip, "LOGIN_FAIL", "Wrong password", false)
		ipReputation.RecordEvent(ip, "login_fail", 15)
		setFlash(w, "Yanlis parola", "error")
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
		return
	}

	flash, flashCat := getFlash(w, r)
	data := pageData{
		LoggedIn:    s.isLoggedIn(r),
		Flash:       flash,
		FlashCat:    flashCat,
		CSRFToken:   "",
		TOTPEnabled: totpManager.IsEnabled(),
	}
	if config.LoginCSRFEnabled {
		data.CSRFToken = csrfManager.Generate()
	}
	s.renderTemplate(w, "base.html", "login.html", data)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ip := security.ClientIP(r)
	auditLog.Record(ip, "LOGOUT", "Admin logout", true)
	clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

// ==================== API Handlers ====================

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	events := db.GetEvents(200)
	if events == nil {
		events = []db.Event{}
	}
	jsonResponse(w, events)
}

func (s *Server) handleAPIRules(w http.ResponseWriter, r *http.Request) {
	rules := db.GetRules()
	if rules == nil {
		rules = []db.Rule{}
	}
	jsonResponse(w, map[string]interface{}{"rules": rules})
}

func (s *Server) handleAPIBans(w http.ResponseWriter, r *http.Request) {
	bans := db.GetBans(200)
	if bans == nil {
		bans = []db.Ban{}
	}
	jsonResponse(w, bans)
}

func (s *Server) handleAPILookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/lookup/")
	if ip == "" {
		jsonError(w, "ip required", 400)
		return
	}
	if !security.ValidateIP(ip) {
		jsonError(w, "invalid IP format", 400)
		return
	}

	// Check geo-blocking on lookup
	info := s.geo.Lookup(ip)
	jsonResponse(w, info)
}

func (s *Server) handleAPIUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		jsonError(w, "ip required", 400)
		return
	}
	if !security.ValidateIP(body.IP) {
		jsonError(w, "invalid IP format", 400)
		return
	}
	clientIP := security.ClientIP(r)
	auditLog.Record(clientIP, "UNBAN", fmt.Sprintf("Unbanned IP: %s", body.IP), true)
	s.fw.RemoveRule(body.IP)
	jsonResponse(w, map[string]bool{"ok": true})
}

func (s *Server) handleAPIBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var body struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		jsonError(w, "ip required", 400)
		return
	}
	if !security.ValidateIP(body.IP) {
		jsonError(w, "invalid IP format", 400)
		return
	}
	if body.Reason == "" {
		body.Reason = "manual"
	}
	body.Reason = security.SanitizeInput(body.Reason, 200)

	clientIP := security.ClientIP(r)
	auditLog.Record(clientIP, "BAN", fmt.Sprintf("Banned IP: %s reason: %s", body.IP, body.Reason), true)
	s.fw.AddRule(body.IP, body.Reason)
	db.AddBan(body.IP, body.Reason)
	s.notifier.SendTelegram(fmt.Sprintf("IP banned: %s — %s", body.IP, body.Reason))
	jsonResponse(w, map[string]bool{"ok": true})
}

func (s *Server) handleAPIRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		jsonError(w, "ip required", 400)
		return
	}
	if !security.ValidateIP(body.IP) {
		jsonError(w, "invalid IP format", 400)
		return
	}
	s.ids.RecordPacket(body.IP, nil, "")
	jsonResponse(w, map[string]bool{"ok": true})
}

func (s *Server) handleAPIWhitelist(w http.ResponseWriter, r *http.Request) {
	ips := whitelist.GetAll()
	jsonResponse(w, map[string]interface{}{"whitelist": ips})
}

func (s *Server) handleAPIWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		jsonError(w, "ip required", 400)
		return
	}
	if !security.ValidateIP(body.IP) {
		jsonError(w, "invalid IP format", 400)
		return
	}
	clientIP := security.ClientIP(r)
	auditLog.Record(clientIP, "WHITELIST_ADD", fmt.Sprintf("Added IP: %s", body.IP), true)
	whitelist.Add(body.IP)
	jsonResponse(w, map[string]bool{"ok": true})
}

func (s *Server) handleAPIWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		jsonError(w, "ip required", 400)
		return
	}
	if !security.ValidateIP(body.IP) {
		jsonError(w, "invalid IP format", 400)
		return
	}
	clientIP := security.ClientIP(r)
	auditLog.Record(clientIP, "WHITELIST_REMOVE", fmt.Sprintf("Removed IP: %s", body.IP), true)
	whitelist.Remove(body.IP)
	jsonResponse(w, map[string]bool{"ok": true})
}

func (s *Server) handleAPIHoneypotStatus(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"status": "running",
		"ports":  config.HoneypotPorts,
	})
}

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	stats := db.GetEventStats()
	jsonResponse(w, stats)
}

func (s *Server) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"status":  "healthy",
		"version": "2.0.0",
		"uptime":  time.Since(startTime).String(),
		"services": map[string]string{
			"database":      "ok",
			"ids":           "ok",
			"honeypot":      "ok",
			"firewall":      "ok",
			"waf":           "ok",
			"ip_reputation": "ok",
		},
		"security": map[string]interface{}{
			"waf_enabled":      config.WAFEnabled,
			"ua_block_enabled": config.UABlockEnabled,
			"totp_enabled":     totpManager.IsEnabled(),
			"geoblock_enabled": len(config.GeoBlockCountries) > 0,
			"admin_allowlist":  adminAllowlist.IsEnabled(),
			"session_max_age":  config.SessionMaxAge,
		},
	})
}

func (s *Server) handleAPIEventsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var body struct {
		Days int `json:"days"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	clientIP := security.ClientIP(r)
	var deleted int64
	if body.Days > 0 {
		deleted = db.DeleteOldEvents(body.Days)
		auditLog.Record(clientIP, "EVENTS_CLEAR", fmt.Sprintf("Cleared events older than %d days", body.Days), true)
	} else {
		deleted = db.DeleteAllEvents()
		auditLog.Record(clientIP, "EVENTS_CLEAR_ALL", "Cleared ALL events", true)
	}
	jsonResponse(w, map[string]interface{}{"ok": true, "deleted": deleted})
}

func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	entries := auditLog.GetEntries(limit)
	jsonResponse(w, map[string]interface{}{
		"audit": entries,
		"stats": auditLog.GetStats(),
	})
}

// ==================== Security API Endpoints ====================

func (s *Server) handleAPISecurityScore(w http.ResponseWriter, r *http.Request) {
	report := security.CalculateSecurityScore(
		config.AdminPassword,
		totpManager.IsEnabled(),
		config.WAFEnabled,
		len(config.GeoBlockCountries) > 0,
		adminAllowlist.IsEnabled(),
	)
	jsonResponse(w, report)
}

func (s *Server) handleAPIWAFStats(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, waf.GetStats())
}

func (s *Server) handleAPIWAFEvents(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	jsonResponse(w, map[string]interface{}{"events": waf.GetEvents(limit)})
}

func (s *Server) handleAPIReputation(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"top_threats": ipReputation.GetTopThreats(20),
	})
}

func (s *Server) handleAPIReputationLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimPrefix(r.URL.Path, "/api/security/reputation/lookup/")
	if ip == "" || !security.ValidateIP(ip) {
		jsonError(w, "valid IP required", 400)
		return
	}
	jsonResponse(w, ipReputation.GetReport(ip))
}

func (s *Server) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	sessions := sessionMgr.GetActiveSessions()
	jsonResponse(w, map[string]interface{}{
		"sessions":    sessions,
		"max_allowed": config.MaxAdminSessions,
	})
}

func (s *Server) handleAPIGeoBlock(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"blocked_countries": geoBlocker.GetBlocked(),
	})
}

func (s *Server) handleAPIGeoBlockAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var body struct {
		Country string `json:"country"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Country == "" {
		jsonError(w, "country code required", 400)
		return
	}
	code := strings.ToUpper(strings.TrimSpace(body.Country))
	if len(code) != 2 {
		jsonError(w, "invalid country code (use 2-letter ISO code)", 400)
		return
	}
	clientIP := security.ClientIP(r)
	geoBlocker.AddCountry(code)
	auditLog.Record(clientIP, "GEOBLOCK_ADD", fmt.Sprintf("Blocked country: %s", code), true)
	jsonResponse(w, map[string]interface{}{"ok": true, "blocked": geoBlocker.GetBlocked()})
}

func (s *Server) handleAPIGeoBlockRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var body struct {
		Country string `json:"country"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Country == "" {
		jsonError(w, "country code required", 400)
		return
	}
	code := strings.ToUpper(strings.TrimSpace(body.Country))
	clientIP := security.ClientIP(r)
	geoBlocker.RemoveCountry(code)
	auditLog.Record(clientIP, "GEOBLOCK_REMOVE", fmt.Sprintf("Unblocked country: %s", code), true)
	jsonResponse(w, map[string]interface{}{"ok": true, "blocked": geoBlocker.GetBlocked()})
}

func (s *Server) handleAPI2FASetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	secret := totpManager.GenerateSecret()
	if secret == "" {
		jsonError(w, "failed to generate TOTP secret", 500)
		return
	}
	uri := totpManager.ProvisioningURI("memOShield", "admin")
	clientIP := security.ClientIP(r)
	auditLog.Record(clientIP, "2FA_SETUP", "TOTP 2FA setup initiated", true)
	jsonResponse(w, map[string]interface{}{
		"secret":           secret,
		"provisioning_uri": uri,
		"message":          "Bu secreti Google Authenticator veya benzeri bir uygulamaya ekleyin. Dogrulama icin /api/security/2fa/verify endpoint'ini kullanin.",
	})
}

func (s *Server) handleAPI2FAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		jsonError(w, "code required", 400)
		return
	}
	clientIP := security.ClientIP(r)
	if totpManager.Validate(body.Code) {
		auditLog.Record(clientIP, "2FA_VERIFY", "TOTP code verified successfully", true)
		jsonResponse(w, map[string]interface{}{"ok": true, "message": "2FA dogrulamasi basarili"})
	} else {
		auditLog.Record(clientIP, "2FA_VERIFY_FAIL", "Invalid TOTP code", false)
		jsonError(w, "invalid TOTP code", 400)
	}
}

func (s *Server) handleAPI2FADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", 405)
		return
	}
	clientIP := security.ClientIP(r)
	totpManager.Disable()
	auditLog.Record(clientIP, "2FA_DISABLE", "TOTP 2FA disabled", true)
	jsonResponse(w, map[string]interface{}{"ok": true, "message": "2FA devre disi birakildi"})
}

func (s *Server) handleAPI2FAStatus(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"enabled": totpManager.IsEnabled(),
	})
}

// ==================== SSE Stream ====================

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", 500)
		return
	}

	// Rate limit SSE connections
	ip := security.ClientIP(r)
	if !streamLimiter.Allow(ip) {
		http.Error(w, "too many stream connections", 429)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := broadcaster.Global.Register()
	defer broadcaster.Global.Unregister(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
