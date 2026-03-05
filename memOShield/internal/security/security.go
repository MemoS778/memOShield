package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ╔══════════════════════════════════════════════════════════════════╗
// ║                       1. RATE LIMITER                          ║
// ╚══════════════════════════════════════════════════════════════════╝

// RateLimiter tracks request counts per IP within sliding windows.
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	go func() {
		for {
			time.Sleep(60 * time.Second)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	entries := rl.requests[ip]
	var valid []time.Time
	for _, t := range entries {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}
	valid = append(valid, now)
	rl.requests[ip] = valid
	return true
}

func (rl *RateLimiter) Remaining(ip string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.window)
	count := 0
	for _, t := range rl.requests[ip] {
		if t.After(cutoff) {
			count++
		}
	}
	rem := rl.limit - count
	if rem < 0 {
		return 0
	}
	return rem
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.window)
	for ip, entries := range rl.requests {
		var valid []time.Time
		for _, t := range entries {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                2. LOGIN BRUTE FORCE PROTECTION                 ║
// ╚══════════════════════════════════════════════════════════════════╝

type LoginProtector struct {
	mu          sync.Mutex
	failures    map[string][]time.Time
	lockouts    map[string]time.Time
	maxAttempts int
	window      time.Duration
	lockoutTime time.Duration
}

func NewLoginProtector(maxAttempts int, window, lockoutTime time.Duration) *LoginProtector {
	return &LoginProtector{
		failures:    make(map[string][]time.Time),
		lockouts:    make(map[string]time.Time),
		maxAttempts: maxAttempts,
		window:      window,
		lockoutTime: lockoutTime,
	}
}

func (lp *LoginProtector) IsLocked(ip string) (bool, time.Duration) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if lockUntil, ok := lp.lockouts[ip]; ok {
		remaining := time.Until(lockUntil)
		if remaining > 0 {
			return true, remaining
		}
		delete(lp.lockouts, ip)
	}
	return false, 0
}

func (lp *LoginProtector) RecordFailure(ip string) bool {
	lp.mu.Lock()
	defer lp.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-lp.window)
	entries := lp.failures[ip]
	var valid []time.Time
	for _, t := range entries {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	lp.failures[ip] = valid

	if len(valid) >= lp.maxAttempts {
		lp.lockouts[ip] = now.Add(lp.lockoutTime)
		delete(lp.failures, ip)
		log.Printf("SECURITY: IP %s locked out after %d failed login attempts", ip, len(valid))
		return true
	}
	return false
}

func (lp *LoginProtector) RecordSuccess(ip string) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	delete(lp.failures, ip)
	delete(lp.lockouts, ip)
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                     3. CSRF PROTECTION                         ║
// ╚══════════════════════════════════════════════════════════════════╝

type CSRFManager struct {
	mu     sync.RWMutex
	tokens map[string]time.Time
	ttl    time.Duration
}

func NewCSRFManager(ttl time.Duration) *CSRFManager {
	m := &CSRFManager{
		tokens: make(map[string]time.Time),
		ttl:    ttl,
	}
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			m.cleanup()
		}
	}()
	return m
}

func (m *CSRFManager) Generate() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Printf("CSRF token generation error: %v", err)
		return ""
	}
	token := hex.EncodeToString(b)
	m.mu.Lock()
	m.tokens[token] = time.Now().Add(m.ttl)
	m.mu.Unlock()
	return token
}

func (m *CSRFManager) Validate(token string) bool {
	if token == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	expiry, ok := m.tokens[token]
	if !ok {
		return false
	}
	delete(m.tokens, token)
	return time.Now().Before(expiry)
}

func (m *CSRFManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for token, expiry := range m.tokens {
		if now.After(expiry) {
			delete(m.tokens, token)
		}
	}
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                    4. IP VALIDATION                            ║
// ╚══════════════════════════════════════════════════════════════════╝

func ValidateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func SanitizeIP(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		raw = host
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// IsPrivateIP checks if an IP is in a private/reserved range.
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, r := range privateRanges {
		_, cidr, _ := net.ParseCIDR(r)
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║              5. WEB APPLICATION FIREWALL (WAF)                 ║
// ╚══════════════════════════════════════════════════════════════════╝

// WAFRule represents a single WAF detection pattern.
type WAFRule struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string // critical, high, medium, low
	Action   string // block, log
}

// WAF is a web application firewall that inspects requests.
type WAF struct {
	mu      sync.RWMutex
	rules   []WAFRule
	enabled bool
	log     []WAFEvent
	maxLog  int
}

// WAFEvent records a WAF detection.
type WAFEvent struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Rule      string    `json:"rule"`
	Severity  string    `json:"severity"`
	Path      string    `json:"path"`
	Payload   string    `json:"payload"`
	Blocked   bool      `json:"blocked"`
}

// NewWAF creates a WAF with default rules.
func NewWAF() *WAF {
	w := &WAF{
		enabled: true,
		maxLog:  2000,
		log:     make([]WAFEvent, 0, 2000),
	}
	w.loadDefaultRules()
	return w
}

func (w *WAF) loadDefaultRules() {
	w.rules = []WAFRule{
		// SQL Injection patterns
		{Name: "SQLi-Union", Pattern: regexp.MustCompile(`(?i)(union\s+(all\s+)?select|select\s+.*from\s+|insert\s+into|update\s+.*set|delete\s+from)`), Severity: "critical", Action: "block"},
		{Name: "SQLi-Comment", Pattern: regexp.MustCompile(`(?i)('|")\s*(or|and)\s+[\d'"].*[=<>]|--\s*$|/\*.*\*/`), Severity: "critical", Action: "block"},
		{Name: "SQLi-Tautology", Pattern: regexp.MustCompile(`(?i)'\s*or\s+['"]?\d+['"]?\s*=\s*['"]?\d+|'\s*or\s+'[^']*'\s*=\s*'`), Severity: "critical", Action: "block"},
		{Name: "SQLi-Stacked", Pattern: regexp.MustCompile(`(?i);\s*(drop|alter|create|truncate|exec|execute)\s+`), Severity: "critical", Action: "block"},
		{Name: "SQLi-Functions", Pattern: regexp.MustCompile(`(?i)(benchmark|sleep|waitfor|delay|load_file|into\s+outfile|into\s+dumpfile|group_concat|concat_ws)\s*\(`), Severity: "high", Action: "block"},
		{Name: "SQLi-Information", Pattern: regexp.MustCompile(`(?i)(information_schema|sys\.objects|sysobjects|syscolumns|msysACEs|sqlite_master|pg_catalog)`), Severity: "critical", Action: "block"},

		// XSS patterns
		{Name: "XSS-Script", Pattern: regexp.MustCompile(`(?i)<\s*script[^>]*>|<\s*/\s*script\s*>`), Severity: "high", Action: "block"},
		{Name: "XSS-Event", Pattern: regexp.MustCompile(`(?i)\bon\w+\s*=\s*["'][^"']*["']`), Severity: "high", Action: "block"},
		{Name: "XSS-JSProtocol", Pattern: regexp.MustCompile(`(?i)javascript\s*:|vbscript\s*:|data\s*:text/html`), Severity: "high", Action: "block"},
		{Name: "XSS-Img", Pattern: regexp.MustCompile(`(?i)<\s*img[^>]+onerror\s*=|<\s*svg[^>]+onload\s*=`), Severity: "high", Action: "block"},
		{Name: "XSS-Iframe", Pattern: regexp.MustCompile(`(?i)<\s*iframe[^>]*>|<\s*object[^>]*>|<\s*embed[^>]*>`), Severity: "medium", Action: "block"},

		// Path Traversal
		{Name: "PathTraversal", Pattern: regexp.MustCompile(`(?i)(\.\.[\\/]){2,}|\.\.[\\/](etc|windows|boot|proc|sys)[\\/]`), Severity: "critical", Action: "block"},
		{Name: "PathTraversal-Encoded", Pattern: regexp.MustCompile(`(?i)(%2e%2e[\\/]|%252e%252e[\\/]|\.\.%2f|%2e%2e%5c)`), Severity: "critical", Action: "block"},
		{Name: "SensitiveFiles", Pattern: regexp.MustCompile(`(?i)(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts|web\.config|\.htaccess|\.env|\.git\/|\.svn\/)`), Severity: "critical", Action: "block"},

		// Command Injection
		{Name: "CmdInject-Pipe", Pattern: regexp.MustCompile(`[|;` + "`" + `]\s*(cat|ls|dir|whoami|id|uname|wget|curl|nc|ncat|bash|sh|cmd|powershell)\b`), Severity: "critical", Action: "block"},
		{Name: "CmdInject-Sub", Pattern: regexp.MustCompile(`\$\([^)]+\)`), Severity: "high", Action: "block"},
		{Name: "CmdInject-Chain", Pattern: regexp.MustCompile(`(?i)&&\s*(cat|ls|whoami|id|net\s+user|ping|tracert)`), Severity: "high", Action: "block"},

		// LFI / RFI
		{Name: "LFI-Include", Pattern: regexp.MustCompile(`(?i)(include|require|include_once|require_once)\s*\(?['"]?(https?://|ftp://|php://|file://)`), Severity: "critical", Action: "block"},
		{Name: "RFI-URL", Pattern: regexp.MustCompile(`(?i)\?(page|file|path|dir|folder|inc|include|template)=https?://`), Severity: "critical", Action: "block"},
		{Name: "PHP-Wrapper", Pattern: regexp.MustCompile(`(?i)php://(filter|input|data|expect)|data://text/plain`), Severity: "critical", Action: "block"},

		// LDAP Injection
		{Name: "LDAP-Inject", Pattern: regexp.MustCompile(`(?i)[\(\)][&|!]\s*[\(\)].*=\*|=\*\)\(|\)\(\|`), Severity: "high", Action: "block"},

		// XML/XXE
		{Name: "XXE-Entity", Pattern: regexp.MustCompile(`(?i)<!ENTITY\s|<!DOCTYPE\s[^>]*\[|SYSTEM\s+["']file://`), Severity: "critical", Action: "block"},

		// Server-Side Template Injection (log only — can conflict with Go templates)
		{Name: "SSTI", Pattern: regexp.MustCompile(`\$\{[^}]{2,}\}`), Severity: "high", Action: "log"},

		// Log4Shell / JNDI
		{Name: "Log4Shell", Pattern: regexp.MustCompile(`(?i)\$\{jndi:(ldap|rmi|dns|iiop)://`), Severity: "critical", Action: "block"},

		// Scanner/Attack Tool Paths
		{Name: "ScannerPath-WP", Pattern: regexp.MustCompile(`(?i)(wp-admin|wp-login|xmlrpc\.php|wp-content/plugins|wp-includes)`), Severity: "medium", Action: "log"},
		{Name: "ScannerPath-PHP", Pattern: regexp.MustCompile(`(?i)(phpmyadmin|adminer|phpinfo|shell\.php|c99\.php|r57\.php|webshell)`), Severity: "high", Action: "block"},
		{Name: "ScannerPath-Admin", Pattern: regexp.MustCompile(`(?i)(/admin\.php|/manager/html|/solr/|/actuator|/console|/_debug)`), Severity: "medium", Action: "log"},
		{Name: "ScannerPath-Backup", Pattern: regexp.MustCompile(`(?i)\.(bak|backup|old|orig|save|swp|sql|tar\.gz|zip|rar)\s*$`), Severity: "medium", Action: "block"},

		// Null Byte Injection
		{Name: "NullByte", Pattern: regexp.MustCompile(`%00|\\x00`), Severity: "high", Action: "block"},

		// HTTP Response Splitting / Header Injection
		{Name: "HeaderInject", Pattern: regexp.MustCompile(`(?i)(%0d%0a|%0a|%0d)\s*(set-cookie|location|content-type)`), Severity: "critical", Action: "block"},
	}
}

// Check inspects a request. Returns blocked=true if it should be blocked.
func (w *WAF) Check(r *http.Request) (blocked bool, event *WAFEvent) {
	if !w.enabled {
		return false, nil
	}

	ip := ClientIP(r)

	// Build payload from URL, query, headers
	payload := r.URL.RequestURI()
	if r.URL.RawQuery != "" {
		payload += "?" + r.URL.RawQuery
	}

	// Inspect form values if content type allows
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "application/x-www-form-urlencoded") {
			if err := r.ParseForm(); err == nil {
				for k, vs := range r.PostForm {
					for _, v := range vs {
						payload += " " + k + "=" + v
					}
				}
			}
		}
	}

	// Check headers attackers often abuse
	payload += " " + r.Header.Get("Referer")
	payload += " " + r.Header.Get("User-Agent")

	w.mu.RLock()
	rules := w.rules
	w.mu.RUnlock()

	for _, rule := range rules {
		if rule.Pattern.MatchString(payload) {
			evt := &WAFEvent{
				Timestamp: time.Now(),
				IP:        ip,
				Rule:      rule.Name,
				Severity:  rule.Severity,
				Path:      r.URL.Path,
				Payload:   truncateStr(payload, 500),
				Blocked:   rule.Action == "block",
			}

			w.mu.Lock()
			w.log = append(w.log, *evt)
			if len(w.log) > w.maxLog {
				w.log = w.log[len(w.log)-w.maxLog:]
			}
			w.mu.Unlock()

			if rule.Action == "block" {
				log.Printf("WAF BLOCK [%s] %s from %s: %s", rule.Severity, rule.Name, ip, r.URL.Path)
				return true, evt
			}
			log.Printf("WAF LOG [%s] %s from %s: %s", rule.Severity, rule.Name, ip, r.URL.Path)
		}
	}
	return false, nil
}

// GetEvents returns recent WAF events.
func (w *WAF) GetEvents(limit int) []WAFEvent {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if limit <= 0 || limit > len(w.log) {
		limit = len(w.log)
	}
	start := len(w.log) - limit
	out := make([]WAFEvent, limit)
	copy(out, w.log[start:])
	return out
}

// GetStats returns WAF statistics.
func (w *WAF) GetStats() map[string]interface{} {
	w.mu.RLock()
	defer w.mu.RUnlock()
	total := len(w.log)
	blocked := 0
	byRule := make(map[string]int)
	bySeverity := make(map[string]int)
	for _, e := range w.log {
		if e.Blocked {
			blocked++
		}
		byRule[e.Rule]++
		bySeverity[e.Severity]++
	}
	return map[string]interface{}{
		"total_detections": total,
		"total_blocked":    blocked,
		"by_rule":          byRule,
		"by_severity":      bySeverity,
		"rules_loaded":     len(w.rules),
		"enabled":          w.enabled,
	}
}

// Middleware returns an HTTP middleware that applies WAF checks.
func (w *WAF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(wr, r)
			return
		}
		blocked, evt := w.Check(r)
		if blocked {
			wr.Header().Set("Content-Type", "application/json")
			wr.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(wr, `{"error":"request blocked by WAF","rule":"%s","severity":"%s"}`, evt.Rule, evt.Severity)
			return
		}
		next.ServeHTTP(wr, r)
	})
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║               6. IP REPUTATION SYSTEM                          ║
// ╚══════════════════════════════════════════════════════════════════╝

// IPReputation tracks reputation scores for IPs.
type IPReputation struct {
	mu      sync.Mutex
	scores  map[string]*reputationEntry
	autoban bool
}

type reputationEntry struct {
	Score      int
	Events     int
	FirstSeen  time.Time
	LastSeen   time.Time
	Categories map[string]int
	AutoBanned bool
}

func NewIPReputation(autoban bool) *IPReputation {
	ipr := &IPReputation{
		scores:  make(map[string]*reputationEntry),
		autoban: autoban,
	}
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			ipr.cleanup()
		}
	}()
	return ipr
}

// RecordEvent records a negative event for an IP.
// Returns the new score and whether it triggered an auto-ban.
func (ipr *IPReputation) RecordEvent(ip, category string, points int) (int, bool) {
	ipr.mu.Lock()
	defer ipr.mu.Unlock()

	entry, ok := ipr.scores[ip]
	if !ok {
		entry = &reputationEntry{
			FirstSeen:  time.Now(),
			Categories: make(map[string]int),
		}
		ipr.scores[ip] = entry
	}

	entry.Score += points
	entry.Events++
	entry.LastSeen = time.Now()
	entry.Categories[category]++
	if entry.Score > 200 {
		entry.Score = 200
	}

	shouldBan := ipr.autoban && entry.Score >= 100 && !entry.AutoBanned
	if shouldBan {
		entry.AutoBanned = true
		log.Printf("IP_REPUTATION: Auto-ban triggered for %s (score=%d, events=%d)", ip, entry.Score, entry.Events)
	}
	return entry.Score, shouldBan
}

func (ipr *IPReputation) GetScore(ip string) int {
	ipr.mu.Lock()
	defer ipr.mu.Unlock()
	if e, ok := ipr.scores[ip]; ok {
		return e.Score
	}
	return 0
}

func (ipr *IPReputation) GetReport(ip string) map[string]interface{} {
	ipr.mu.Lock()
	defer ipr.mu.Unlock()
	if e, ok := ipr.scores[ip]; ok {
		return map[string]interface{}{
			"ip":          ip,
			"score":       e.Score,
			"events":      e.Events,
			"first_seen":  e.FirstSeen,
			"last_seen":   e.LastSeen,
			"categories":  e.Categories,
			"auto_banned": e.AutoBanned,
			"risk_level":  riskLevel(e.Score),
		}
	}
	return map[string]interface{}{"ip": ip, "score": 0, "risk_level": "clean"}
}

func (ipr *IPReputation) GetTopThreats(limit int) []map[string]interface{} {
	ipr.mu.Lock()
	defer ipr.mu.Unlock()

	type ipScore struct {
		ip    string
		score int
	}
	all := make([]ipScore, 0, len(ipr.scores))
	for ip, e := range ipr.scores {
		all = append(all, ipScore{ip, e.Score})
	}
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].score > all[j-1].score; j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	if limit > len(all) {
		limit = len(all)
	}
	result := make([]map[string]interface{}, limit)
	for i := 0; i < limit; i++ {
		e := ipr.scores[all[i].ip]
		result[i] = map[string]interface{}{
			"ip":         all[i].ip,
			"score":      e.Score,
			"events":     e.Events,
			"risk_level": riskLevel(e.Score),
			"categories": e.Categories,
		}
	}
	return result
}

func riskLevel(score int) string {
	switch {
	case score >= 100:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 15:
		return "low"
	default:
		return "clean"
	}
}

func (ipr *IPReputation) cleanup() {
	ipr.mu.Lock()
	defer ipr.mu.Unlock()
	cutoff := time.Now().Add(-24 * time.Hour)
	for ip, e := range ipr.scores {
		if e.LastSeen.Before(cutoff) && e.Score < 50 {
			delete(ipr.scores, ip)
		}
	}
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║            7. USER-AGENT ANALYSIS & BOT DETECTION              ║
// ╚══════════════════════════════════════════════════════════════════╝

type UAAnalyzer struct {
	blockedPatterns []*regexp.Regexp
	suspiciousPats  []*regexp.Regexp
}

func NewUAAnalyzer() *UAAnalyzer {
	ua := &UAAnalyzer{}

	blocked := []string{
		`^$`,
		`(?i)sqlmap`, `(?i)nikto`, `(?i)nmap`, `(?i)masscan`,
		`(?i)zgrab`, `(?i)gobuster`, `(?i)dirbuster`, `(?i)wpscan`,
		`(?i)hydra`, `(?i)metasploit`, `(?i)burpsuite|burp`,
		`(?i)nessus`, `(?i)openvas`, `(?i)acunetix`, `(?i)w3af`,
		`(?i)havij`, `(?i)commix`,
		`(?i)^python-requests`, `(?i)^python-urllib`,
		`(?i)^go-http-client`, `(?i)^ruby`, `(?i)^java/`,
		`(?i)^perl`, `(?i)^libwww-perl`,
		`(?i)^wget`, `(?i)^curl/`,
		`(?i)^okhttp`, `(?i)^aiohttp`, `(?i)^scrapy`,
		`(?i)^httpclient`,
	}

	suspicious := []string{
		`(?i)bot|crawler|spider`,
		`(?i)phantomjs|headless`,
		`(?i)selenium|webdriver`,
		`(?i)puppeteer`,
	}

	for _, p := range blocked {
		ua.blockedPatterns = append(ua.blockedPatterns, regexp.MustCompile(p))
	}
	for _, p := range suspicious {
		ua.suspiciousPats = append(ua.suspiciousPats, regexp.MustCompile(p))
	}
	return ua
}

// Analyze returns "block", "suspicious", or "ok".
func (ua *UAAnalyzer) Analyze(userAgent string) string {
	for _, p := range ua.blockedPatterns {
		if p.MatchString(userAgent) {
			return "block"
		}
	}
	for _, p := range ua.suspiciousPats {
		if p.MatchString(userAgent) {
			return "suspicious"
		}
	}
	return "ok"
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║              8. SESSION FINGERPRINTING                         ║
// ╚══════════════════════════════════════════════════════════════════╝

// SessionFingerprint creates a fingerprint from request headers.
func SessionFingerprint(r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	accept := r.Header.Get("Accept-Language")
	h := sha256.New()
	h.Write([]byte(ua + "|" + accept))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║            9. CONCURRENT SESSION MANAGER                       ║
// ╚══════════════════════════════════════════════════════════════════╝

type SessionManager struct {
	mu         sync.Mutex
	sessions   map[string]*SessionInfo
	maxPerUser int
}

type SessionInfo struct {
	ID          string    `json:"id"`
	IP          string    `json:"ip"`
	UserAgent   string    `json:"user_agent"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	LastActive  time.Time `json:"last_active"`
}

func NewSessionManager(maxPerUser int) *SessionManager {
	sm := &SessionManager{
		sessions:   make(map[string]*SessionInfo),
		maxPerUser: maxPerUser,
	}
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sm.cleanup()
		}
	}()
	return sm
}

func (sm *SessionManager) CreateSession(ip, userAgent string) string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	b := make([]byte, 32)
	rand.Read(b)
	sessionID := hex.EncodeToString(b)

	h := sha256.New()
	h.Write([]byte(userAgent))
	fp := hex.EncodeToString(h.Sum(nil))[:16]

	sm.sessions[sessionID] = &SessionInfo{
		ID:          sessionID,
		IP:          ip,
		UserAgent:   truncateStr(userAgent, 200),
		Fingerprint: fp,
		CreatedAt:   time.Now(),
		LastActive:  time.Now(),
	}

	// Enforce max sessions — remove oldest
	if len(sm.sessions) > sm.maxPerUser {
		var oldestID string
		var oldestTime time.Time
		first := true
		for id, s := range sm.sessions {
			if first || s.CreatedAt.Before(oldestTime) {
				oldestID = id
				oldestTime = s.CreatedAt
				first = false
			}
		}
		if oldestID != "" && oldestID != sessionID {
			delete(sm.sessions, oldestID)
			log.Printf("SESSION: Evicted oldest session %s...", oldestID[:8])
		}
	}

	return sessionID
}

func (sm *SessionManager) ValidateSession(sessionID, userAgent string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	info, ok := sm.sessions[sessionID]
	if !ok {
		return false
	}

	h := sha256.New()
	h.Write([]byte(userAgent))
	fp := hex.EncodeToString(h.Sum(nil))[:16]

	if info.Fingerprint != fp {
		log.Printf("SESSION: Fingerprint mismatch for session %s... (possible hijack)", sessionID[:8])
		delete(sm.sessions, sessionID)
		return false
	}

	info.LastActive = time.Now()
	return true
}

func (sm *SessionManager) DestroySession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, sessionID)
}

func (sm *SessionManager) GetActiveSessions() []SessionInfo {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	out := make([]SessionInfo, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		out = append(out, *s)
	}
	return out
}

func (sm *SessionManager) cleanup() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	cutoff := time.Now().Add(-2 * time.Hour)
	for id, s := range sm.sessions {
		if s.LastActive.Before(cutoff) {
			delete(sm.sessions, id)
		}
	}
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                10. GEO-BLOCKING                                ║
// ╚══════════════════════════════════════════════════════════════════╝

type GeoBlocker struct {
	mu               sync.RWMutex
	blockedCountries map[string]bool
	enabled          bool
}

func NewGeoBlocker(countries []string) *GeoBlocker {
	gb := &GeoBlocker{
		blockedCountries: make(map[string]bool),
		enabled:          len(countries) > 0,
	}
	for _, c := range countries {
		gb.blockedCountries[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	return gb
}

func (gb *GeoBlocker) IsBlocked(countryCode string) bool {
	if !gb.enabled {
		return false
	}
	gb.mu.RLock()
	defer gb.mu.RUnlock()
	return gb.blockedCountries[strings.ToUpper(countryCode)]
}

func (gb *GeoBlocker) AddCountry(code string) {
	gb.mu.Lock()
	defer gb.mu.Unlock()
	gb.blockedCountries[strings.ToUpper(strings.TrimSpace(code))] = true
	gb.enabled = true
}

func (gb *GeoBlocker) RemoveCountry(code string) {
	gb.mu.Lock()
	defer gb.mu.Unlock()
	delete(gb.blockedCountries, strings.ToUpper(strings.TrimSpace(code)))
}

func (gb *GeoBlocker) GetBlocked() []string {
	gb.mu.RLock()
	defer gb.mu.RUnlock()
	out := make([]string, 0, len(gb.blockedCountries))
	for c := range gb.blockedCountries {
		out = append(out, c)
	}
	return out
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║              11. ADMIN IP ALLOWLIST                             ║
// ╚══════════════════════════════════════════════════════════════════╝

type AdminAllowlist struct {
	mu      sync.RWMutex
	ips     map[string]bool
	enabled bool
}

func NewAdminAllowlist(ips []string) *AdminAllowlist {
	al := &AdminAllowlist{
		ips:     make(map[string]bool),
		enabled: len(ips) > 0,
	}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			al.ips[ip] = true
		}
	}
	return al
}

func (al *AdminAllowlist) IsAllowed(ip string) bool {
	if !al.enabled {
		return true
	}
	al.mu.RLock()
	defer al.mu.RUnlock()
	if ip == "127.0.0.1" || ip == "::1" {
		return true
	}
	return al.ips[ip]
}

func (al *AdminAllowlist) IsEnabled() bool {
	return al.enabled
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                12. TOTP TWO-FACTOR AUTH                        ║
// ╚══════════════════════════════════════════════════════════════════╝

type TOTPManager struct {
	mu      sync.RWMutex
	secret  string
	enabled bool
	digits  int
	period  int
}

func NewTOTPManager() *TOTPManager {
	return &TOTPManager{
		digits: 6,
		period: 30,
	}
}

func (t *TOTPManager) GenerateSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		log.Printf("TOTP secret generation error: %v", err)
		return ""
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	t.mu.Lock()
	t.secret = secret
	t.enabled = true
	t.mu.Unlock()
	log.Println("TOTP: New secret generated, 2FA enabled")
	return secret
}

func (t *TOTPManager) SetSecret(secret string) {
	if secret == "" {
		return
	}
	t.mu.Lock()
	t.secret = secret
	t.enabled = true
	t.mu.Unlock()
}

func (t *TOTPManager) IsEnabled() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.enabled
}

func (t *TOTPManager) GetSecret() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.secret
}

// Validate checks a TOTP code (allows ±1 time window for clock skew).
func (t *TOTPManager) Validate(code string) bool {
	t.mu.RLock()
	secret := t.secret
	enabled := t.enabled
	t.mu.RUnlock()

	if !enabled || secret == "" {
		return true // If 2FA not enabled, always pass
	}

	if len(code) != t.digits {
		return false
	}

	now := time.Now().Unix()
	for _, offset := range []int64{-1, 0, 1} {
		counter := (now / int64(t.period)) + offset
		expected := generateTOTP(secret, counter, t.digits)
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func (t *TOTPManager) ProvisioningURI(issuer, account string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=%d&period=%d",
		issuer, account, t.secret, issuer, t.digits, t.period)
}

func (t *TOTPManager) Disable() {
	t.mu.Lock()
	t.enabled = false
	t.secret = ""
	t.mu.Unlock()
	log.Println("TOTP: 2FA disabled")
}

func generateTOTP(secret string, counter int64, digits int) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := int64(binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff)
	mod := int64(math.Pow10(digits))
	otp := code % mod
	return fmt.Sprintf("%0*d", digits, otp)
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                 13. ENTROPY DETECTOR                           ║
// ╚══════════════════════════════════════════════════════════════════╝

func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	length := float64(utf8.RuneCountInString(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func IsHighEntropy(s string, threshold float64) bool {
	return CalculateEntropy(s) > threshold
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                 14. SECURITY HEADERS                           ║
// ╚══════════════════════════════════════════════════════════════════╝

func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=(), vr=(), accelerometer=(), gyroscope=()")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("X-Download-Options", "noopen")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "+
				"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "+
				"img-src 'self' data: https://*.basemaps.cartocdn.com https://*.tile.openstreetmap.org; "+
				"connect-src 'self'; "+
				"font-src 'self' https://cdn.jsdelivr.net; "+
				"frame-ancestors 'none'; "+
				"form-action 'self'; "+
				"base-uri 'self'; "+
				"object-src 'none'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/dashboard" || r.URL.Path == "/login" {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		w.Header().Del("Server")
		w.Header().Del("X-Powered-By")

		next.ServeHTTP(w, r)
	})
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                 15. BODY LIMITER                               ║
// ╚══════════════════════════════════════════════════════════════════╝

func MaxBodySize(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                 16. REQUEST LOGGER                             ║
// ╚══════════════════════════════════════════════════════════════════╝

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start)

		if !strings.HasPrefix(r.URL.Path, "/static/") {
			log.Printf("HTTP %d %s %s %s [%v] UA=%q",
				wrapped.status, r.Method, r.URL.Path, ClientIP(r), duration,
				truncateStr(r.Header.Get("User-Agent"), 80))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(code)
	}
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                 17. PANIC RECOVERY                             ║
// ╚══════════════════════════════════════════════════════════════════╝

func PanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("PANIC RECOVERED: %v [%s %s from %s]", err, r.Method, r.URL.Path, ClientIP(r))
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║              18. REQUEST ID TRACKING                           ║
// ╚══════════════════════════════════════════════════════════════════╝

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 8)
		rand.Read(b)
		requestID := hex.EncodeToString(b)
		w.Header().Set("X-Request-ID", requestID)
		r.Header.Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║          19. CONTENT-TYPE & METHOD ENFORCEMENT                 ║
// ╚══════════════════════════════════════════════════════════════════╝

func ContentTypeCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if ct != "" &&
				!strings.Contains(ct, "application/json") &&
				!strings.Contains(ct, "application/x-www-form-urlencoded") &&
				!strings.Contains(ct, "multipart/form-data") {
				http.Error(w, `{"error":"unsupported content type"}`, http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║              20. HONEYPOT FORM FIELD DETECTION                 ║
// ╚══════════════════════════════════════════════════════════════════╝

const HoneypotFieldName = "website_url_hp"

func IsHoneypotTriggered(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	return r.FormValue(HoneypotFieldName) != ""
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                 21. CLIENT IP                                  ║
// ╚══════════════════════════════════════════════════════════════════╝

func ClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		if parsed, ok := SanitizeIP(ip); ok {
			return parsed
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		if len(parts) > 0 {
			if parsed, ok := SanitizeIP(parts[0]); ok {
				return parsed
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                 22. SECURE COMPARE                             ║
// ╚══════════════════════════════════════════════════════════════════╝

func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║           23. PASSWORD HASHING (SHA512 + Salt + Iterations)    ║
// ╚══════════════════════════════════════════════════════════════════╝

func HashPassword(password string) string {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		log.Printf("Salt generation error: %v", err)
		return ""
	}
	saltHex := hex.EncodeToString(salt)

	// 10000 iterations of SHA512
	hash := []byte(saltHex + password)
	for i := 0; i < 10000; i++ {
		h := sha512.Sum512(hash)
		hash = h[:]
	}
	hashHex := hex.EncodeToString(hash)
	return fmt.Sprintf("sha512:%s:%s", saltHex, hashHex)
}

func VerifyPassword(password, storedHash string) bool {
	if strings.HasPrefix(storedHash, "sha512:") {
		parts := strings.SplitN(storedHash, ":", 3)
		if len(parts) != 3 {
			return false
		}
		hash := []byte(parts[1] + password)
		for i := 0; i < 10000; i++ {
			h := sha512.Sum512(hash)
			hash = h[:]
		}
		expected := hex.EncodeToString(hash)
		return SecureCompare(expected, parts[2])
	}

	// Legacy: salt:hash (SHA256, single iteration)
	parts := strings.SplitN(storedHash, ":", 2)
	if len(parts) == 2 && len(parts[0]) == 32 {
		h := sha256.New()
		h.Write([]byte(parts[0] + password))
		expected := hex.EncodeToString(h.Sum(nil))
		return SecureCompare(expected, parts[1])
	}

	// Fallback: plaintext comparison (env-set passwords)
	return SecureCompare(password, storedHash)
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                 24. AUDIT LOG                                  ║
// ╚══════════════════════════════════════════════════════════════════╝

type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	maxSize int
}

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	Success   bool      `json:"success"`
	RequestID string    `json:"request_id,omitempty"`
	Severity  string    `json:"severity,omitempty"`
}

func NewAuditLog(maxSize int) *AuditLog {
	return &AuditLog{
		entries: make([]AuditEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

func (al *AuditLog) Record(ip, action, details string, success bool) {
	al.mu.Lock()
	defer al.mu.Unlock()

	severity := "info"
	if !success {
		severity = "medium"
	}
	switch action {
	case "LOGIN_FAIL", "CSRF_FAIL", "LOGIN_LOCKED":
		severity = "high"
	case "WAF_BLOCK", "UA_BLOCKED", "GEOBLOCK", "TOTP_FAIL":
		severity = "critical"
	case "BAN", "UNBAN", "EVENTS_CLEAR_ALL":
		severity = "medium"
	}

	entry := AuditEntry{
		Timestamp: time.Now(),
		IP:        ip,
		Action:    action,
		Details:   truncateStr(details, 500),
		Success:   success,
		Severity:  severity,
	}
	al.entries = append(al.entries, entry)
	if len(al.entries) > al.maxSize {
		al.entries = al.entries[len(al.entries)-al.maxSize:]
	}

	status := "SUCCESS"
	if !success {
		status = "FAILED"
	}
	log.Printf("AUDIT [%s][%s] %s from %s: %s", severity, status, action, ip, truncateStr(details, 200))
}

func (al *AuditLog) GetEntries(limit int) []AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()
	if limit <= 0 || limit > len(al.entries) {
		limit = len(al.entries)
	}
	start := len(al.entries) - limit
	out := make([]AuditEntry, limit)
	copy(out, al.entries[start:])
	return out
}

func (al *AuditLog) GetEntriesByAction(action string, limit int) []AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()
	var out []AuditEntry
	for i := len(al.entries) - 1; i >= 0 && len(out) < limit; i-- {
		if al.entries[i].Action == action {
			out = append(out, al.entries[i])
		}
	}
	return out
}

func (al *AuditLog) GetStats() map[string]interface{} {
	al.mu.Lock()
	defer al.mu.Unlock()
	byAction := make(map[string]int)
	bySeverity := make(map[string]int)
	successes, failures := 0, 0
	for _, e := range al.entries {
		byAction[e.Action]++
		bySeverity[e.Severity]++
		if e.Success {
			successes++
		} else {
			failures++
		}
	}
	return map[string]interface{}{
		"total":       len(al.entries),
		"successes":   successes,
		"failures":    failures,
		"by_action":   byAction,
		"by_severity": bySeverity,
	}
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║              25. SECURE COOKIE HELPERS                         ║
// ╚══════════════════════════════════════════════════════════════════╝

func SecureCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	}
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║           26. INPUT SANITIZATION                               ║
// ╚══════════════════════════════════════════════════════════════════╝

var htmlTagRegex = regexp.MustCompile(`<[^>]*>`)

func SanitizeInput(input string, maxLen int) string {
	if maxLen > 0 && len(input) > maxLen {
		input = input[:maxLen]
	}
	input = strings.ReplaceAll(input, "\x00", "")
	input = htmlTagRegex.ReplaceAllString(input, "")
	return strings.TrimSpace(input)
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║           27. SECURITY SCORE CALCULATOR                        ║
// ╚══════════════════════════════════════════════════════════════════╝

type SecurityScoreReport struct {
	Score     int             `json:"score"`
	Grade     string          `json:"grade"`
	Checks    []SecurityCheck `json:"checks"`
	Timestamp time.Time       `json:"timestamp"`
}

type SecurityCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details"`
	Points  int    `json:"points"`
}

func CalculateSecurityScore(adminPassword string, totpEnabled, wafEnabled, geoBlockEnabled, adminAllowlistEnabled bool) SecurityScoreReport {
	var checks []SecurityCheck
	score := 0

	if adminPassword == "admin" || adminPassword == "password" || adminPassword == "123456" || len(adminPassword) < 8 {
		checks = append(checks, SecurityCheck{"Sifre Gucu", "fail", "Admin sifresi zayif veya varsayilan", 0})
	} else if len(adminPassword) >= 12 {
		checks = append(checks, SecurityCheck{"Sifre Gucu", "pass", "Guclu sifre ayarlanmis", 15})
		score += 15
	} else {
		checks = append(checks, SecurityCheck{"Sifre Gucu", "warn", "Sifre daha guclu olabilir (12+ karakter)", 8})
		score += 8
	}

	if totpEnabled {
		checks = append(checks, SecurityCheck{"Iki Faktorlu Dogrulama", "pass", "TOTP 2FA aktif", 20})
		score += 20
	} else {
		checks = append(checks, SecurityCheck{"Iki Faktorlu Dogrulama", "warn", "TOTP 2FA aktif degil", 0})
	}

	if wafEnabled {
		checks = append(checks, SecurityCheck{"WAF", "pass", "Web Application Firewall aktif", 15})
		score += 15
	} else {
		checks = append(checks, SecurityCheck{"WAF", "fail", "WAF deaktif", 0})
	}

	if geoBlockEnabled {
		checks = append(checks, SecurityCheck{"Geo-Engelleme", "pass", "Ulke bazli engelleme aktif", 10})
		score += 10
	} else {
		checks = append(checks, SecurityCheck{"Geo-Engelleme", "warn", "Geo-engelleme yapilandirilmamis", 0})
	}

	if adminAllowlistEnabled {
		checks = append(checks, SecurityCheck{"Admin IP Kisitlamasi", "pass", "Admin erisimi IP ile kisitli", 15})
		score += 15
	} else {
		checks = append(checks, SecurityCheck{"Admin IP Kisitlamasi", "warn", "Admin erisimi herhangi IP'den acik", 0})
	}

	checks = append(checks, SecurityCheck{"Rate Limiting", "pass", "API ve login rate limiting aktif", 10})
	score += 10
	checks = append(checks, SecurityCheck{"Guvenlik Basliklari", "pass", "Tam guvenlik basliklari yapilandirilmis", 10})
	score += 10
	checks = append(checks, SecurityCheck{"CSRF Korumasi", "pass", "CSRF tokenlari aktif", 5})
	score += 5

	grade := "F"
	switch {
	case score >= 95:
		grade = "A+"
	case score >= 85:
		grade = "A"
	case score >= 75:
		grade = "B"
	case score >= 60:
		grade = "C"
	case score >= 40:
		grade = "D"
	}

	return SecurityScoreReport{Score: score, Grade: grade, Checks: checks, Timestamp: time.Now()}
}

// ╔══════════════════════════════════════════════════════════════════╗
// ║                  28. HELPER FUNCTIONS                          ║
// ╚══════════════════════════════════════════════════════════════════╝

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func GenerateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
