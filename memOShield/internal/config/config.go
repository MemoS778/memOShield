package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// ProjectRoot is resolved relative to the binary or working directory.
var ProjectRoot string

func init() {
	// Try working directory first
	wd, err := os.Getwd()
	if err == nil {
		ProjectRoot = wd
	} else {
		ProjectRoot = "."
	}
}

// DBPath returns the SQLite database file path.
func DBPath() string {
	return filepath.Join(ProjectRoot, "memoshield.db")
}

// IDS thresholds
var (
	IDSThreshold          = envInt("IDS_THRESHOLD", 300)
	IDSWindowSeconds      = envInt("IDS_WINDOW_SECONDS", 10)
	IDSBanDurationSeconds = envInt("IDS_BAN_DURATION_SECONDS", 600)
	IDSPortThreshold      = envInt("IDS_PORT_THRESHOLD", 80)
)

// Honeypot ports
var HoneypotPorts = []int{2121, 2323, 3307}

// User-Agent detection rules (IDS will ban matching UAs)
var IDSUserAgentRules = envSlice("IDS_UA_RULES", []string{
	"sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster",
	"dirbuster", "wpscan", "hydra", "metasploit", "burpsuite",
})

// GeoIP
var GeoIPURL = envStr("GEOIP_URL", "https://ipapi.co/%s/json/")

// Admin password
var AdminPassword = envStr("ADMIN_PASSWORD", "admin")

// Flask-like secret for cookie signing
var SecretKey = envStr("FLASK_SECRET", "change-this-secret")

// Server port
var ServerPort = envStr("PORT", "5000")

// Mock stream
var (
	EnableMockStream   = envStr("ENABLE_MOCK_STREAM", "0")
	MockStreamInterval = envInt("MOCK_STREAM_INTERVAL", 3)
	MockStreamMode     = envStr("MOCK_STREAM_MODE", "steady")
)

// Security: WAF
var WAFEnabled = envBool("WAF_ENABLED", false)

// Security: UA blocking
var UABlockEnabled = envBool("UA_BLOCK_ENABLED", false)

// Security: Geo-blocking (comma-separated country codes)
var GeoBlockCountries = envSlice("GEO_BLOCK_COUNTRIES", []string{})

// Security: Admin IP allowlist (comma-separated IPs, empty=disabled)
var AdminAllowedIPs = envSlice("ADMIN_ALLOWED_IPS", []string{})

// Security: TOTP 2FA secret (set to enable, empty=disabled)
var TOTPSecret = envStr("TOTP_SECRET", "")

// Security: Max concurrent admin sessions
var MaxAdminSessions = envInt("MAX_ADMIN_SESSIONS", 10)

// Security: IP reputation auto-ban
var IPReputationAutoBan = envBool("IP_REPUTATION_AUTOBAN", false)

// Security: Session max age (seconds)
var SessionMaxAge = envInt("SESSION_MAX_AGE", 86400)

// Security: Login hardening toggles
var LoginRateLimitEnabled = envBool("LOGIN_RATE_LIMIT_ENABLED", false)
var LoginLockoutEnabled = envBool("LOGIN_LOCKOUT_ENABLED", false)
var LoginCSRFEnabled = envBool("LOGIN_CSRF_ENABLED", false)
var LoginHoneypotEnabled = envBool("LOGIN_HONEYPOT_ENABLED", false)

// Telegram
var (
	TelegramBotToken = envStr("TELEGRAM_BOT_TOKEN", "")
	TelegramChatID   = envStr("TELEGRAM_CHAT_ID", "")
)

// Slack
var SlackWebhook = envStr("SLACK_WEBHOOK", "")

// IsLinux returns true if running on Linux.
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}

func envSlice(key string, fallback []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
