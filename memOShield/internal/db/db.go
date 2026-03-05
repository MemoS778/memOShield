package db

import (
	"database/sql"
	"log"
	"sync"
	"time"

	"github.com/MemoS778/memOShield/internal/broadcaster"
	"github.com/MemoS778/memOShield/internal/config"
	_ "modernc.org/sqlite"
)

var (
	once sync.Once
	db   *sql.DB
	mu   sync.Mutex
)

// DB returns the singleton database connection.
func DB() *sql.DB {
	once.Do(func() {
		var err error
		db, err = sql.Open("sqlite", config.DBPath())
		if err != nil {
			log.Fatalf("Failed to open database: %v", err)
		}
		db.SetMaxOpenConns(1) // SQLite single-writer
	})
	return db
}

// InitDB creates tables if they don't exist.
func InitDB() {
	d := DB()
	mu.Lock()
	defer mu.Unlock()

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT,
			src_ip TEXT,
			country TEXT,
			lat REAL,
			lon REAL,
			attack_type TEXT,
			details TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS bans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT,
			src_ip TEXT,
			reason TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TEXT,
			ip TEXT,
			reason TEXT
		)`,
	}
	for _, s := range stmts {
		if _, err := d.Exec(s); err != nil {
			log.Printf("InitDB exec error: %v", err)
		}
	}

	// ensure lat/lon columns exist on older DBs
	for _, col := range []string{"lat", "lon"} {
		_, _ = d.Exec("ALTER TABLE events ADD COLUMN " + col + " REAL")
	}
}

// Event represents a security event row.
type Event struct {
	ID         int64   `json:"id"`
	Timestamp  string  `json:"timestamp"`
	SrcIP      string  `json:"src_ip"`
	Country    string  `json:"country"`
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	AttackType string  `json:"attack_type"`
	Details    string  `json:"details"`
}

// Ban represents a banned IP row.
type Ban struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	Reason    string `json:"reason"`
}

// Rule represents a firewall rule row.
type Rule struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
}

// LogEvent inserts a new event and publishes it via SSE.
func LogEvent(srcIP, country, attackType, details string, lat, lon float64) {
	ts := time.Now().UTC().Format(time.RFC3339)
	mu.Lock()
	_, err := DB().Exec(
		`INSERT INTO events (timestamp, src_ip, country, lat, lon, attack_type, details) VALUES (?,?,?,?,?,?,?)`,
		ts, srcIP, country, lat, lon, attackType, details,
	)
	mu.Unlock()
	if err != nil {
		log.Printf("LogEvent error: %v", err)
	}

	evt := map[string]interface{}{
		"timestamp":   ts,
		"src_ip":      srcIP,
		"country":     country,
		"lat":         lat,
		"lon":         lon,
		"attack_type": attackType,
		"details":     details,
	}
	broadcaster.Global.Publish(evt)
}

// AddBan inserts a ban record.
func AddBan(srcIP, reason string) {
	ts := time.Now().UTC().Format(time.RFC3339)
	mu.Lock()
	defer mu.Unlock()
	_, _ = DB().Exec(`INSERT INTO bans (timestamp, src_ip, reason) VALUES (?,?,?)`, ts, srcIP, reason)
}

// AddRule inserts a firewall rule record.
func AddRule(ip, reason string) {
	ts := time.Now().UTC().Format(time.RFC3339)
	mu.Lock()
	defer mu.Unlock()
	_, _ = DB().Exec(`INSERT INTO rules (created_at, ip, reason) VALUES (?,?,?)`, ts, ip, reason)
}

// GetEvents returns the latest events.
func GetEvents(limit int) []Event {
	mu.Lock()
	defer mu.Unlock()
	rows, err := DB().Query(`SELECT id, timestamp, src_ip, country, COALESCE(lat,0), COALESCE(lon,0), attack_type, details FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		log.Printf("GetEvents error: %v", err)
		return nil
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SrcIP, &e.Country, &e.Lat, &e.Lon, &e.AttackType, &e.Details); err != nil {
			continue
		}
		events = append(events, e)
	}
	return events
}

// GetBans returns the latest bans.
func GetBans(limit int) []Ban {
	mu.Lock()
	defer mu.Unlock()
	rows, err := DB().Query(`SELECT id, timestamp, src_ip, reason FROM bans ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var bans []Ban
	for rows.Next() {
		var b Ban
		if err := rows.Scan(&b.ID, &b.Timestamp, &b.SrcIP, &b.Reason); err != nil {
			continue
		}
		bans = append(bans, b)
	}
	return bans
}

// GetRules returns all firewall rules.
func GetRules() []Rule {
	mu.Lock()
	defer mu.Unlock()
	rows, err := DB().Query(`SELECT id, created_at, ip, reason FROM rules ORDER BY id DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.CreatedAt, &r.IP, &r.Reason); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	return rules
}

// DeleteRuleByIP removes firewall rules for a specific IP from DB.
func DeleteRuleByIP(ip string) {
	mu.Lock()
	defer mu.Unlock()
	_, _ = DB().Exec(`DELETE FROM rules WHERE ip = ?`, ip)
}

// DeleteBanByIP removes ban records for a specific IP from DB.
func DeleteBanByIP(ip string) {
	mu.Lock()
	defer mu.Unlock()
	_, _ = DB().Exec(`DELETE FROM bans WHERE src_ip = ?`, ip)
}

// EventStats holds aggregated dashboard statistics.
type EventStats struct {
	TotalEvents   int            `json:"total_events"`
	TotalBans     int            `json:"total_bans"`
	Last24h       int            `json:"last_24h"`
	LastHour      int            `json:"last_hour"`
	AttackTypes   map[string]int `json:"attack_types"`
	TopCountries  map[string]int `json:"top_countries"`
	TopIPs        map[string]int `json:"top_ips"`
	EventsPerHour map[string]int `json:"events_per_hour"`
}

// GetEventStats returns aggregated statistics.
func GetEventStats() EventStats {
	stats := EventStats{
		AttackTypes:   make(map[string]int),
		TopCountries:  make(map[string]int),
		TopIPs:        make(map[string]int),
		EventsPerHour: make(map[string]int),
	}

	mu.Lock()
	defer mu.Unlock()

	// Total events
	row := DB().QueryRow(`SELECT COUNT(*) FROM events`)
	_ = row.Scan(&stats.TotalEvents)

	// Total bans
	row = DB().QueryRow(`SELECT COUNT(*) FROM bans`)
	_ = row.Scan(&stats.TotalBans)

	// Last 24h
	row = DB().QueryRow(`SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now', '-1 day')`)
	_ = row.Scan(&stats.Last24h)

	// Last hour
	row = DB().QueryRow(`SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now', '-1 hour')`)
	_ = row.Scan(&stats.LastHour)

	// Attack types
	rows, err := DB().Query(`SELECT attack_type, COUNT(*) as cnt FROM events GROUP BY attack_type ORDER BY cnt DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			var c int
			if rows.Scan(&t, &c) == nil {
				stats.AttackTypes[t] = c
			}
		}
	}

	// Top countries
	rows2, err := DB().Query(`SELECT country, COUNT(*) as cnt FROM events GROUP BY country ORDER BY cnt DESC LIMIT 10`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var t string
			var c int
			if rows2.Scan(&t, &c) == nil {
				stats.TopCountries[t] = c
			}
		}
	}

	// Top IPs
	rows3, err := DB().Query(`SELECT src_ip, COUNT(*) as cnt FROM events GROUP BY src_ip ORDER BY cnt DESC LIMIT 10`)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var t string
			var c int
			if rows3.Scan(&t, &c) == nil {
				stats.TopIPs[t] = c
			}
		}
	}

	// Events per hour (last 24h)
	rows4, err := DB().Query(`SELECT strftime('%H', timestamp) as hr, COUNT(*) as cnt FROM events WHERE timestamp >= datetime('now', '-1 day') GROUP BY hr ORDER BY hr`)
	if err == nil {
		defer rows4.Close()
		for rows4.Next() {
			var t string
			var c int
			if rows4.Scan(&t, &c) == nil {
				stats.EventsPerHour[t] = c
			}
		}
	}

	return stats
}

// DeleteOldEvents removes events older than the given number of days.
func DeleteOldEvents(days int) int64 {
	mu.Lock()
	defer mu.Unlock()
	result, err := DB().Exec(`DELETE FROM events WHERE timestamp < datetime('now', '-' || ? || ' days')`, days)
	if err != nil {
		log.Printf("DeleteOldEvents error: %v", err)
		return 0
	}
	n, _ := result.RowsAffected()
	return n
}

// DeleteAllEvents clears all events.
func DeleteAllEvents() int64 {
	mu.Lock()
	defer mu.Unlock()
	result, err := DB().Exec(`DELETE FROM events`)
	if err != nil {
		log.Printf("DeleteAllEvents error: %v", err)
		return 0
	}
	n, _ := result.RowsAffected()
	return n
}
