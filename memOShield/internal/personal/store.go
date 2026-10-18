package personal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Event struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	SourceIP string    `json:"source_ip"`
	TargetIP string    `json:"target_ip,omitempty"`
	Port     int       `json:"port,omitempty"`
	User     string    `json:"user,omitempty"`
	Evidence string    `json:"evidence"`
	Key      string    `json:"-"`
}

type Ban struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Expires   time.Time `json:"expires"`
	Desired   bool      `json:"desired"`
	State     string    `json:"state"`
	Error     string    `json:"error,omitempty"`
	Confirmed time.Time `json:"confirmed"`
}

type Store struct{ db *sql.DB }

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "personal.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	_, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS personal_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT UNIQUE NOT NULL, time INTEGER NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, source_ip TEXT NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS personal_events_time ON personal_events(time);
CREATE INDEX IF NOT EXISTS personal_events_detection ON personal_events(source_ip, kind, time);
CREATE TABLE IF NOT EXISTS personal_bans (ip TEXT PRIMARY KEY, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS personal_allowlist (prefix TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS personal_checkpoints (source TEXT PRIMARY KEY, value TEXT NOT NULL);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// A previous process's confirmation is historical, not a fresh OS observation.
func (s *Store) InvalidateBans() error {
	bans, err := s.Bans()
	if err != nil {
		return err
	}
	for _, b := range bans {
		if b.State == "applied" || b.State == "pending" {
			b.State = "unconfirmed"
			b.Error = "Uygulama yeniden başladı; firewall durumu henüz doğrulanmadı"
			if err := s.SaveBan(b); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) AddEvent(e *Event) (bool, error) {
	if e.Key == "" {
		return false, fmt.Errorf("event requires deduplication key")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return false, err
	}
	r, err := s.db.Exec(`INSERT INTO personal_events(event_key,time,source,kind,source_ip,payload) VALUES(?,?,?,?,?,?) ON CONFLICT(event_key) DO NOTHING`, e.Key, e.Time.UnixMilli(), e.Source, e.Kind, e.SourceIP, string(b))
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	e.ID, err = r.LastInsertId()
	return true, err
}

// Events returns ascending events for cursor replay, newest-first for snapshots.
func (s *Store) Events(after int64, latest bool) ([]Event, error) {
	query := `SELECT id,payload FROM personal_events WHERE id > ? ORDER BY id ASC LIMIT 200`
	if latest {
		query = `SELECT id,payload FROM personal_events WHERE id > ? ORDER BY id DESC LIMIT 200`
	}
	rows, err := s.db.Query(query, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var id int64
		var raw string
		var e Event
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			return nil, err
		}
		e.ID = id
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) FailureCount(ip string, since, until time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM personal_events WHERE source='journal' AND kind='ssh_failed' AND source_ip=? AND time>=? AND time<=?`, ip, since.UnixMilli(), until.UnixMilli()).Scan(&n)
	return n, err
}

func (s *Store) SaveBan(b Ban) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO personal_bans(ip,payload) VALUES(?,?) ON CONFLICT(ip) DO UPDATE SET payload=excluded.payload`, b.IP, string(raw))
	return err
}

func (s *Store) Bans() ([]Ban, error) {
	rows, err := s.db.Query(`SELECT payload FROM personal_bans ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Ban{}
	for rows.Next() {
		var raw string
		var b Ban
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) Allowlist() ([]string, error) {
	rows, err := s.db.Query(`SELECT prefix FROM personal_allowlist ORDER BY prefix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) SetAllowed(prefix string, add bool) error {
	if add {
		_, err := s.db.Exec(`INSERT OR IGNORE INTO personal_allowlist(prefix) VALUES(?)`, prefix)
		return err
	}
	_, err := s.db.Exec(`DELETE FROM personal_allowlist WHERE prefix=?`, prefix)
	return err
}

func (s *Store) Checkpoint(source string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM personal_checkpoints WHERE source=?`, source).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

func (s *Store) SaveCheckpoint(source, value string) error {
	_, err := s.db.Exec(`INSERT INTO personal_checkpoints(source,value) VALUES(?,?) ON CONFLICT(source) DO UPDATE SET value=excluded.value`, source, value)
	return err
}

func (s *Store) Prune() error {
	_, err := s.db.Exec(`DELETE FROM personal_events WHERE time < ? OR id <= (SELECT COALESCE(MAX(id),0)-100000 FROM personal_events)`, time.Now().Add(-30*24*time.Hour).UnixMilli())
	return err
}
