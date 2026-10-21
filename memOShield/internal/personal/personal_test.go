package personal

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MemoS778/memOShield/internal/firewallctl"
)

type fakeFirewall struct {
	mu      sync.Mutex
	entries []firewallctl.Entry
	calls   int
	err     error
}

func (f *fakeFirewall) Apply(_ context.Context, entries []firewallctl.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.entries = append([]firewallctl.Entry{}, entries...)
	return nil
}
func fixture(t *testing.T, mode string) (*Store, *Engine, *fakeFirewall) {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	f := &fakeFirewall{}
	return s, NewEngine(s, Config{Mode: mode}, f), f
}
func event(key string, ts time.Time) Event {
	return Event{Key: key, Time: ts, Source: "journal", Kind: "ssh_failed", Severity: "medium", SourceIP: "192.0.2.9", Evidence: "test fixture"}
}

func TestBanLifecycleAndFailures(t *testing.T) {
	s, e, f := fixture(t, "manual")
	ctx := context.Background()
	f.err = fmt.Errorf("helper unavailable")
	if err := e.Ban(ctx, "192.0.2.9", "test", time.Minute); err == nil {
		t.Fatal("failed firewall reported success")
	}
	bans, _ := s.Bans()
	if len(bans) != 1 || bans[0].State != "unconfirmed" {
		t.Fatalf("incorrect failure state: %+v", bans)
	}
	f.err = nil
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	bans, _ = s.Bans()
	expiry := bans[0].Expires
	if bans[0].State != "applied" {
		t.Fatal(bans)
	}
	if err := e.Ban(ctx, "192.0.2.9", "duplicate", time.Hour); err != nil {
		t.Fatal(err)
	}
	bans, _ = s.Bans()
	if len(bans) != 1 || !bans[0].Expires.Equal(expiry) {
		t.Fatal("duplicate extended ban")
	}
	bans[0].Expires = time.Now().Add(-time.Second)
	if err := s.SaveBan(bans[0]); err != nil {
		t.Fatal(err)
	}
	if err := e.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	bans, _ = s.Bans()
	if len(f.entries) != 0 || bans[0].State != "expired" {
		t.Fatal("expired ban not removed")
	}
	if err := e.Ban(ctx, "192.0.2.9", "again", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := e.Unban(ctx, "192.0.2.9"); err != nil {
		t.Fatal(err)
	}
	bans, _ = s.Bans()
	if len(f.entries) != 0 || bans[0].State != "removed" {
		t.Fatal("unban not applied")
	}
}

func TestAllowlistRevokesExistingBanAndPersists(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeFirewall{}
	e := NewEngine(s, Config{Mode: "manual"}, f)
	ctx := context.Background()
	if err := e.Ban(ctx, "192.0.2.8", "test", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := e.Allow(ctx, "192.0.2.0/24", true); err != nil {
		t.Fatal(err)
	}
	if len(f.entries) != 0 {
		t.Fatal("allowlisted IP still blocked")
	}
	if err := e.Ban(ctx, "::ffff:192.0.2.8", "test", time.Minute); err == nil {
		t.Fatal("mapped IPv4 bypassed allowlist")
	}
	s.Close()
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	list, err := s.Allowlist()
	if err != nil || len(list) != 1 {
		t.Fatalf("lost allowlist: %v %v", list, err)
	}
}

func TestAutoRequiresFreshLocalSSHFailures(t *testing.T) {
	for _, mode := range []string{"monitor", "manual", "auto"} {
		t.Run(mode, func(t *testing.T) {
			s, e, f := fixture(t, mode)
			ctx := context.Background()
			for i := 0; i < 10; i++ {
				if err := e.Ingest(ctx, event(fmt.Sprint("old", i), time.Now().Add(-time.Hour))); err != nil {
					t.Fatal(err)
				}
			}
			if f.calls != 0 {
				t.Fatal("historical replay caused a ban")
			}
			for i := 0; i < 10; i++ {
				ev := event(fmt.Sprint("eve", i), time.Now())
				ev.Source = "suricata"
				if err := e.Ingest(ctx, ev); err != nil {
					t.Fatal(err)
				}
			}
			if f.calls != 0 {
				t.Fatal("EVE input caused auto-ban")
			}
			for i := 0; i < 10; i++ {
				ev := event(fmt.Sprint("ssh", i), time.Now())
				if err := e.Ingest(ctx, ev); err != nil {
					t.Fatal(err)
				}
				if err := e.Ingest(ctx, ev); err != nil {
					t.Fatal(err)
				}
			}
			count, err := s.FailureCount("192.0.2.9", time.Now().Add(-time.Minute), time.Now().Add(time.Second))
			if err != nil || count != 10 {
				t.Fatalf("deduplication failed: %d %v", count, err)
			}
			if mode == "auto" && len(f.entries) != 1 {
				t.Fatal("fresh failures not blocked")
			}
			if mode != "auto" && f.calls != 0 {
				t.Fatal("unexpected automatic enforcement")
			}
		})
	}
}

func TestJournalParsingDoesNotTrustSpoofedSyslogTag(t *testing.T) {
	row := map[string]string{"__CURSOR": "s=abc;i=1", "__REALTIME_TIMESTAMP": fmt.Sprint(time.Now().UnixMicro()), "_UID": "0", "_COMM": "sshd-session", "MESSAGE": "Failed password for invalid user admin from 2001:db8::2 port 49152 ssh2"}
	raw, _ := json.Marshal(row)
	e, _, err := ParseJournal(raw)
	if err != nil || e == nil || e.Kind != "ssh_failed" || e.Port != 0 || e.SourceIP != "2001:db8::2" {
		t.Fatalf("incorrect parse: %+v %v", e, err)
	}
	row["_UID"] = "1000"
	row["SYSLOG_IDENTIFIER"] = "sshd"
	raw, _ = json.Marshal(row)
	e, _, err = ParseJournal(raw)
	if err != nil || e != nil {
		t.Fatal("forged syslog tag accepted")
	}
	row["_UID"] = "0"
	row["MESSAGE"] = "Accepted publickey for memos from 192.0.2.4 port 44444 ssh2: ED25519 SHA256:example"
	raw, _ = json.Marshal(row)
	e, _, err = ParseJournal(raw)
	if err != nil || e == nil || e.Kind != "ssh_success" {
		t.Fatal("successful login not distinguished")
	}
}

func eveLine(ip string) string {
	return fmt.Sprintf(`{"timestamp":"2026-10-18T15:00:00.000000+0300","event_type":"alert","src_ip":%q,"dest_ip":"192.168.1.10","dest_port":22,"alert":{"signature_id":1000001,"signature":"Possible TCP scan","severity":2,"category":"Attempted Information Leak"}}`, ip)
}

func TestEVEPartialAppendRotationAndRestart(t *testing.T) {
	s, e, _ := fixture(t, "monitor")
	path := filepath.Join(t.TempDir(), "eve.json")
	e.config.EVEPath = path
	line := eveLine("192.0.2.1")
	if err := os.WriteFile(path, []byte(line[:40]), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.EVE(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitEvents := func(n int) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			rows, err := s.Events(0, true)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) == n {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("did not receive %d events", n)
	}
	time.Sleep(100 * time.Millisecond)
	rows, _ := s.Events(0, true)
	if len(rows) != 0 {
		t.Fatal("partial line ingested")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(line[40:] + "\n")
	f.Close()
	waitEvents(1)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(eveLine("192.0.2.2")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	waitEvents(2)
	// Checkpoints and stable event keys make replay idempotent.
	parsed, err := ParseEVE([]byte(line + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Ingest(ctx, *parsed); err != nil {
		t.Fatal(err)
	}
	waitEvents(2)
}

func TestStoreReplayAndTimeRange(t *testing.T) {
	s, _, _ := fixture(t, "monitor")
	now := time.Now()
	first := event("before", now.Add(-2*time.Hour))
	second := event("now", now)
	s.AddEvent(&first)
	s.AddEvent(&second)
	rows, err := s.Events(first.ID, false)
	if err != nil || len(rows) != 1 || rows[0].ID != second.ID {
		t.Fatal("cursor replay failed")
	}
	n, err := s.FailureCount(first.SourceIP, now.Add(-time.Hour), now.Add(time.Second))
	if err != nil || n != 1 {
		t.Fatal("timestamp range incorrect")
	}
}

func TestHTTPAuthOriginHostAndRealSSE(t *testing.T) {
	s, e, _ := fixture(t, "monitor")
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = NewLocalAPI(e, strings.Repeat("a", 64))
	srv.Start()
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 4 * time.Second}
	get := func(path string) (*http.Response, error) {
		r, err := http.NewRequest("GET", srv.URL+path, nil)
		if err != nil {
			return nil, err
		}
		r.Host = "localhost"
		return client.Do(r)
	}
	post := func(path, body, origin string) *http.Response {
		t.Helper()
		r, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
		r.Host = "localhost"
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		res, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	res, err := get("/api/events")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("events exposed")
	}
	res = post("/api/login", `{"token":"`+strings.Repeat("a", 64)+`"}`, "http://attacker.example")
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("cross-origin login accepted")
	}
	r, _ := http.NewRequest("GET", srv.URL+"/", nil)
	r.Host = "attacker.example"
	res, err = client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("DNS rebinding host accepted")
	}
	res = post("/api/login", `{"token":"`+strings.Repeat("a", 64)+`"}`, "http://localhost")
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("login failed")
	}
	res = post("/api/allowlist", `{"prefix":"192.0.2.1","add":true} {}`, "http://localhost")
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatal("trailing JSON accepted")
	}
	res = post("/api/ban", `{"ip":"192.0.2.1","minutes":10,"reason":"test"}`, "http://localhost")
	res.Body.Close()
	if res.StatusCode != 409 {
		t.Fatal("monitor mode allowed ban")
	}
	ev := event("sse1", time.Now())
	s.AddEvent(&ev)
	request, _ := http.NewRequest("GET", srv.URL+"/api/stream", nil)
	request.Host = "localhost"
	res, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("SSE failed")
	}
	reader := bufio.NewReader(res.Body)
	id, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if id != fmt.Sprintf("id: %d\n", ev.ID) {
		t.Fatalf("wrong SSE id: %s", id)
	}
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "data: ") {
		t.Fatalf("no SSE data: %s %v", line, err)
	}
	res.Body.Close()
	res = post("/api/logout", `{}`, "http://localhost")
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	res, err = get("/api/status")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("logout did not revoke session")
	}
}

func TestConfigValidatesSocketAndMode(t *testing.T) {
	t.Setenv("MEMOSHIELD_SOCKET", "relative/control.sock")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("relative socket path accepted")
	}
	t.Setenv("MEMOSHIELD_SOCKET", "/tmp/memoshield-test/control.sock")
	t.Setenv("MEMOSHIELD_MODE", "typo")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("invalid mode accepted")
	}
}
