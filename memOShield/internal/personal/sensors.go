package personal

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var sshMessage = regexp.MustCompile(`^(Failed password|Accepted password|Accepted publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)(?: |$)`)

// ParseJournal trusts journald metadata, not a caller-supplied syslog tag.
// Only root-owned sshd/sshd-session records are eligible for auto-protection.
func ParseJournal(line []byte) (*Event, string, error) {
	var row map[string]json.RawMessage
	if err := json.Unmarshal(line, &row); err != nil {
		return nil, "", err
	}
	field := func(k string) string { var s string; _ = json.Unmarshal(row[k], &s); return s }
	cursor := field("__CURSOR")
	comm := field("_COMM")
	if field("_UID") != "0" || (comm != "sshd" && comm != "sshd-session") {
		return nil, cursor, nil
	}
	message := field("MESSAGE")
	m := sshMessage.FindStringSubmatch(message)
	if m == nil {
		return nil, cursor, nil
	}
	ip, err := netip.ParseAddr(m[3])
	if err != nil {
		return nil, cursor, fmt.Errorf("invalid SSH source IP")
	}
	micros, err := strconv.ParseInt(field("__REALTIME_TIMESTAMP"), 10, 64)
	if err != nil || micros <= 0 || cursor == "" {
		return nil, cursor, fmt.Errorf("missing journal timestamp/cursor")
	}
	kind, severity := "ssh_success", "info"
	if m[1] == "Failed password" {
		kind, severity = "ssh_failed", "medium"
	}
	// The logged port is the client's ephemeral source port, NOT SSH's target port.
	return &Event{Time: time.UnixMicro(micros).UTC(), Source: "journal", Kind: kind, Severity: severity,
		SourceIP: ip.Unmap().String(), User: m[2], Evidence: message, Key: "journal:" + cursor}, cursor, nil
}

func ParseEVE(line []byte) (*Event, error) {
	var row struct {
		Timestamp string `json:"timestamp"`
		Type      string `json:"event_type"`
		SourceIP  string `json:"src_ip"`
		TargetIP  string `json:"dest_ip"`
		Port      int    `json:"dest_port"`
		Alert     struct {
			Signature string `json:"signature"`
			ID        int64  `json:"signature_id"`
			Severity  int    `json:"severity"`
			Category  string `json:"category"`
		} `json:"alert"`
	}
	if err := json.Unmarshal(line, &row); err != nil {
		return nil, err
	}
	if row.Type != "alert" {
		return nil, nil
	}
	source, err := netip.ParseAddr(row.SourceIP)
	if err != nil {
		return nil, err
	}
	target, err := netip.ParseAddr(row.TargetIP)
	if err != nil {
		return nil, err
	}
	if row.Port < 0 || row.Port > 65535 {
		return nil, fmt.Errorf("invalid EVE target port")
	}
	ts, err := time.Parse(time.RFC3339Nano, row.Timestamp)
	if err != nil {
		ts, err = time.Parse("2006-01-02T15:04:05.999999999-0700", row.Timestamp)
	}
	if err != nil {
		return nil, err
	}
	severity := "info"
	switch row.Alert.Severity {
	case 1:
		severity = "high"
	case 2:
		severity = "medium"
	case 3:
		severity = "low"
	}
	return &Event{Time: ts.UTC(), Source: "suricata", Kind: "network_alert", Severity: severity,
		SourceIP: source.Unmap().String(), TargetIP: target.Unmap().String(), Port: row.Port,
		Evidence: fmt.Sprintf("SID %d — %s (%s). Sensör uyarısı; başarılı giriş kanıtı değildir.", row.Alert.ID, row.Alert.Signature, row.Alert.Category),
		Key:      fmt.Sprintf("eve:%x", sha256.Sum256(line))}, nil
}

func (e *Engine) Journal(ctx context.Context) {
	for ctx.Err() == nil {
		if err := e.journalOnce(ctx); err != nil && ctx.Err() == nil {
			e.Status("journal", "error", err.Error())
		}
		if !pause(ctx, 10*time.Second) {
			return
		}
	}
}

func (e *Engine) journalOnce(ctx context.Context) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	probe, err := exec.CommandContext(probeCtx, "journalctl", "--system", "--no-pager", "-n", "1", "-o", "json").Output()
	cancel()
	if err != nil || len(strings.TrimSpace(string(probe))) == 0 {
		return fmt.Errorf("sistem günlüğü okunamıyor; journal izinlerini kontrol edin (SSH koruması etkin değil)")
	}
	cursor, err := e.store.Checkpoint("journal")
	if err != nil {
		return err
	}
	args := []string{"--system", "--follow", "--no-pager", "--output=json", "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session"}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor, "-n", "all")
	} else {
		args = append(args, "--since=-24h", "-n", "200")
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmd.Wait()
	}()
	e.Status("journal", "watching", "SSH günlüğü izleniyor; bu durum SSH servisinin açık olduğunu göstermez")
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		event, cursor, err := ParseJournal(scanner.Bytes())
		if err != nil {
			e.Status("journal", "warning", "Geçersiz SSH kaydı atlandı: "+err.Error())
			continue
		}
		if event != nil {
			if err := e.Ingest(ctx, *event); err != nil {
				return err
			}
			e.Status("journal", "receiving", "Son SSH olayı: "+event.Time.Format(time.RFC3339))
		}
		if cursor != "" {
			if err := e.store.SaveCheckpoint("journal", cursor); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("journalctl akışı sonlandı; tekrar bağlanılıyor (eski cursor veya erişim hatası olabilir)")
}

type filePosition struct {
	Identity string `json:"identity"`
	Offset   int64  `json:"offset"`
}

func identity(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	}
	return info.Name()
}

// EVE follows complete JSON lines, preserving an incomplete trailing line for
// the next poll. It drains an old inode before following rename rotation.
func (e *Engine) EVE(ctx context.Context) {
	for ctx.Err() == nil {
		if err := e.eveOnce(ctx); err != nil && ctx.Err() == nil {
			e.Status("suricata", "error", err.Error())
		}
		if !pause(ctx, 3*time.Second) {
			return
		}
	}
}

func (e *Engine) eveOnce(ctx context.Context) error {
	path := e.config.EVEPath
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("EVE path must be a regular file")
	}
	position := filePosition{Identity: identity(info)}
	key := "eve:" + path
	checkpoint, err := e.store.Checkpoint(key)
	if err != nil {
		return err
	}
	if checkpoint != "" {
		var saved filePosition
		if err := json.Unmarshal([]byte(checkpoint), &saved); err != nil {
			return err
		}
		if saved.Identity == position.Identity && saved.Offset >= 0 && saved.Offset <= info.Size() {
			position.Offset = saved.Offset
		}
	}
	e.Status("suricata", "watching", "EVE dosyası okunuyor; sensörün paket yakaladığını tek başına kanıtlamaz")
	for ctx.Err() == nil {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.Size() < position.Offset {
			position.Offset = 0
		}
		if _, err := f.Seek(position.Offset, io.SeekStart); err != nil {
			return err
		}
		reader := bufio.NewReaderSize(f, 1<<20)
		eof := false
		for n := 0; n < 500; n++ {
			line, err := reader.ReadSlice('\n')
			if err == io.EOF {
				eof = true
				break
			}
			if err != nil {
				return fmt.Errorf("EVE line exceeds 1 MiB or read failed: %w", err)
			}
			event, parseErr := ParseEVE(line)
			if parseErr != nil {
				e.Status("suricata", "warning", "Geçersiz EVE satırı atlandı: "+parseErr.Error())
			} else if event != nil {
				if err := e.Ingest(ctx, *event); err != nil {
					return err
				}
				e.Status("suricata", "receiving", "Son ağ uyarısı: "+event.Time.Format(time.RFC3339))
			}
			position.Offset += int64(len(line))
			b, err := json.Marshal(position)
			if err != nil {
				return err
			}
			if err := e.store.SaveCheckpoint(key, string(b)); err != nil {
				return err
			}
		}
		if eof {
			current, err := os.Stat(path)
			if err == nil && !os.SameFile(info, current) {
				return nil
			}
		}
		if !pause(ctx, time.Second) {
			return ctx.Err()
		}
	}
	return ctx.Err()
}

func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
