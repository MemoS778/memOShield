package personal

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/MemoS778/memOShield/internal/firewallctl"
)

type Backend interface {
	Apply(context.Context, []firewallctl.Entry) error
}
type SensorStatus struct {
	State   string    `json:"state"`
	Detail  string    `json:"detail"`
	Updated time.Time `json:"updated"`
}

type Engine struct {
	store    *Store
	config   Config
	backend  Backend
	mu       sync.Mutex // serializes ban/allowlist mutations and reconciliation
	statusMu sync.RWMutex
	statuses map[string]SensorStatus
}

func NewEngine(store *Store, c Config, b Backend) *Engine {
	e := &Engine{store: store, config: c, backend: b, statuses: make(map[string]SensorStatus)}
	e.Status("journal", "disabled", "SSH günlük sensörü kapalı")
	e.Status("suricata", "disabled", "EVE dosyası yapılandırılmadı; ağ taraması görünürlüğü yok")
	e.Status("firewall", "disabled", "İzleme modu; engelleme uygulanmıyor")
	return e
}

func (e *Engine) Status(name, state, detail string) {
	e.statusMu.Lock()
	defer e.statusMu.Unlock()
	e.statuses[name] = SensorStatus{State: state, Detail: detail, Updated: time.Now().UTC()}
}
func (e *Engine) Statuses() map[string]SensorStatus {
	e.statusMu.RLock()
	defer e.statusMu.RUnlock()
	out := make(map[string]SensorStatus)
	for k, v := range e.statuses {
		out[k] = v
	}
	return out
}

func (e *Engine) Ingest(ctx context.Context, event Event) error {
	inserted, err := e.store.AddEvent(&event)
	if err != nil || !inserted {
		return err
	}
	// Only fresh, locally observed SSH failures can trigger automatic protection.
	// Remote EVE alerts and replayed historical records NEVER auto-ban.
	if event.Source != "journal" || event.Kind != "ssh_failed" {
		return nil
	}
	now := time.Now()
	age := now.Sub(event.Time)
	if age < -5*time.Second || age > 30*time.Second {
		return nil
	}
	n, err := e.store.FailureCount(event.SourceIP, now.Add(-2*time.Minute), now.Add(5*time.Second))
	if err != nil {
		return err
	}
	if n < 10 {
		return nil
	}
	alert := event
	alert.Kind = "ssh_bruteforce"
	alert.Severity = "high"
	alert.Key = fmt.Sprintf("ssh-burst:%s:%d", event.SourceIP, now.Unix()/120)
	alert.Evidence = fmt.Sprintf("Son 2 dakikada %d başarısız SSH parola girişi. Kaynak kişinin kimliğini kanıtlamaz.", n)
	newAlert, err := e.store.AddEvent(&alert)
	if err != nil {
		return err
	}
	if newAlert {
		log.Printf("ALERT ssh_bruteforce source=%s failures=%d", event.SourceIP, n)
	}
	if e.config.Mode == "auto" {
		if err := e.Ban(ctx, event.SourceIP, "SSH: 2 dakikada en az 10 başarısız parola girişi", 10*time.Minute); err != nil {
			e.Status("firewall", "error", err.Error())
		}
	}
	return nil
}

func normalizePrefix(raw string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(raw); err == nil {
		if a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("IPv6 zones are not supported")
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("invalid IP or CIDR")
	}
	return p.Masked(), nil
}

func (e *Engine) allowed(ip netip.Addr) (bool, error) {
	list, err := e.store.Allowlist()
	if err != nil {
		return false, err
	}
	for _, raw := range list {
		p, err := normalizePrefix(raw)
		if err != nil {
			return false, err
		}
		if p.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

func (e *Engine) Ban(ctx context.Context, raw, reason string, duration time.Duration) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.config.Mode == "monitor" {
		return fmt.Errorf("monitor mode: blocking is disabled")
	}
	ip, err := firewallctl.ParseAddress(raw)
	if err != nil {
		return err
	}
	allowed, err := e.allowed(ip)
	if err != nil {
		return err
	}
	if allowed {
		return fmt.Errorf("IP is allowlisted")
	}
	if duration < time.Minute || duration > time.Hour {
		return fmt.Errorf("duration must be between 1 and 60 minutes")
	}
	if len(reason) == 0 || len(reason) > 300 {
		return fmt.Errorf("reason must contain 1–300 bytes")
	}
	bans, err := e.store.Bans()
	if err != nil {
		return err
	}
	active := 0
	for _, b := range bans {
		if b.Desired && b.Expires.After(time.Now()) {
			active++
			if b.IP == ip.String() {
				return e.syncLocked(ctx)
			} // no duplicate or indefinite extension
		}
	}
	if active >= 256 {
		return fmt.Errorf("active ban limit reached")
	}
	if err := e.store.SaveBan(Ban{IP: ip.String(), Reason: reason, Desired: true, State: "pending", Expires: time.Now().Add(duration)}); err != nil {
		return err
	}
	return e.syncLocked(ctx)
}

func (e *Engine) Unban(ctx context.Context, raw string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.config.Mode == "monitor" {
		return fmt.Errorf("switch to manual mode to change firewall state")
	}
	ip, err := firewallctl.ParseAddress(raw)
	if err != nil {
		return err
	}
	bans, err := e.store.Bans()
	if err != nil {
		return err
	}
	for _, b := range bans {
		if b.IP == ip.String() {
			b.Desired = false
			b.State = "pending"
			if err := e.store.SaveBan(b); err != nil {
				return err
			}
		}
	}
	return e.syncLocked(ctx)
}

func (e *Engine) Allow(ctx context.Context, raw string, add bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	p, err := normalizePrefix(raw)
	if err != nil {
		return err
	}
	if err := e.store.SetAllowed(p.String(), add); err != nil {
		return err
	}
	if add {
		bans, err := e.store.Bans()
		if err != nil {
			return err
		}
		for _, b := range bans {
			if a, err := netip.ParseAddr(b.IP); err == nil && p.Contains(a) {
				b.Desired = false
				b.State = "pending"
				if err := e.store.SaveBan(b); err != nil {
					return err
				}
			}
		}
	}
	if e.config.Mode != "monitor" {
		return e.syncLocked(ctx)
	}
	return nil
}

func (e *Engine) Sync(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.syncLocked(ctx)
}

func (e *Engine) syncLocked(ctx context.Context) error {
	if e.config.Mode == "monitor" {
		return nil
	}
	bans, err := e.store.Bans()
	if err != nil {
		return err
	}
	entries := []firewallctl.Entry{}
	now := time.Now()
	for i := range bans {
		b := &bans[i]
		a, err := netip.ParseAddr(b.IP)
		if err != nil {
			return err
		}
		allowed, err := e.allowed(a)
		if err != nil {
			return err
		}
		if allowed {
			b.Desired = false
		}
		if b.Desired && b.Expires.After(now) {
			entries = append(entries, firewallctl.Entry{IP: b.IP, Expires: b.Expires})
		}
	}
	err = e.backend.Apply(ctx, entries)
	for _, b := range bans {
		if err != nil {
			b.State = "unconfirmed"
			b.Error = err.Error()
		} else {
			b.Error = ""
			b.Confirmed = now
			switch {
			case !b.Desired:
				b.State = "removed"
			case !b.Expires.After(now):
				b.State = "expired"
			default:
				b.State = "applied"
			}
		}
		if saveErr := e.store.SaveBan(b); saveErr != nil {
			return saveErr
		}
	}
	if err != nil {
		e.Status("firewall", "error", err.Error())
	} else {
		e.Status("firewall", "ready", fmt.Sprintf("%d süreli engel doğrulandı", len(entries)))
	}
	return err
}
