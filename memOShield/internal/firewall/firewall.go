package firewall

import (
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/MemoS778/memOShield/internal/config"
	"github.com/MemoS778/memOShield/internal/db"
)

// Rule represents an in-memory firewall rule.
type Rule struct {
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

// Firewall manages IP blocking rules.
type Firewall struct {
	mu    sync.Mutex
	rules []Rule
}

// New creates a new Firewall instance.
func New() *Firewall {
	return &Firewall{}
}

// AddRule blocks an IP address.
func (f *Firewall) AddRule(ip, reason string) bool {
	ts := time.Now().UTC().Format(time.RFC3339)
	f.mu.Lock()
	f.rules = append(f.rules, Rule{IP: ip, Reason: reason, CreatedAt: ts})
	f.mu.Unlock()

	db.AddRule(ip, reason)
	db.AddBan(ip, reason)
	log.Printf("Firewall: added rule %s (%s)", ip, reason)

	if config.IsLinux() {
		cmd := exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		if err := cmd.Run(); err != nil {
			log.Printf("OS firewall apply failed (need root): %v", err)
		}
	}
	return true
}

// RemoveRule unblocks an IP address (in-memory + DB + OS firewall).
func (f *Firewall) RemoveRule(ip string) bool {
	f.mu.Lock()
	var filtered []Rule
	for _, r := range f.rules {
		if r.IP != ip {
			filtered = append(filtered, r)
		}
	}
	f.rules = filtered
	f.mu.Unlock()

	// Remove from DB
	db.DeleteRuleByIP(ip)
	db.DeleteBanByIP(ip)

	// Remove OS-level iptables rule if on Linux
	if config.IsLinux() {
		cmd := exec.Command("sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
		if err := cmd.Run(); err != nil {
			log.Printf("OS firewall remove failed: %v", err)
		}
	}

	log.Printf("Firewall: removed %s (memory+DB+OS)", ip)
	return true
}

// ListRules returns all in-memory rules.
func (f *Firewall) ListRules() []Rule {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Rule, len(f.rules))
	copy(out, f.rules)
	return out
}
