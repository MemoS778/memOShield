// Package firewallctl defines a narrowly scoped Unix-socket firewall protocol.
// The web process never executes sudo or receives CAP_NET_ADMIN.
package firewallctl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Entry struct {
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires"`
}
type Request struct {
	Entries []Entry `json:"entries"`
}
type Response struct {
	Error string `json:"error,omitempty"`
}

type Client struct{ Socket string }

func (c Client) Apply(ctx context.Context, entries []Entry) error {
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return fmt.Errorf("firewall helper unavailable: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(Request{Entries: entries}); err != nil {
		return err
	}
	var response Response
	if err := json.NewDecoder(io.LimitReader(conn, 65536)).Decode(&response); err != nil {
		return err
	}
	if response.Error != "" {
		return fmt.Errorf("firewall: %s", response.Error)
	}
	return nil
}

func ParseAddress(raw string) (netip.Addr, error) {
	a, err := netip.ParseAddr(raw)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid IP address")
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return netip.Addr{}, fmt.Errorf("loopback, multicast, link-local and unspecified addresses cannot be blocked")
	}
	return a, nil
}

// Protected discovers this host's addresses, gateways and configured DNS servers.
// It is refreshed by the helper before every transaction as Wi-Fi networks change.
func Protected(ctx context.Context) ([]netip.Addr, error) {
	var out []netip.Addr
	add := func(s string) {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap())
		}
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addresses {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	for _, family := range []string{"-4", "-6"} {
		b, err := exec.CommandContext(ctx, "ip", family, "-json", "route", "show", "default").Output()
		if err != nil {
			return nil, fmt.Errorf("cannot discover gateways: %w", err)
		}
		var routes []struct {
			Gateway string `json:"gateway"`
		}
		if err := json.Unmarshal(b, &routes); err != nil {
			return nil, err
		}
		for _, route := range routes {
			add(route.Gateway)
		}
	}
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "nameserver" {
				add(fields[1])
			}
		}
	}
	return out, nil
}

const InitRules = `add table inet memoshield_personal
add set inet memoshield_personal blocked4 { type ipv4_addr; flags timeout; }
add set inet memoshield_personal blocked6 { type ipv6_addr; flags timeout; }
add chain inet memoshield_personal input { type filter hook input priority -10; policy accept; }
flush chain inet memoshield_personal input
add rule inet memoshield_personal input ip saddr @blocked4 counter drop
add rule inet memoshield_personal input ip6 saddr @blocked6 counter drop
`

// Batch updates only our two sets in one nft transaction. Kernel timeouts ensure
// bans expire even if both the dashboard and helper stop running.
func Batch(entries []Entry, protected []netip.Addr, now time.Time) (string, error) {
	if len(entries) > 256 {
		return "", fmt.Errorf("at most 256 active bans are supported")
	}
	var b strings.Builder
	b.WriteString("flush set inet memoshield_personal blocked4\nflush set inet memoshield_personal blocked6\n")
	seen := map[netip.Addr]bool{}
	for _, e := range entries {
		a, err := ParseAddress(e.IP)
		if err != nil {
			return "", err
		}
		for _, p := range protected {
			if a == p.Unmap() {
				return "", fmt.Errorf("protected host/gateway/DNS address: %s", a)
			}
		}
		if seen[a] {
			return "", fmt.Errorf("duplicate IP")
		}
		seen[a] = true
		remaining := e.Expires.Sub(now)
		if remaining <= 0 {
			continue
		}
		if remaining > time.Hour {
			return "", fmt.Errorf("ban duration exceeds one hour")
		}
		seconds := int64(remaining / time.Second)
		if seconds < 1 {
			continue
		}
		set := "blocked6"
		if a.Is4() {
			set = "blocked4"
		}
		fmt.Fprintf(&b, "add element inet memoshield_personal %s { %s timeout %ds }\n", set, a.String(), seconds)
	}
	return b.String(), nil
}

func Execute(ctx context.Context, batch string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(batch)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft transaction failed: %w: %s", err, strings.TrimSpace(string(b)))
	}
	return nil
}
