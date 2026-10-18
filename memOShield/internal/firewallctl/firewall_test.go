package firewallctl

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNftInIsolatedNetworkNamespace(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft unavailable")
	}
	if err := exec.Command("unshare", "--user", "--map-root-user", "--net", "true").Run(); err != nil {
		t.Skip("rootless network namespace unavailable")
	}
	batch, err := Batch([]Entry{{IP: "192.0.2.9", Expires: time.Now().Add(10 * time.Minute)}}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Never run nft in the host namespace, even when the test itself runs as root.
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--net", "sh", "-c", "nft -f - && nft -j list ruleset")
	cmd.Stdin = strings.NewReader("add table inet unrelated\n" + InitRules + batch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated nft transaction failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "192.0.2.9") || !strings.Contains(string(out), "unrelated") {
		t.Fatalf("missing applied ban or unrelated table: %s", out)
	}
}

func TestBatchOnlyChangesOwnedSetsAndUsesTimeouts(t *testing.T) {
	now := time.Now()
	b, err := Batch([]Entry{{IP: "192.0.2.7", Expires: now.Add(10 * time.Minute)}, {IP: "2001:db8::7", Expires: now.Add(time.Minute)}}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"flush set inet memoshield_personal blocked4", "blocked4 { 192.0.2.7 timeout 600s }", "blocked6 { 2001:db8::7 timeout 60s }"} {
		if !strings.Contains(b, want) {
			t.Fatalf("missing %q in %s", want, b)
		}
	}
	if strings.Contains(b, "flush ruleset") {
		t.Fatal("must not modify unrelated firewall state")
	}
}

func TestBatchRejectsUnsafeRequests(t *testing.T) {
	now := time.Now()
	protected := []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "169.254.1.1", "ff02::1", "fe80::1%wlan0", "192.168.1.1", "192.0.2.1; flush ruleset"} {
		t.Run(ip, func(t *testing.T) {
			if _, err := Batch([]Entry{{IP: ip, Expires: now.Add(time.Minute)}}, protected, now); err == nil {
				t.Fatal("unsafe target accepted")
			}
		})
	}
	if _, err := Batch([]Entry{{IP: "192.0.2.1", Expires: now.Add(2 * time.Hour)}}, nil, now); err == nil {
		t.Fatal("unbounded duration accepted")
	}
	if _, err := Batch(make([]Entry, 257), nil, now); err == nil {
		t.Fatal("unbounded set accepted")
	}
}

func TestClientPropagatesHelperFailure(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "fw.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var request Request
		json.NewDecoder(c).Decode(&request)
		json.NewEncoder(c).Encode(Response{Error: "permission denied"})
	}()
	err = (Client{Socket: socket}).Apply(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("failure hidden: %v", err)
	}
	<-done
}
