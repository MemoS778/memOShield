// Linux-only optional privileged helper. It accepts validated timed IP sets,
// never shell commands, file paths, arbitrary nft expressions or forwarding rules.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MemoS778/memOShield/internal/firewallctl"
)

func main() {
	socket := flag.String("socket", "/run/memoshield/firewall.sock", "Unix socket in a root-owned directory")
	uid := flag.Int("uid", -1, "UID of the local dashboard user")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *socket, *uid); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, socket string, uid int) error {
	if os.Geteuid() != 0 || uid <= 0 {
		return fmt.Errorf("run helper as root and supply --uid of a non-root user")
	}
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("socket directory must be root-owned and not writable by other users")
	}
	// Refuse an existing socket instead of unlinking another running helper.
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	if err := os.Chown(socket, uid, -1); err != nil {
		return err
	}
	initCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = firewallctl.Execute(initCtx, firewallctl.InitRules)
	cancel()
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); listener.Close() }()
	log.Printf("firewall helper ready at %s for UID %d", socket, uid)
	// Serial transactions; idle connections cannot hold the helper indefinitely.
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		conn.SetDeadline(time.Now().Add(8 * time.Second))
		response := firewallctl.Response{}
		var request firewallctl.Request
		decoder := json.NewDecoder(io.LimitReader(conn, 65536))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			response.Error = "invalid request"
		} else {
			opCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			protected, err := firewallctl.Protected(opCtx)
			if err == nil {
				var batch string
				batch, err = firewallctl.Batch(request.Entries, protected, time.Now())
				if err == nil {
					err = firewallctl.Execute(opCtx, batch)
				}
			}
			cancel()
			if err != nil {
				response.Error = err.Error()
			}
		}
		json.NewEncoder(conn).Encode(response)
		conn.Close()
	}
}
