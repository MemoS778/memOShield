package personal

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/MemoS778/memOShield/internal/firewallctl"
)

func Run(parent context.Context) error {
	c, err := LoadConfig()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.DataDir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(c.DataDir, "instance.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another memOShield instance uses this data directory: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	store, err := OpenStore(c.DataDir)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.InvalidateBans(); err != nil {
		return err
	}
	token, err := loadToken(c.DataDir)
	if err != nil {
		return err
	}
	engine := NewEngine(store, c, firewallctl.Client{Socket: c.FirewallSocket})
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	var workers sync.WaitGroup
	start := func(fn func(context.Context)) { workers.Add(1); go func() { defer workers.Done(); fn(ctx) }() }
	if c.Journal {
		start(engine.Journal)
	}
	if c.EVEPath != "" {
		start(engine.EVE)
	}
	start(func(ctx context.Context) {
		for ctx.Err() == nil {
			if err := engine.Sync(ctx); err != nil {
				log.Printf("firewall: %v", err)
			}
			if !pause(ctx, 10*time.Second) {
				return
			}
		}
	})
	start(func(ctx context.Context) {
		for ctx.Err() == nil {
			if err := store.Prune(); err != nil {
				engine.Status("database", "error", err.Error())
			} else {
				engine.Status("database", "ready", "30 gün / en fazla 100.000 olay saklanır")
			}
			if !pause(ctx, time.Minute) {
				return
			}
		}
	})
	server := &http.Server{Handler: NewWeb(engine, token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, BaseContext: func(net.Listener) context.Context { return ctx }}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	log.Printf("memOShield Personal: http://%s (mode=%s)", c.Listen, c.Mode)
	log.Printf("Login token file: %s (not printed in logs)", filepath.Join(c.DataDir, "access-token"))
	select {
	case <-ctx.Done():
	case err = <-result:
	}
	cancel()
	shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
		server.Close()
	}
	workers.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
