package main

import (
	"log"
	"net/http"
	"time"

	"github.com/MemoS778/memOShield/internal/config"
	"github.com/MemoS778/memOShield/internal/db"
	"github.com/MemoS778/memOShield/internal/firewall"
	"github.com/MemoS778/memOShield/internal/geoip"
	"github.com/MemoS778/memOShield/internal/honeypot"
	"github.com/MemoS778/memOShield/internal/ids"
	"github.com/MemoS778/memOShield/internal/mockstream"
	"github.com/MemoS778/memOShield/internal/notifier"
	"github.com/MemoS778/memOShield/internal/pcap"
	"github.com/MemoS778/memOShield/internal/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("memOShield starting...")

	// Initialize database
	db.InitDB()

	// Core services
	fw := firewall.New()
	geo := geoip.NewClient()
	idsEngine := ids.New(fw, geo)
	hp := honeypot.New(idsEngine, fw, geo)
	n := notifier.New()
	pcapRec := pcap.New("", "")

	// Start background services (best-effort)
	idsEngine.Start()
	hp.Start()
	pcapRec.Start("")
	log.Println("Background services started")

	// Optional mock stream
	mockstream.StartFromEnv()

	// HTTP server with security timeouts (Slow Loris / connection exhaustion protection)
	srv := web.NewServer(fw, geo, idsEngine, n)

	addr := "0.0.0.0:" + config.ServerPort
	log.Printf("memOShield v2.0 listening on http://%s", addr)
	log.Println("Security: WAF, Rate Limiting, CSRF, Brute Force Protection, UA Analysis, IP Reputation, Session Management, 2FA Ready")

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB max headers
	}

	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
