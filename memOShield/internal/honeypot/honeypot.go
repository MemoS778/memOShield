package honeypot

import (
	"log"
	"net"
	"strconv"

	"github.com/MemoS778/memOShield/internal/config"
	"github.com/MemoS778/memOShield/internal/db"
	"github.com/MemoS778/memOShield/internal/firewall"
	"github.com/MemoS778/memOShield/internal/geoip"
	"github.com/MemoS778/memOShield/internal/ids"
)

// Honeypot listens on decoy ports and logs/bans connecting IPs.
type Honeypot struct {
	ids   *ids.IDS
	fw    *firewall.Firewall
	geo   *geoip.Client
	ports []int
}

// New creates a Honeypot.
func New(i *ids.IDS, fw *firewall.Firewall, geo *geoip.Client) *Honeypot {
	return &Honeypot{
		ids:   i,
		fw:    fw,
		geo:   geo,
		ports: config.HoneypotPorts,
	}
}

// Start begins listening on all honeypot ports.
func (h *Honeypot) Start() {
	for _, p := range h.ports {
		go h.listenPort(p)
	}
}

func (h *Honeypot) listenPort(port int) {
	addr := "0.0.0.0:" + strconv.Itoa(port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Honeypot port %d failed: %v", port, err)
		return
	}
	log.Printf("Honeypot listening on port %d", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		log.Printf("Honeypot triggered by %s on port %d", srcIP, port)

		geo := h.geo.Lookup(srcIP)
		db.LogEvent(srcIP, geo.Country, "Honeypot Trigger", "Port "+strconv.Itoa(port), geo.Lat, geo.Lon)
		h.fw.AddRule(srcIP, "Honeypot triggered")

		conn.Close()
	}
}
