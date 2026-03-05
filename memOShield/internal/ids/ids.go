package ids

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/MemoS778/memOShield/internal/config"
	"github.com/MemoS778/memOShield/internal/db"
	"github.com/MemoS778/memOShield/internal/firewall"
	"github.com/MemoS778/memOShield/internal/geoip"
	"github.com/MemoS778/memOShield/internal/whitelist"
)

// IDS implements a rate-limit based intrusion detection system.
type IDS struct {
	fw            *firewall.Firewall
	geo           *geoip.Client
	threshold     int
	window        time.Duration
	banDuration   time.Duration
	portThreshold int
	uaRules       []string

	mu     sync.Mutex
	events map[string][]float64       // ip -> timestamps
	ports  map[string]map[int]float64 // ip -> port -> timestamp
	banned map[string]float64         // ip -> banned_at
	stopCh chan struct{}
}

// New creates a new IDS instance.
func New(fw *firewall.Firewall, geo *geoip.Client) *IDS {
	return &IDS{
		fw:            fw,
		geo:           geo,
		threshold:     config.IDSThreshold,
		window:        time.Duration(config.IDSWindowSeconds) * time.Second,
		banDuration:   time.Duration(config.IDSBanDurationSeconds) * time.Second,
		portThreshold: config.IDSPortThreshold,
		events:        make(map[string][]float64),
		uaRules:       config.IDSUserAgentRules,
		ports:         make(map[string]map[int]float64),
		banned:        make(map[string]float64),
		stopCh:        make(chan struct{}),
	}
}

// Start begins the background sweeper goroutine.
func (ids *IDS) Start() {
	go ids.sweeperLoop()
}

// Stop signals the sweeper to stop.
func (ids *IDS) Stop() {
	close(ids.stopCh)
}

// RecordPacket records a packet from src_ip and triggers detection if thresholds are met.
func (ids *IDS) RecordPacket(srcIP string, destPort *int, userAgent string) {
	if whitelist.IsWhitelisted(srcIP) {
		return
	}

	now := float64(time.Now().UnixMilli()) / 1000.0
	windowStart := now - ids.window.Seconds()

	ids.mu.Lock()
	defer ids.mu.Unlock()

	// Rate limit detection
	timestamps := ids.events[srcIP]
	// Clean old entries
	cleaned := timestamps[:0]
	for _, ts := range timestamps {
		if ts >= windowStart {
			cleaned = append(cleaned, ts)
		}
	}
	cleaned = append(cleaned, now)
	ids.events[srcIP] = cleaned

	count := len(cleaned)
	if count >= ids.threshold {
		if _, banned := ids.banned[srcIP]; !banned {
			ids.banned[srcIP] = now
			reason := fmt.Sprintf("IDS threshold %d/%ds", count, int(ids.window.Seconds()))
			ids.fw.AddRule(srcIP, reason)
			geo := ids.lookupGeo(srcIP)
			db.LogEvent(srcIP, geo.Country, "DoS/DDoS", reason, geo.Lat, geo.Lon)
			log.Printf("IDS: banned %s (%d packets)", srcIP, count)
		}
	}

	// Port scan detection
	if destPort != nil {
		if ids.ports[srcIP] == nil {
			ids.ports[srcIP] = make(map[int]float64)
		}
		ids.ports[srcIP][*destPort] = now

		// Cleanup old ports
		for p, ts := range ids.ports[srcIP] {
			if ts < windowStart {
				delete(ids.ports[srcIP], p)
			}
		}

		if len(ids.ports[srcIP]) >= ids.portThreshold {
			if _, banned := ids.banned[srcIP]; !banned {
				ids.banned[srcIP] = now
				reason := fmt.Sprintf("Port-scan detected (%d ports)", len(ids.ports[srcIP]))
				ids.fw.AddRule(srcIP, reason)
				geo := ids.lookupGeo(srcIP)
				db.LogEvent(srcIP, geo.Country, "PortScan", reason, geo.Lat, geo.Lon)
				log.Printf("IDS: port-scan banned %s (%d ports)", srcIP, len(ids.ports[srcIP]))
			}
		}
	}

	// User-Agent analysis
	if userAgent != "" {
		uaLower := strings.ToLower(userAgent)
		for _, rule := range ids.uaRules {
			if strings.Contains(uaLower, strings.ToLower(rule)) {
				if _, banned := ids.banned[srcIP]; !banned {
					ids.banned[srcIP] = now
					reason := fmt.Sprintf("User-Agent rule matched: %s", rule)
					ids.fw.AddRule(srcIP, reason)
					geo := ids.lookupGeo(srcIP)
					db.LogEvent(srcIP, geo.Country, "UA-Detect", reason, geo.Lat, geo.Lon)
					log.Printf("IDS: UA banned %s rule=%s", srcIP, rule)
				}
				break
			}
		}
	}
}

func (ids *IDS) lookupGeo(ip string) geoip.Info {
	if ids.geo != nil {
		return ids.geo.Lookup(ip)
	}
	return geoip.Info{Country: "Unknown"}
}

func (ids *IDS) sweeperLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ids.stopCh:
			return
		case <-ticker.C:
			now := float64(time.Now().UnixMilli()) / 1000.0
			ids.mu.Lock()
			for ip, bannedAt := range ids.banned {
				if now-bannedAt > ids.banDuration.Seconds() {
					delete(ids.banned, ip)
				}
			}
			ids.mu.Unlock()
		}
	}
}
