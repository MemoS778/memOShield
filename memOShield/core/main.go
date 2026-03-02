package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type OutEvent struct {
	Type      string `json:"type"`
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	Timestamp int64  `json:"ts"`
}

var engineToken string

func postEvent(url string, ev OutEvent) {
	b, _ := json.Marshal(ev)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if engineToken != "" {
		req.Header.Set("Authorization", "Bearer "+engineToken)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("postEvent error: %v", err)
		return
	}
	resp.Body.Close()
}

func main() {
	iface := flag.String("iface", "any", "network interface to capture on (or 'any')")
	snaplen := flag.Int("snaplen", 1600, "pcap snaplen")
	promisc := flag.Bool("promisc", false, "promiscuous")
	filter := flag.String("filter", "tcp or udp", "BPF filter")
	engineURL := flag.String("engine", "http://127.0.0.1:8081/ingest", "Go engine ingest URL")
	rateThreshold := flag.Int("rate", 200, "packets/sec threshold per IP to consider DoS")
	portThreshold := flag.Int("portth", 20, "unique dest ports in window to consider portscan")
	windowSec := flag.Int("window", 10, "sliding window seconds")
	flag.Parse()

	engineToken = os.Getenv("ENGINE_TOKEN")
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, pcap.BlockForever)
	if err != nil {
		log.Fatalf("pcap open: %v", err)
	}
	defer handle.Close()

	if *filter != "" {
		if err := handle.SetBPFFilter(*filter); err != nil {
			log.Printf("failed to set bpf filter: %v", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// simple state
	var mu sync.Mutex
	hits := make(map[string][]int64)           // ip -> timestamps
	ports := make(map[string]map[uint16]int64) // ip -> port -> ts

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			now := time.Now().Unix()
			mu.Lock()
			for ip, ts := range hits {
				// cleanup older than window
				cutoff := now - int64(*windowSec)
				i := 0
				for ; i < len(ts); i++ {
					if ts[i] >= cutoff {
						break
					}
				}
				if i > 0 {
					hits[ip] = ts[i:]
				}
			}
			// cleanup ports
			for ip, m := range ports {
				for p, t := range m {
					if t < now-int64(*windowSec) {
						delete(m, p)
					}
				}
				if len(m) == 0 {
					delete(ports, ip)
				}
			}
			mu.Unlock()
		}
	}()

	log.Printf("Starting capture on %s (filter='%s')", *iface, *filter)

	for packet := range packetSource.Packets() {
		select {
		case <-sig:
			log.Println("shutting down")
			return
		default:
		}

		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			ipLayer = packet.Layer(layers.LayerTypeIPv6)
		}
		var srcIP string
		if ipLayer != nil {
			switch v := ipLayer.(type) {
			case *layers.IPv4:
				srcIP = v.SrcIP.String()
			case *layers.IPv6:
				srcIP = v.SrcIP.String()
			}
		}
		if srcIP == "" {
			continue
		}

		now := time.Now().Unix()
		mu.Lock()
		hits[srcIP] = append(hits[srcIP], now)
		// check rate
		if len(hits[srcIP]) >= *rateThreshold {
			ev := OutEvent{Type: "ban", IP: srcIP, Reason: fmt.Sprintf("rate %d", len(hits[srcIP])), Timestamp: now}
			go postEvent(*engineURL, ev)
			// reset
			hits[srcIP] = []int64{}
			mu.Unlock()
			continue
		}

		// check ports for TCP/UDP
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			if _, ok := ports[srcIP]; !ok {
				ports[srcIP] = make(map[uint16]int64)
			}
			ports[srcIP][uint16(tcp.DstPort)] = now
			if len(ports[srcIP]) >= *portThreshold {
				ev := OutEvent{Type: "ban", IP: srcIP, Reason: fmt.Sprintf("portscan %d", len(ports[srcIP])), Timestamp: now}
				go postEvent(*engineURL, ev)
				delete(ports, srcIP)
				mu.Unlock()
				continue
			}
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			if _, ok := ports[srcIP]; !ok {
				ports[srcIP] = make(map[uint16]int64)
			}
			ports[srcIP][uint16(udp.DstPort)] = now
			if len(ports[srcIP]) >= *portThreshold {
				ev := OutEvent{Type: "ban", IP: srcIP, Reason: fmt.Sprintf("portscan %d", len(ports[srcIP])), Timestamp: now}
				go postEvent(*engineURL, ev)
				delete(ports, srcIP)
				mu.Unlock()
				continue
			}
		}

		mu.Unlock()
	}
}
