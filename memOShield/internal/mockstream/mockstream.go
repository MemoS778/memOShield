package mockstream

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/MemoS778/memOShield/internal/db"
)

var attackTypes = []string{"Honeypot Trigger", "Port Scan", "DoS/DDoS", "Brute Force", "SQL Injection", "XSS"}

var sampleCountries = []struct {
	Country string
	Lat     float64
	Lon     float64
}{
	{"US", 37.7749, -122.4194},
	{"TR", 39.9255, 32.8663},
	{"DE", 52.52, 13.405},
	{"RU", 55.7558, 37.6173},
	{"CN", 39.9042, 116.4074},
	{"BR", -23.5505, -46.6333},
}

var stopCh chan struct{}

func emitOne() {
	ip := fmt.Sprintf("%d.%d.%d.%d", rand.Intn(254)+1, rand.Intn(254)+1, rand.Intn(254)+1, rand.Intn(254)+1)
	c := sampleCountries[rand.Intn(len(sampleCountries))]
	attack := attackTypes[rand.Intn(len(attackTypes))]
	details := fmt.Sprintf("Live mock: %s from %s", attack, ip)
	db.LogEvent(ip, c.Country, attack, details, c.Lat+rand.Float64()-0.5, c.Lon+rand.Float64()-0.5)
}

func steadyLoop(interval time.Duration) {
	for {
		select {
		case <-stopCh:
			return
		default:
			emitOne()
			time.Sleep(interval)
		}
	}
}

func burstLoop(burstSize int, baseInterval time.Duration) {
	for {
		select {
		case <-stopCh:
			return
		default:
			time.Sleep(baseInterval)
			spread := float64(baseInterval) * 0.5 / float64(burstSize)
			for i := 0; i < burstSize; i++ {
				select {
				case <-stopCh:
					return
				default:
					emitOne()
					if spread > float64(50*time.Millisecond) {
						time.Sleep(time.Duration(spread))
					} else {
						time.Sleep(50 * time.Millisecond)
					}
				}
			}
		}
	}
}

func randomizedLoop(minInterval, maxInterval time.Duration) {
	for {
		select {
		case <-stopCh:
			return
		default:
			emitOne()
			d := minInterval + time.Duration(rand.Int63n(int64(maxInterval-minInterval)))
			time.Sleep(d)
		}
	}
}

// Start launches the mock stream in the given mode.
func Start(mode string, interval int, burstSize int, baseInterval int) {
	stopCh = make(chan struct{})

	// Override from env
	if m := os.Getenv("MOCK_STREAM_MODE"); m != "" {
		mode = m
	}

	switch mode {
	case "burst":
		go burstLoop(burstSize, time.Duration(baseInterval)*time.Second)
	case "random":
		maxInt := interval
		if maxInt < 2 {
			maxInt = 2
		}
		go randomizedLoop(1*time.Second, time.Duration(maxInt)*time.Second)
	default:
		go steadyLoop(time.Duration(interval) * time.Second)
	}
}

// Stop halts the mock stream.
func Stop() {
	if stopCh != nil {
		close(stopCh)
	}
}

// StartFromEnv starts mock stream using environment variables.
func StartFromEnv() {
	enable := os.Getenv("ENABLE_MOCK_STREAM")
	if enable != "1" && enable != "true" && enable != "True" {
		return
	}
	interval := 3
	if v := os.Getenv("MOCK_STREAM_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			interval = n
		}
	}
	mode := os.Getenv("MOCK_STREAM_MODE")
	if mode == "" {
		mode = "steady"
	}
	Start(mode, interval, 10, 10)
}
