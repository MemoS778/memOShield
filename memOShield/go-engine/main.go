package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	broker := NewBroker()
	go broker.Run()

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	http.HandleFunc("/events", broker.ServeHTTP)

	// ingest arbitrary event (from core engine)
	http.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// simple token auth between services
		svcToken := os.Getenv("AUTH_TOKEN")
		if svcToken != "" {
			h := r.Header.Get("Authorization")
			if h == "" {
				h = r.Header.Get("X-API-KEY")
			}
			if !strings.HasPrefix(h, "Bearer ") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if strings.TrimPrefix(h, "Bearer ") != svcToken {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}

		var ev Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if ev.Timestamp == 0 {
			ev.Timestamp = time.Now().Unix()
		}
		broker.Broadcast(ev)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	http.HandleFunc("/ban", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var b struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		e := Event{Type: "ban", IP: b.IP, Reason: b.Reason, Timestamp: time.Now().Unix()}
		broker.Broadcast(e)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	http.HandleFunc("/simulate", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			for i := 1; i <= 10; i++ {
				e := Event{Type: "alert", IP: fmt.Sprintf("203.0.113.%d", i), Reason: "simulated", Timestamp: time.Now().Unix()}
				broker.Broadcast(e)
				time.Sleep(400 * time.Millisecond)
			}
		}()
		w.Write([]byte("simulate started"))
	})

	addr := ":8081"
	log.Println("Go engine listening on", addr)

	// TLS support if TLS_CERT and TLS_KEY env vars provided
	cert := os.Getenv("TLS_CERT")
	key := os.Getenv("TLS_KEY")
	if cert != "" && key != "" {
		log.Println("Starting with TLS")
		log.Fatal(http.ListenAndServeTLS(addr, cert, key, nil))
	}
	log.Fatal(http.ListenAndServe(addr, nil))
}
