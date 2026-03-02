package main

import (
  "encoding/json"
  "fmt"
  "net/http"
  "sync"
)

// Event represents a security event sent to consumers
type Event struct {
  Type      string `json:"type"`
  IP        string `json:"ip"`
  Reason    string `json:"reason"`
  Timestamp int64  `json:"ts"`
}

// Broker is a simple in-memory SSE broker
type Broker struct {
  clients  map[chan Event]bool
  addCh    chan chan Event
  removeCh chan chan Event
  sendCh   chan Event
  mu       sync.Mutex
}

func NewBroker() *Broker {
  return &Broker{
    clients:  make(map[chan Event]bool),
    addCh:    make(chan chan Event),
    removeCh: make(chan chan Event),
    sendCh:   make(chan Event, 16),
  }
}

func (b *Broker) Run() {
  for {
    select {
    case c := <-b.addCh:
      b.mu.Lock()
      b.clients[c] = true
      b.mu.Unlock()
    case c := <-b.removeCh:
      b.mu.Lock()
      delete(b.clients, c)
      close(c)
      b.mu.Unlock()
    case ev := <-b.sendCh:
      b.mu.Lock()
      for c := range b.clients {
        select {
        case c <- ev:
        default:
        }
      }
      b.mu.Unlock()
    }
  }
}

func (b *Broker) Broadcast(e Event) {
  select {
  case b.sendCh <- e:
  default:
  }
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  flusher, ok := w.(http.Flusher)
  if !ok {
    http.Error(w, "streaming unsupported", http.StatusInternalServerError)
    return
  }
  w.Header().Set("Content-Type", "text/event-stream")
  w.Header().Set("Cache-Control", "no-cache")
  ch := make(chan Event, 8)
  b.addCh <- ch
  defer func() { b.removeCh <- ch }()

  // initial ping
  fmt.Fprintf(w, "event: connected\ndata: %s\n\n", `{"status":"ok"}`)
  flusher.Flush()

  enc := json.NewEncoder(w)
  for ev := range ch {
    data, _ := json.Marshal(ev)
    fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
    flusher.Flush()
    _ = enc
  }
}
