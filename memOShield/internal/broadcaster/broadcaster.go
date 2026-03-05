package broadcaster

import (
	"encoding/json"
	"sync"
)

// Broadcaster fans out events to registered SSE subscribers.
type Broadcaster struct {
	mu      sync.RWMutex
	clients []chan string
}

// Global singleton
var Global = &Broadcaster{}

// Register creates a new channel for a subscriber.
func (b *Broadcaster) Register() chan string {
	ch := make(chan string, 64)
	b.mu.Lock()
	b.clients = append(b.clients, ch)
	b.mu.Unlock()
	return ch
}

// Unregister removes and closes a subscriber channel.
func (b *Broadcaster) Unregister(ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, c := range b.clients {
		if c == ch {
			b.clients = append(b.clients[:i], b.clients[i+1:]...)
			close(ch)
			return
		}
	}
}

// Publish sends an event to all subscribers (non-blocking).
func (b *Broadcaster) Publish(obj interface{}) {
	data, err := json.Marshal(obj)
	if err != nil {
		return
	}
	s := string(data)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.clients {
		select {
		case ch <- s:
		default:
			// drop if full
		}
	}
}
