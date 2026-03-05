package whitelist

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

var (
	mu  sync.RWMutex
	set = make(map[string]struct{})
)

// LoadFile loads whitelisted IPs from a file (one per line, # comments).
func LoadFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	mu.Lock()
	defer mu.Unlock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			set[line] = struct{}{}
		}
	}
}

// IsWhitelisted checks if an IP is in the whitelist.
func IsWhitelisted(ip string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := set[ip]
	return ok
}

// Add adds an IP to the whitelist.
func Add(ip string) {
	mu.Lock()
	defer mu.Unlock()
	set[ip] = struct{}{}
}

// Remove removes an IP from the whitelist.
func Remove(ip string) {
	mu.Lock()
	defer mu.Unlock()
	delete(set, ip)
}

// GetAll returns all whitelisted IPs.
func GetAll() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	return out
}
