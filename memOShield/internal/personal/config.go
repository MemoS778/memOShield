// Package personal is the unprivileged local personal IDS control plane.
// Firewall operations are delegated to a separate privileged helper.
package personal

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Socket, DataDir, Mode, EVEPath, FirewallSocket string
	Journal                                        bool
}

func LoadConfig() (Config, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Config{}, err
		}
		base = filepath.Join(home, ".local", "state")
	}
	c := Config{
		Socket:  env("MEMOSHIELD_SOCKET", filepath.Join(env("XDG_RUNTIME_DIR", filepath.Join(base, "memoshield")), "memoshield", "control.sock")),
		DataDir: env("MEMOSHIELD_DATA_DIR", filepath.Join(base, "memoshield")),
		Mode:    env("MEMOSHIELD_MODE", "monitor"), EVEPath: os.Getenv("MEMOSHIELD_EVE_PATH"),
		FirewallSocket: env("MEMOSHIELD_FIREWALL_SOCKET", "/run/memoshield/firewall.sock"),
		Journal:        env("MEMOSHIELD_JOURNAL", "1") == "1",
	}
	if !filepath.IsAbs(c.Socket) {
		return c, fmt.Errorf("MEMOSHIELD_SOCKET must be an absolute path")
	}
	if c.Mode != "monitor" && c.Mode != "manual" && c.Mode != "auto" {
		return c, fmt.Errorf("MEMOSHIELD_MODE must be monitor, manual or auto")
	}
	return c, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func loadToken(dir string) (string, error) {
	path := filepath.Join(dir, "access-token")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		token, err := randomToken()
		if err != nil {
			return "", err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return "", err
		}
		_, err = f.WriteString(token + "\n")
		closeErr := f.Close()
		if err != nil {
			return "", err
		}
		return token, closeErr
	}
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(b))
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("invalid access-token file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	return token, nil
}
