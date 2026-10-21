package personal

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeUnixSocketClient(t *testing.T) {
	store, engine, _ := fixture(t, "monitor")
	ev := event("native-window-event", time.Now())
	if _, err := store.AddEvent(&ev); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	socket := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(dir, "access-token"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: NewLocalAPI(engine, token), ReadHeaderTimeout: time.Second}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		res, err := client.Get("http://localhost" + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Fatalf("browser asset exposed: %s", path)
		}
	}
	res, err := client.Get("http://localhost/api/events")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("unauthenticated IPC request accepted")
	}
	gjs, err := exec.LookPath("gjs")
	if err != nil {
		t.Skip("GJS is not installed; Unix API checks passed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, gjs, "-m", "../../desktop/app/client-test.js")
	cmd.Env = append(os.Environ(), "MEMOSHIELD_SOCKET="+socket, "XDG_STATE_HOME="+dir)
	// Client's default token path is under the memoshield state directory.
	if err := os.Mkdir(filepath.Join(dir, "memoshield"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memoshield", "access-token"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("GJS Unix client: %v\n%s", err, output)
	}
	if os.Getenv("MEMOSHIELD_UI_TEST") == "1" {
		ui := exec.CommandContext(ctx, gjs, "-m", "../../desktop/app/main.js")
		ui.Env = append(cmd.Env, "MEMOSHIELD_UI_SMOKE=1")
		if output, err := ui.CombinedOutput(); err != nil {
			t.Fatalf("GTK window: %v\n%s", err, output)
		}
	}
}
