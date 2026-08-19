//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracesleuth/internal/catalog"
	"tracesleuth/internal/event"
	"tracesleuth/internal/exec"
	"tracesleuth/internal/service"
)

// The daemon accepts a socket connection, derives identity from the peer's
// credentials, and serves the MCP surface — an open_investigation is attributed
// to this process's own user, not to any client-supplied label.
func TestDaemonServesOverSocketWithPeerIdentity(t *testing.T) {
	svc, err := service.New(service.Config{
		DataDir: t.TempDir(), Host: "test-host", Executor: exec.NewMock(), Catalog: catalog.Default(),
		CaptureEnv: func() event.Environment { return event.Environment{Arch: "amd64"} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })

	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := listenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serve(ln, svc, "test-host")

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)

	// initialize
	send(t, conn, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	readResult(t, r)

	// open, trying to spoof identity — the daemon must ignore it in favour of the
	// kernel-attested peer identity (this test's own user).
	send(t, conn, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_investigation","arguments":{"hypothesis":"h","identity":"root@spoof"}}}`)
	text := toolText(t, readResult(t, r))

	me, _ := user.Current()
	if strings.Contains(text, "root@spoof") {
		t.Fatalf("client-supplied identity honored over peer credentials:\n%s", text)
	}
	if !strings.Contains(text, "as "+me.Username) {
		t.Fatalf("expected identity %q from peer credentials:\n%s", me.Username, text)
	}
}

func send(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
}

func readResult(t *testing.T, r *bufio.Reader) map[string]any {
	t.Helper()
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode %q: %v", line, err)
	}
	return resp.Result
}

func toolText(t *testing.T, result map[string]any) string {
	t.Helper()
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %v", result)
	}
	return content[0].(map[string]any)["text"].(string)
}
