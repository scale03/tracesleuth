// Command tracesleuthd is the long-lived TraceSleuth daemon. It owns the data
// directory (the JSONL audit log and the SQLite index) and serves the MCP
// surface over a Unix socket: an agent reaches it through the ephemeral
// tracesleuth-mcp shim (launched over ssh), which relays stdio to this socket.
// Identity is the connecting peer's kernel-attested uid (SO_PEERCRED), so the
// caller is exactly the user their ssh session authenticated as.
//
// It also exposes an HTTP endpoint for health (/healthz) and, once wired,
// Prometheus metrics (/metrics).
//
// Config (flags override environment):
//
//	-socket   Unix socket to listen on         (TRACESLEUTH_SOCKET)
//	-http     health/metrics listen address    (TRACESLEUTH_HTTP, default :9464)
//	-data     data directory                   (TRACESLEUTH_DATA, default ./data)
//	-host     host label on investigations     (TRACESLEUTH_HOST, default hostname)
//
// Catalog and policy load from TRACESLEUTH_CATALOG / TRACESLEUTH_POLICY when set,
// otherwise from the built-ins compiled into the binary.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"tracesleuth/internal/mcp"
	"tracesleuth/internal/metrics"
	"tracesleuth/internal/service"
	"tracesleuth/internal/transport"
)

const defaultSocket = "/run/tracesleuth/tracesleuth.sock"

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("tracesleuthd: ")

	socket := flag.String("socket", env("TRACESLEUTH_SOCKET", defaultSocket), "Unix socket to listen on")
	httpAddr := flag.String("http", env("TRACESLEUTH_HTTP", ":9464"), "health/metrics HTTP listen address")
	data := flag.String("data", env("TRACESLEUTH_DATA", "./data"), "data directory")
	host := flag.String("host", env("TRACESLEUTH_HOST", hostname()), "host label recorded on investigations")
	flag.Parse()

	if !transport.PeerCredsSupported() {
		log.Fatal("this platform cannot read peer credentials; tracesleuthd requires Linux")
	}

	cat, engine, err := service.PolicyFromEnv()
	if err != nil {
		log.Fatalf("policy: %v", err)
	}
	met := metrics.New()
	svc, err := service.New(service.Config{DataDir: *data, Host: *host, Catalog: cat, Policy: engine, Metrics: met})
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	defer svc.Close()
	log.Printf("policy bundle %s, data=%s host=%s", cat.BundleVersion, *data, *host)

	ln, err := listenUnix(*socket)
	if err != nil {
		log.Fatalf("listen %s: %v", *socket, err)
	}
	defer ln.Close()
	log.Printf("listening on unix://%s", *socket)

	httpSrv := &http.Server{Addr: *httpAddr, Handler: httpMux(met)}
	go func() {
		log.Printf("health/metrics on http://%s", *httpAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http server: %v", err)
		}
	}()

	// Shut down cleanly on signal: stop accepting, drain HTTP, close the socket.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Print("shutting down")
		ln.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		httpSrv.Shutdown(ctx)
	}()

	serve(ln, svc, *host)
}

// serve accepts connections until the listener is closed, handling each on its
// own goroutine so a slow probe never blocks another caller.
func serve(ln *net.UnixListener, svc *service.Service, host string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // shutting down
			}
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn.(*net.UnixConn), svc, host)
	}
}

// handleConn resolves the peer's identity from its kernel credentials and serves
// the MCP surface for the life of the connection. A connection whose identity
// can't be established is refused — the daemon never invents a caller.
func handleConn(conn *net.UnixConn, svc *service.Service, host string) {
	defer conn.Close()
	id, err := transport.PeerIdentity(conn)
	if err != nil {
		log.Printf("refusing connection: cannot resolve peer identity: %v", err)
		return
	}
	log.Printf("connection from %s", id.Name)
	srv := mcp.NewServer(svc, id, true, host)
	if err := srv.Serve(conn, conn); err != nil {
		log.Printf("serve (%s): %v", id.Name, err)
	}
}

func httpMux(met *metrics.Prometheus) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok\n"))
	})
	mux.Handle("/metrics", met.Handler())
	return mux
}

// listenUnix binds the socket, replacing a stale file left by an unclean exit,
// and restricts it to owner+group (identity is still enforced per-connection).
func listenUnix(path string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
