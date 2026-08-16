package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/releaseinfo"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
	"github.com/privat655/VPSmith/internal/studio"
)

const listenAddress = "127.0.0.1:8787"

var (
	version         = "dev"
	revision        = "unknown"
	sourceDateEpoch = "0"
	embeddedRoot    = "/usr/share/vpsmith/embedded"
	stateDir        = "/var/lib/vpsmith/state"
	sourcesDir      = "/var/lib/vpsmith/sources"
	backupsDir      = "/var/lib/vpsmith/backups"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	if len(args) > 1 {
		return fmt.Errorf("unexpected arguments: %v", args[1:])
	}
	switch command {
	case "serve":
		return serve()
	case "healthcheck":
		return healthcheck()
	case "version":
		identity, err := loadIdentity()
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(identity)
	default:
		return fmt.Errorf("unknown command %q; expected serve, healthcheck, or version", command)
	}
}

func serve() error {
	identity, err := loadIdentity()
	if err != nil {
		return err
	}
	for _, mount := range []struct{ name, path string }{
		{name: "state", path: stateDir},
		{name: "sources", path: sourcesDir},
		{name: "backups", path: backupsDir},
	} {
		if err := requireWritableDirectory(mount.name, mount.path); err != nil {
			return err
		}
	}

	state, err := managementstate.Open(stateDir)
	if err != nil {
		return fmt.Errorf("open canonical management state: %w", err)
	}
	defer func() {
		if err := state.Close(); err != nil {
			log.Printf("ERROR: close management state: %v", err)
		}
	}()

	sources, err := sourcelibrary.New(sourcesDir, embeddedRoot, state, sourcelibrary.NewGithubRemote())
	if err != nil {
		return fmt.Errorf("open canonical source library: %w", err)
	}
	if _, err := sources.ImportEmbedded(context.Background()); err != nil {
		return fmt.Errorf("import embedded source snapshots: %w", err)
	}

	listener, err := net.Listen("tcp4", listenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddress, err)
	}
	defer listener.Close()
	if err := requireLoopbackListener(listener); err != nil {
		return err
	}

	server := &http.Server{
		Handler:           studio.Handler(identity),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	log.Printf("VPSmith Studio %s listening on http://%s", identity.Version, listenAddress)
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve VPSmith Studio: %w", err)
	case <-shutdownContext.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown VPSmith Studio: %w", err)
		}
		return nil
	}
}

func loadIdentity() (studio.BuildIdentity, error) {
	info, err := releaseinfo.Load(embeddedRoot)
	if err != nil {
		return studio.BuildIdentity{}, err
	}
	if info.Studio.Version != version {
		return studio.BuildIdentity{}, fmt.Errorf("studio version mismatch: binary=%s manifest=%s", version, info.Studio.Version)
	}
	return studio.BuildIdentity{Version: version, Revision: revision, BuiltAt: buildTime(sourceDateEpoch), Embedded: info.Embedded}, nil
}

func buildTime(epoch string) string {
	seconds, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil || seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func requireWritableDirectory(name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("persistent %s directory %s is unavailable: %w", name, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("persistent %s path %s is not a directory", name, path)
	}
	probe, err := os.CreateTemp(path, ".vpsmith-write-check-*")
	if err != nil {
		return fmt.Errorf("persistent %s directory %s must be writable: %w", name, path, err)
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		return fmt.Errorf("close persistent %s write probe: %w", name, err)
	}
	if err := os.Remove(probePath); err != nil {
		return fmt.Errorf("remove persistent %s write probe %s: %w", name, filepath.Base(probePath), err)
	}
	return nil
}

func requireLoopbackListener(listener net.Listener) error {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP == nil || !address.IP.IsLoopback() {
		return fmt.Errorf("refusing non-loopback VPSmith Studio listener %s", listener.Addr())
	}
	return nil
}

func healthcheck() error {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + listenAddress + "/healthz")
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned HTTP %d", response.StatusCode)
	}
	return nil
}
