package integration_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const studioAddress = "127.0.0.1:8787"

func TestStudioProcessListensOnlyOnLoopbackAndRequiresWritableMounts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("socket binding verification uses Linux /proc/net/tcp")
	}
	probe, err := net.Listen("tcp4", studioAddress)
	if err != nil {
		t.Skipf("port 8787 is already in use: %v", err)
	}
	_ = probe.Close()

	repo := repositoryRoot(t)
	binary := filepath.Join(t.TempDir(), "vpsmith-studio")
	state := filepath.Join(t.TempDir(), "state")
	sources := filepath.Join(t.TempDir(), "sources")
	backups := filepath.Join(t.TempDir(), "backups")
	for _, dir := range []string{state, sources, backups} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	ldflags := strings.Join([]string{
		"-X", "main.version=0.1.0-dev.1",
		"-X", "main.revision=integration-test",
		"-X", "main.sourceDateEpoch=1786816800",
		"-X", "main.embeddedRoot=" + filepath.Join(repo, "embedded"),
		"-X", "main.stateDir=" + state,
		"-X", "main.sourcesDir=" + sources,
		"-X", "main.backupsDir=" + backups,
	}, " ")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags, "-o", binary, "./cmd/vpsmith-studio")
	build.Dir = repo
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build studio: %v\n%s", err, output)
	}

	command := exec.Command(binary, "serve")
	command.Dir = repo
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		_, _ = command.Process.Wait()
	})

	waitForHealth(t)
	assertLoopbackOnly(t)

	response, err := http.Get("http://" + studioAddress + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var identity struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
	}
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		t.Fatal(err)
	}
	if identity.Version != "0.1.0-dev.1" || identity.Revision != "integration-test" {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestStudioProcessFailsWhenPersistentMountIsNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can bypass directory write permission checks")
	}
	repo := repositoryRoot(t)
	binary := filepath.Join(t.TempDir(), "vpsmith-studio")
	readOnly := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	writableA := t.TempDir()
	writableB := t.TempDir()
	ldflags := strings.Join([]string{
		"-X", "main.version=0.1.0-dev.1",
		"-X", "main.embeddedRoot=" + filepath.Join(repo, "embedded"),
		"-X", "main.stateDir=" + readOnly,
		"-X", "main.sourcesDir=" + writableA,
		"-X", "main.backupsDir=" + writableB,
	}, " ")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", ldflags, "-o", binary, "./cmd/vpsmith-studio")
	build.Dir = repo
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build studio: %v\n%s", err, output)
	}

	command := exec.Command(binary, "serve")
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "state") || !strings.Contains(string(output), "writable") {
		t.Fatalf("serve error = %v output=%q", err, output)
	}
}

func waitForHealth(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 250 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("http://" + studioAddress + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("studio did not become healthy")
}

func assertLoopbackOnly(t *testing.T) {
	t.Helper()
	portHex := fmt.Sprintf("%04X", 8787)
	foundLoopback := false
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 || !strings.EqualFold(parts[1], portHex) {
				continue
			}
			address := strings.ToUpper(parts[0])
			switch address {
			case "0100007F":
				foundLoopback = true
			case "00000000", "00000000000000000000000000000000":
				_ = file.Close()
				t.Fatalf("studio is listening on a wildcard address: %s", fields[1])
			default:
				_ = file.Close()
				t.Fatalf("studio is listening on a non-loopback address: %s", fields[1])
			}
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		_ = file.Close()
	}
	if !foundLoopback {
		t.Fatal("no 127.0.0.1 listener found for port 8787")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate integration test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
