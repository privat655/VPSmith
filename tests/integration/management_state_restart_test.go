package integration_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestStudioRestartPreservesManagementState(t *testing.T) {
	ctx := context.Background()
	repo := repositoryRoot(t)
	binary := filepath.Join(t.TempDir(), "vpsmith-studio")
	root := t.TempDir()
	state := filepath.Join(root, "state")
	sources := filepath.Join(root, "sources")
	backups := filepath.Join(root, "backups")
	for _, dir := range []string{state, sources, backups} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	store, err := managementstate.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	targetID, err := managementstate.NewTargetID()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		return change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "203.0.113.30", SSHUser: "dev", SSHTrust: managementstate.TrustConfirmed})
	}); err != nil {
		t.Fatal(err)
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	ldflags := strings.Join([]string{
		"-X", "main.version=0.1.0-dev.1",
		"-X", "main.revision=restart-integration-test",
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

	startAndStopStudio(t, binary, repo)
	startAndStopStudio(t, binary, repo)

	reopened, err := managementstate.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Targets) != 1 || after.Targets[0].ID != targetID {
		t.Fatalf("target state lost across Studio restart: %#v", after.Targets)
	}
	if len(before.Targets) != len(after.Targets) || before.Targets[0] != after.Targets[0] {
		t.Fatalf("management state changed across Studio restart\nbefore=%#v\nafter=%#v", before.Targets, after.Targets)
	}
}

func startAndStopStudio(t *testing.T, binary, repo string) {
	t.Helper()
	probe, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	command := exec.Command(binary, "serve")
	command.Dir = repo
	command.Stdout = probe
	command.Stderr = probe
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waitForHealth(t)
	if err := command.Process.Signal(os.Interrupt); err != nil {
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("Studio process shutdown failed: %v", err)
	}
}
