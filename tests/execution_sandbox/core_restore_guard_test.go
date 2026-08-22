//go:build execution_sandbox

package execution_sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/executionstate"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

func TestCoreRestoreRequiresVerifiedStagingOnRealSSHSystemdTarget(t *testing.T) {
	if os.Getenv("VPSMITH_EXECUTION_SANDBOX") != "1" {
		t.Skip("execution sandbox is opt-in")
	}
	ctx := context.Background()
	image := "vpsmith-core-restore-guard-sandbox:" + fmt.Sprint(os.Getpid())
	run(t, "docker", "build", "-f", "tests/execution_sandbox/Containerfile", "-t", image, ".")
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", image).Run() })
	cid := strings.TrimSpace(run(t, "docker", "run", "-d", "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-p", "127.0.0.1::22", image))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", cid).Run() })
	portLine := strings.TrimSpace(run(t, "docker", "port", cid, "22/tcp"))
	address := portLine
	if i := strings.LastIndex(portLine, ":"); i >= 0 {
		address = "127.0.0.1:" + portLine[i+1:]
	}
	waitTCP(t, address)
	waitCommand(t, 20*time.Second, func() bool {
		return exec.Command("docker", "exec", cid, "systemctl", "is-active", "--quiet", "ssh.service").Run() == nil
	}, "sshd did not become active")

	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	targetID := managementstate.TargetID("target-core-restore-guard")
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		return change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: address, SSHUser: "dev", SSHTrust: managementstate.TrustUnknown})
	}); err != nil {
		t.Fatal(err)
	}
	gateway, err := targetgateway.New(store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := gateway.EnsureIdentity(ctx, targetID)
	if err != nil {
		t.Fatal(err)
	}
	dockerInput(t, cid, []byte(identity.PublicKey+"\n"), "sh", "-c", "cat >/home/dev/.ssh/authorized_keys && chown dev:dev /home/dev/.ssh/authorized_keys && chmod 0600 /home/dev/.ssh/authorized_keys")
	observedKey, err := gateway.ObserveHostKey(ctx, targetID)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, targetID, observedKey); err != nil {
		t.Fatal(err)
	}

	executionTarget, err := targetgateway.NewExecutionTarget(gateway)
	if err != nil {
		t.Fatal(err)
	}
	history, err := executionstate.New(store)
	if err != nil {
		t.Fatal(err)
	}
	assembler, err := executionbundle.NewAssembler(filepath.Join(t.TempDir(), "bundles"))
	if err != nil {
		t.Fatal(err)
	}
	managedPath := "/var/tmp/vpsmith-core-restore-guard/managed.txt"
	managedData := []byte("restored\n")
	bundle := assemble(t, assembler, executionbundle.Input{
		Kind:            executionbundle.Migration,
		TargetID:        string(targetID),
		SubjectKind:     "core",
		SubjectID:       "core",
		SubjectIdentity: "core-restore-test",
		PackageSHA256:   strings.Repeat("a", 64),
		Version:         "1.0.0",
		Directories:     []executionbundle.Directory{{Path: "/var/tmp/vpsmith-core-restore-guard", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o755}},
		Files:           []executionbundle.File{{Path: "generated/managed.txt", TargetPath: managedPath, Mode: 0o644, Data: managedData}},
		Actions:         []executionbundle.File{{Path: "actions/restore.sh", Mode: 0o500, Data: []byte("#!/bin/sh\nset -eu\nexit 0\n")}},
		ActionIDs:       []string{"core-restore"},
		Preconditions:   []executionbundle.Precondition{{Kind: "target", Subject: string(targetID), Expected: "same-target"}},
		ExpectedPost:    map[string]any{"artifacts": map[string]string{managedPath: digest(managedData)}},
		Steps: []executionbundle.Step{
			{ID: "apply:managed", Kind: "apply-artifact", Artifact: "generated/managed.txt", Mutating: true},
			{ID: "core-restore", Kind: "action", Action: "core-restore", Mutating: true},
		},
	})

	first := executor(t, executionTarget, history, "run_core_restore_unstaged")
	if _, err := first.ExecuteVerifiedCoreRestore(ctx, string(targetID), bundle); err == nil || !strings.Contains(err.Error(), "execution failed") {
		t.Fatalf("unstaged Core restore error=%v", err)
	}
	if dockerExists(t, cid, managedPath) {
		t.Fatal("unstaged Core restore mutated target before staging guard")
	}

	storage, err := targetgateway.NewStorageBackupTarget(gateway)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified-restore-payload\n")
	if err := storage.StageCoreRestorePayload(ctx, string(targetID), bundle.ID, bytes.NewReader(payload), digest(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = storage.CleanupCoreRestorePayload(context.Background(), string(targetID), bundle.ID) })

	second := executor(t, executionTarget, history, "run_core_restore_staged")
	result, err := second.ExecuteVerifiedCoreRestore(ctx, string(targetID), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != execution.StatusSuccess {
		t.Fatalf("staged Core restore status=%s", result.Status)
	}
	if got := dockerRead(t, cid, managedPath); got != string(managedData) {
		t.Fatalf("staged Core restore managed file=%q", got)
	}
	if err := storage.CleanupCoreRestorePayload(ctx, string(targetID), bundle.ID); err != nil {
		t.Fatal(err)
	}
}
