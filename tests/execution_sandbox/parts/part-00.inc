//go:build execution_sandbox

package execution_sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/executionstate"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

const sandboxTargetID = managementstate.TargetID("target-sandbox")

func TestRealSSHSystemdExecutionProtocol(t *testing.T) {
	if os.Getenv("VPSMITH_EXECUTION_SANDBOX") != "1" {
		t.Skip("execution sandbox is opt-in")
	}
	ctx := context.Background()
	image := "vpsmith-execution-sandbox:" + fmt.Sprint(os.Getpid())
	run(t, "docker", "build", "-f", "tests/execution_sandbox/Containerfile", "-t", image, ".")
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", image).Run() })
	cid := strings.TrimSpace(run(t, "docker", "run", "-d", "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-p", "127.0.0.1::22", image))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", cid).Run() })
	portLine := strings.TrimSpace(run(t, "docker", "port", cid, "22/tcp"))
	address := strings.TrimPrefix(portLine, "0.0.0.0:")
	if strings.HasPrefix(address, "127.0.0.1:") {
		// already in the exact targetgateway form
	} else if i := strings.LastIndex(portLine, ":"); i >= 0 {
		address = "127.0.0.1:" + portLine[i+1:]
	}
	waitTCP(t, address)
	waitCommand(t, 20*time.Second, func() bool {
		cmd := exec.Command("docker", "exec", cid, "systemctl", "is-active", "--quiet", "ssh.service")
		return cmd.Run() == nil
	}, "sshd did not become active")

	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		return change.CreateTarget(managementstate.TargetRegistration{ID: sandboxTargetID, Address: address, SSHUser: "dev", SSHTrust: managementstate.TrustUnknown})
	}); err != nil {
		t.Fatal(err)
	}
	gateway, err := targetgateway.New(store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := gateway.EnsureIdentity(ctx, sandboxTargetID)
	if err != nil {
		t.Fatal(err)
	}
	dockerInput(t, cid, []byte(identity.PublicKey+"\n"), "sh", "-c", "cat >/home/dev/.ssh/authorized_keys && chown dev:dev /home/dev/.ssh/authorized_keys && chmod 0600 /home/dev/.ssh/authorized_keys")
	observedKey, err := gateway.ObserveHostKey(ctx, sandboxTargetID)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, sandboxTargetID, observedKey); err != nil {
		t.Fatal(err)
	}

	target, err := targetgateway.NewExecutionTarget(gateway)
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

	t.Run("first-core-run-promotes-immutable-history", func(t *testing.T) {
		path := "/var/tmp/vpsmith-sandbox/managed.txt"
		data := []byte("core-v1\n")
		bundle := assemble(t, assembler, executionbundle.Input{
			Kind: executionbundle.Installation, TargetID: string(sandboxTargetID), SubjectKind: "core", SubjectID: "core", SubjectIdentity: "core-v1", Version: "1.0.0",
			Directories:   []executionbundle.Directory{{Path: "/var/tmp/vpsmith-sandbox", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o755}},
			Files:         []executionbundle.File{{Path: "artifacts/managed.txt", TargetPath: path, Mode: 0o644, Data: data}},
			Preconditions: []executionbundle.Precondition{{Kind: "target", Subject: string(sandboxTargetID), Expected: "same-target"}},
			ExpectedPost:  map[string]any{"artifacts": map[string]string{path: digest(data)}},
			Steps:         []executionbundle.Step{{ID: "apply:managed", Kind: "apply-artifact", Artifact: "artifacts/managed.txt", Mutating: true}},
		})
		runResult, err := executor(t, target, history, "run_core_1").Execute(ctx, string(sandboxTargetID), bundle)
		if err != nil {
			t.Fatal(err)
		}
		if runResult.Status != execution.StatusSuccess {
			t.Fatalf("status=%s", runResult.Status)
		}
		if go