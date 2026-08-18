//go:build execution_sandbox

package execution_sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/executionstate"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

type validationRegistry struct{}

func (validationRegistry) Resolve(_ context.Context, ref string) (string, error) {
	if ref != "docker.io/example/validation:1.0.0" {
		return "", fmt.Errorf("unexpected image ref %s", ref)
	}
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
}

func TestCompilerGeneratedValidationUsesProductionExecutionPathAndCannotMutateHost(t *testing.T) {
	if os.Getenv("VPSMITH_EXECUTION_SANDBOX") != "1" {
		t.Skip("execution sandbox is opt-in")
	}
	ctx := context.Background()
	image := "vpsmith-execution-validation-sandbox:" + fmt.Sprint(os.Getpid())
	run(t, "docker", "build", "-f", "tests/execution_sandbox/Containerfile", "-t", image, ".")
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", image).Run() })
	cid := strings.TrimSpace(run(t, "docker", "run", "-d", "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-p", "127.0.0.1::22", image))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", cid).Run() })
	portLine := strings.TrimSpace(run(t, "docker", "port", cid, "22/tcp"))
	address := strings.TrimPrefix(portLine, "0.0.0.0:")
	if !strings.HasPrefix(address, "127.0.0.1:") {
		if i := strings.LastIndex(portLine, ":"); i >= 0 {
			address = "127.0.0.1:" + portLine[i+1:]
		}
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

	assembler, err := executionbundle.NewAssembler(filepath.Join(t.TempDir(), "compiled-bundles"))
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := deployment.New(validationRegistry{}, assembler)
	if err != nil {
		t.Fatal(err)
	}
	const instance = "validation-1"
	source := deployment.FrozenModuleSource{
		InstanceID:    instance,
		SourceID:      "source-validation-1",
		PackageID:     "pkg-validation-1",
		PackageSHA256: strings.Repeat("d", 64),
		PackageFS:     validationModulePackage(),
	}
	prepared, err := compiler.Prepare(ctx, deployment.Request{
		Operation:       deployment.Validate,
		TargetID:        string(sandboxTargetID),
		SubjectInstance: instance,
		DesiredModules:  []deployment.DesiredModule{{InstanceID: instance, Source: source}},
		Observed:        deployment.ObservedState{TargetID: string(sandboxTargetID)},
		CoreContract:    "1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Bundle.Kind != executionbundle.Validation || len(prepared.Bundle.Manifest.Steps) != 1 {
		t.Fatalf("compiled validation steps = %#v", prepared.Bundle.Manifest.Steps)
	}
	step := prepared.Bundle.Manifest.Steps[0]
	if step.Kind != "action" || step.Action != "validate" || step.Mutating {
		t.Fatalf("compiled validation step = %#v", step)
	}

	// Validation is intentionally non-mutating, so materialize the expected
	// generated artifacts as the already-installed target state. The operation
	// under test still travels through module.yaml -> Module Contract ->
	// Deployment Compiler -> immutable bundle -> Executor -> SSH -> systemd ->
	// bundle-local runner.
	for _, artifact := range prepared.Artifacts {
		command := "install -d -m 0755 " + sandboxShellQuote(filepath.Dir(artifact.TargetPath)) +
			" && cat > " + sandboxShellQuote(artifact.TargetPath) +
			fmt.Sprintf(" && chmod %04o ", artifact.Mode) + sandboxShellQuote(artifact.TargetPath)
		dockerInput(t, cid, artifact.Data, "sh", "-c", command)
	}

	for _, runID := range []string{"run_compiled_validation_1", "run_compiled_validation_2"} {
		result, err := executor(t, target, history, runID).Execute(ctx, string(sandboxTargetID), prepared.Bundle)
		if err != nil || result.Status != execution.StatusSuccess {
			t.Fatalf("compiled validation %s status=%s err=%v", runID, result.Status, err)
		}
	}
	for _, path := range []string{
		"/etc/vpsmith-validation-sudo-escape",
		"/home/dev/vpsmith-validation-home-escape",
		"/var/tmp/vpsmith-validation-tmp-escape",
	} {
		if dockerExists(t, cid, path) {
			t.Fatalf("validation escaped read-only action sandbox: %s", path)
		}
	}

	const owned = "/var/tmp/vpsmith-module-owned"
	run(t, "docker", "exec", cid, "install", "-d", "-m", "0755", "-o", "dev", "-g", "dev", owned)
	mutation := assemble(t, assembler, executionbundle.Input{
		Kind:                executionbundle.Migration,
		TargetID:            string(sandboxTargetID),
		SubjectKind:         "module",
		SubjectID:           instance,
		SubjectIdentity:     "validation-1.0.0",
		Version:             "1.0.0",
		Actions:             []executionbundle.File{{Path: "actions/mutate.sh", Mode: 0o555, Data: []byte("#!/bin/sh\nset -eu\nprintf owned > " + owned + "/changed\nif printf escaped > /etc/vpsmith-module-escape; then exit 73; fi\n")}},
		ActionIDs:           []string{"mutate"},
		ActionWritablePaths: []string{owned},
		Preconditions:       []executionbundle.Precondition{{Kind: "target", Subject: string(sandboxTargetID), Expected: "same-target"}},
		ExpectedPost:        map[string]any{"artifacts": map[string]string{}},
		Steps:               []executionbundle.Step{{ID: "action:mutate", Kind: "action", Action: "mutate", Mutating: true}},
	})
	result, err := executor(t, target, history, "run_module_mutation").Execute(ctx, string(sandboxTargetID), mutation)
	if err != nil || result.Status != execution.StatusSuccess {
		t.Fatalf("scoped module mutation status=%s err=%v", result.Status, err)
	}
	if got := dockerRead(t, cid, owned+"/changed"); got != "owned" {
		t.Fatalf("module-owned mutation = %q", got)
	}
	if dockerExists(t, cid, "/etc/vpsmith-module-escape") {
		t.Fatal("mutating module action escaped declared persistent storage")
	}
}

func validationModulePackage() fstest.MapFS {
	const moduleYAML = `module_id: validation
module_version: "1.0.0"
core_contract: "1.0"
images:
  app: {ref: docker.io/example/validation:1.0.0}
containers:
  - id: app
    image: app
    user: 1000
    userns: nomap
    capabilities: []
    mounts: []
    networks: []
    environment: {}
persistent_storage: []
secrets: []
resources: {memory_bytes: 134217728, cpu_quota_percent: 100, pids_limit: 64, tasks_max: 128}
networks: []
egress: []
public_routes: []
healthcheck: {type: tcp, container: app, port: 8080}
service_checks: []
validation_action: validate
interfaces: []
dependencies: []
actions:
  validate: actions/validate.sh
update_from: {}
uninstall: {delete_persistent_data: true, delete_secrets: true}
`
	const action = `#!/bin/sh
set -eu
test -r /etc/os-release
if printf escaped > /home/dev/vpsmith-validation-home-escape; then
  echo 'validation unexpectedly wrote administrator home' >&2
  exit 70
fi
if printf escaped > /var/tmp/vpsmith-validation-tmp-escape; then
  echo 'validation unexpectedly wrote host tmp' >&2
  exit 71
fi
if sudo -n sh -c 'printf escaped > /etc/vpsmith-validation-sudo-escape'; then
  echo 'validation unexpectedly inherited sudo privilege' >&2
  exit 72
fi
exit 0
`
	return fstest.MapFS{
		"module.yaml":         &fstest.MapFile{Data: []byte(moduleYAML)},
		"actions/validate.sh": &fstest.MapFile{Data: []byte(action)},
	}
}

func sandboxShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
