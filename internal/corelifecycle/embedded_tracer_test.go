package corelifecycle

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

type embeddedTracerInspector struct {
	observed managementstate.ObservedState
}

func (i embeddedTracerInspector) Inspect(context.Context, managementstate.TargetID) (managementstate.ObservedState, error) {
	return i.observed, nil
}

type embeddedTracerRegistry struct{}

func (embeddedTracerRegistry) Resolve(_ context.Context, ref string) (string, error) {
	if strings.Contains(ref, "authelia") {
		return "sha256:" + strings.Repeat("b", 64), nil
	}
	return "sha256:" + strings.Repeat("a", 64), nil
}

type embeddedTracerTarget struct{}

func (embeddedTracerTarget) Upload(context.Context, string, executionbundle.Bundle) error { return nil }
func (embeddedTracerTarget) Start(context.Context, string, execution.StartRequest) error  { return nil }
func (embeddedTracerTarget) Observe(context.Context, string, string) (execution.Observation, error) {
	return execution.Observation{}, nil
}
func (embeddedTracerTarget) SendSecrets(context.Context, string, string, []execution.SecretValue) error {
	return nil
}

type embeddedTracerSecrets struct{}

func (embeddedTracerSecrets) Resolve(context.Context, string, func([]byte) error) error { return nil }

type embeddedTracerHistory struct{}

func (embeddedTracerHistory) RegisterBundle(context.Context, execution.Run) error { return nil }
func (embeddedTracerHistory) Finished(context.Context, execution.Run, execution.Proof) error {
	return nil
}

func TestEmbeddedCorePreparesInstallThroughCanonicalLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	targetID := managementstate.TargetID("target_step9_tracer")
	var secretRefs managementstate.CoreSecretReferences
	if err := state.Change(ctx, func(change *managementstate.Change) error {
		if err := change.CreateTarget(managementstate.TargetRegistration{
			ID: targetID, Address: "192.0.2.10", SSHUser: "vpsmith", SSHTrust: managementstate.TrustConfirmed,
		}); err != nil {
			return err
		}
		create := func(name string) (managementstate.SecretID, error) {
			id, err := change.CreateSecret(name, managementstate.SecretGenerated)
			if err != nil {
				return "", err
			}
			if err := change.SetSecret(id, []byte("test-only-secret-material-"+name)); err != nil {
				return "", err
			}
			return id, nil
		}
		if secretRefs.AutheliaSession, err = create("authelia-session"); err != nil {
			return err
		}
		if secretRefs.AutheliaStorage, err = create("authelia-storage"); err != nil {
			return err
		}
		if secretRefs.AutheliaResetPassword, err = create("authelia-reset-password"); err != nil {
			return err
		}
		if secretRefs.AutheliaUsersDatabase, err = create("authelia-users-database"); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	embeddedRoot, err := filepath.Abs(filepath.Join("..", "..", "embedded"))
	if err != nil {
		t.Fatal(err)
	}
	sources, err := sourcelibrary.New(filepath.Join(root, "sources"), embeddedRoot, state, sourcelibrary.NewGithubRemote())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sources.ImportEmbedded(ctx); err != nil {
		t.Fatal(err)
	}
	bundles, err := executionbundle.NewAssembler(filepath.Join(root, "bundles"))
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := deployment.New(embeddedTracerRegistry{}, bundles)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := execution.New(embeddedTracerTarget{}, embeddedTracerSecrets{}, embeddedTracerHistory{}, execution.Options{})
	if err != nil {
		t.Fatal(err)
	}
	backups, err := backuprestore.New(filepath.Join(root, "backups"), filepath.Join(root, "scratch"), state)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := targetgateway.New(state, filepath.Join(root, "ssh"))
	if err != nil {
		t.Fatal(err)
	}
	storage, err := targetgateway.NewStorageBackupTarget(gateway)
	if err != nil {
		t.Fatal(err)
	}
	observed := managementstate.ObservedState{
		Host: managementstate.HostObservedState{
			Reachable: true,
			SSH:       true,
			OSID:      "ubuntu",
			OSVersion: "24.04",
			Kernel:    "6.8.0-test",
			RootFilesystem: managementstate.FilesystemObservedState{
				TotalBytes: 40 << 30, AvailableBytes: 30 << 30,
			},
			Memory: managementstate.MemoryObservedState{TotalBytes: 2 << 30, AvailableBytes: 1 << 30},
			PrimaryHardening: managementstate.PrimaryHardeningObservedState{
				RootPasswordLocked:       true,
				SSHConfigValid:           true,
				UFWActive:                true,
				UFWUnexpectedPublicAllow: false,
				Fail2banSSHActive:        true,
				Fail2banRecidiveActive:   true,
			},
		},
		CloudInit: managementstate.CloudInitObservedState{Present: true, Status: "ok"},
	}
	lifecycle, err := New(state, sources, embeddedTracerInspector{observed: observed}, compiler, executor, backups, storage)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle.dns = dnsResolverStub{ips: []net.IP{net.ParseIP("192.0.2.10")}}
	prepared, err := lifecycle.PrepareInstall(ctx, PrepareRequest{
		TargetID: targetID,
		Configuration: CoreConfiguration{
			Domain: "example.com", ACMEEmail: "ops@example.com", Secrets: secretRefs,
		},
		Swap: managementstate.SwapDesiredState{Mode: "none"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.DesiredCore.SourceID == "" || prepared.DesiredCore.Version != "0.1.0" {
		t.Fatalf("unexpected embedded Core identity: %#v", prepared.DesiredCore)
	}
	if prepared.Operation.CoreContract != "1" {
		t.Fatalf("unexpected core_contract %q", prepared.Operation.CoreContract)
	}
	manifest := prepared.Operation.Bundle.Manifest
	if len(manifest.Sources) != 1 || manifest.Sources[0].ID != string(prepared.DesiredCore.SourceID) {
		t.Fatalf("bundle did not freeze canonical embedded Core source: %#v", manifest.Sources)
	}
	if len(manifest.Images) != 2 {
		t.Fatalf("bundle did not freeze Caddy and Authelia image identities: %#v", manifest.Images)
	}
	if len(manifest.Actions) != 1 || manifest.Actions[0].ID != "core-install" {
		t.Fatalf("bundle did not carry real embedded Core install action: %#v", manifest.Actions)
	}
	if len(manifest.Artifacts) == 0 {
		t.Fatal("Core install bundle must contain compiler-generated desired state")
	}
}
