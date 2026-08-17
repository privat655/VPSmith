package bootstrap

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

type rejectingRegistry struct{}

func (rejectingRegistry) Resolve(context.Context, string) (string, error) {
	return "", errors.New("registry must not be used for Cloud-init")
}

func newTestCoordinator(t *testing.T) (*Coordinator, *managementstate.Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	embeddedRoot, err := filepath.Abs(filepath.Join("..", "..", "embedded"))
	if err != nil {
		t.Fatal(err)
	}
	sources, err := sourcelibrary.New(t.TempDir(), embeddedRoot, state, sourcelibrary.NewGithubRemote())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sources.ImportEmbedded(ctx); err != nil {
		t.Fatal(err)
	}
	gateway, err := targetgateway.New(state, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := executionbundle.NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := deployment.New(rejectingRegistry{}, bundles)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := New(state, gateway, compiler, sources)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, state, ctx
}

func TestPrepareNewTargetUsesReleasedCloudInitSnapshotAndPerTargetIdentity(t *testing.T) {
	coordinator, state, ctx := newTestCoordinator(t)
	defer state.Close()
	prepared, err := coordinator.PrepareNewTarget(ctx, NewTargetRequest{Hostname: "vps-a", Timezone: "Etc/UTC", Administrator: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.CloudInitSource.Kind != managementstate.SourceCloudInit || prepared.CloudInitSource.Version != "0.1.0" {
		t.Fatalf("unexpected source: %#v", prepared.CloudInitSource)
	}
	if prepared.CloudInit.Identity != prepared.CloudInitSource.Version {
		t.Fatalf("artifact identity=%q source version=%q", prepared.CloudInit.Identity, prepared.CloudInitSource.Version)
	}
	keyFields := strings.Fields(prepared.SSHIdentity.PublicKey)
	if len(keyFields) < 2 || !strings.Contains(string(prepared.CloudInit.Bytes), keyFields[0]+" "+keyFields[1]) {
		t.Fatal("generated per-target public key material is not in Cloud-init")
	}
	if strings.Contains(string(prepared.CloudInit.Bytes), "OPENSSH PRIVATE KEY") {
		t.Fatal("private key leaked into Cloud-init")
	}
	snapshot, err := state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Targets) != 1 {
		t.Fatalf("targets=%d", len(snapshot.Targets))
	}
	desired := snapshot.Targets[0].Desired.CloudInit
	if desired.DefinitionVersion != prepared.CloudInitSource.Version || desired.DefinitionSHA256 != prepared.CloudInit.SHA256 {
		t.Fatalf("desired Cloud-init is not bound to rendered released source: %#v", desired)
	}
}

func TestPrepareNewTargetRejectsInvalidInputBeforePersistentTargetCreation(t *testing.T) {
	coordinator, state, ctx := newTestCoordinator(t)
	defer state.Close()
	if _, err := coordinator.PrepareNewTarget(ctx, NewTargetRequest{Hostname: "Bad_Host", Timezone: "Etc/UTC", Administrator: "admin"}); err == nil {
		t.Fatal("invalid bootstrap input accepted")
	}
	snapshot, err := state.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Targets) != 0 || len(snapshot.Secrets) != 0 {
		t.Fatalf("invalid bootstrap input left persistent target or identity state: %#v", snapshot)
	}
}
