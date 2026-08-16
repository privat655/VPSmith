package managementstate

import (
	"context"
	"strings"
	"testing"
)

func TestSourceStateKeepsImmutableArtifactsAndWorkspaceBases(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	artifactID, err := NewSourceSnapshotID()
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, err := NewSourceWorkspaceID()
	if err != nil {
		t.Fatal(err)
	}
	artifact := SourceArtifact{
		ID: artifactID, Kind: SourceCore, Version: "1.0.0",
		SHA256: strings.Repeat("a", 64), StorageRef: "snapshots/sha256/" + strings.Repeat("a", 64),
	}
	workspace := SourceWorkspace{
		ID: workspaceID, Kind: SourceCore, BaseSourceID: artifactID,
		CurrentSHA256: strings.Repeat("b", 64), StorageRef: "workspaces/" + string(workspaceID),
	}
	if err := store.Change(ctx, func(change *Change) error {
		if err := change.RegisterSourceArtifact(artifact); err != nil {
			return err
		}
		return change.CreateSourceWorkspace(workspace)
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE source_artifacts SET sha256=? WHERE id=?`, strings.Repeat("c", 64), artifactID); err == nil {
		t.Fatal("immutable source artifact accepted direct update")
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM source_artifacts WHERE id=?`, artifactID); err == nil {
		t.Fatal("immutable source artifact accepted direct delete")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE source_workspaces SET base_source_id=? WHERE id=?`, "different", workspaceID); err == nil {
		t.Fatal("workspace accepted base source replacement")
	}
	if err := store.Change(ctx, func(change *Change) error {
		return change.UpdateSourceWorkspaceCurrent(workspaceID, strings.Repeat("d", 64))
	}); err != nil {
		t.Fatal(err)
	}
	state, err := store.Sources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Artifacts) != 1 || state.Artifacts[0].SHA256 != artifact.SHA256 {
		t.Fatalf("artifact identity changed: %#v", state.Artifacts)
	}
	if len(state.Workspaces) != 1 || state.Workspaces[0].BaseSourceID != artifactID || state.Workspaces[0].CurrentSHA256 != strings.Repeat("d", 64) {
		t.Fatalf("workspace state unexpected: %#v", state.Workspaces)
	}
}

func TestCustomModuleGithubStoresOnlyPATReferenceAndProtectsIt(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const material = "github_pat_secret_material_must_not_leak"
	var secretID SecretID
	if err := store.Change(ctx, func(change *Change) error {
		var err error
		secretID, err = change.CreateSecret("custom-module-github-pat", SecretUser)
		if err != nil {
			return err
		}
		if err := change.SetSecret(secretID, []byte(material)); err != nil {
			return err
		}
		return change.ConfigureCustomModuleGithub(CustomModuleGithubConfig{
			Owner: "example", Repository: "custom-modules", Ref: "main", PATSecretID: secretID,
		})
	}); err != nil {
		t.Fatal(err)
	}
	state, err := store.Sources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.CustomModuleGithub == nil || state.CustomModuleGithub.PATSecretID != secretID {
		t.Fatalf("PAT reference missing: %#v", state.CustomModuleGithub)
	}
	if strings.Contains(strings.TrimSpace(strings.Join([]string{
		state.CustomModuleGithub.Owner,
		state.CustomModuleGithub.Repository,
		state.CustomModuleGithub.Ref,
		string(state.CustomModuleGithub.PATSecretID),
	}, "|")), material) {
		t.Fatal("plaintext PAT leaked into normal source state")
	}
	if err := store.Change(ctx, func(change *Change) error { return change.DeleteSecret(secretID) }); err == nil {
		t.Fatal("referenced Custom Module Github PAT was deletable")
	}
}
