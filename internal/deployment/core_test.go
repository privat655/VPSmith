package deployment

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"
)

const caddyTestRef = "docker.io/library/caddy:2.10.2"
const autheliaTestRef = "ghcr.io/authelia/authelia:4.39.20"

func coreFS() fstest.MapFS {
	files := fstest.MapFS{
		"core.json":          &fstest.MapFile{Data: []byte(`{"core_version":"1.0.0","core_contract":"1.0","images":{"caddy":{"ref":"` + caddyTestRef + `"},"authelia":{"ref":"` + autheliaTestRef + `"}}}`)},
		"actions/runtime.sh": &fstest.MapFile{Data: []byte("#!/bin/sh\nset -eu\n")},
	}
	for _, operation := range []OperationKind{Install, Update, Reconfigure, Restore, Validate} {
		files["actions/"+string(operation)+".sh"] = &fstest.MapFile{Data: []byte("#!/bin/sh\nset -eu\nexit 0\n"), Mode: 0o755}
	}
	return files
}

func coreCompiler(t *testing.T) *Compiler {
	t.Helper()
	return newCompiler(t, caddyTestRef, autheliaTestRef)
}

func coreRequest(operation OperationKind) CoreRequest {
	return CoreRequest{
		Operation: operation,
		TargetID:  "target-1",
		AdminUser: "vpsmith",
		Domain:    "example.test",
		ACMEEmail: "admin@example.test",
		Secrets: CoreSecretIDs{
			AutheliaSession:       "secret-session",
			AutheliaStorage:       "secret-storage",
			AutheliaResetPassword: "secret-reset",
			AutheliaUsersDatabase: "secret-users",
		},
		Source: FrozenCoreSource{
			SourceID:      "source-core-1",
			Version:       "1.0.0",
			PackageSHA256: strings.Repeat("a", 64),
			PackageFS:     coreFS(),
		},
		SwapMode: "none",
	}
}

func TestPrepareCoreFreezesExactInstalledIdentityAndGeneratedDesiredState(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Update)
	req.ObservedCoreID = "source-core-old"
	req.ObservedCoreSHA256 = strings.Repeat("b", 64)
	req.BackupRequired = true
	req.SwapMode = "swapfile"
	req.SwapSizeGiB = 2
	req.EffectiveSwapBytes = 2 << 30
	req.ObservedArtifacts = map[string]string{coreDesiredTarget: strings.Repeat("c", 64)}

	prepared, err := compiler.PrepareCore(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.CoreContract != "1.0" {
		t.Fatalf("compiled Core contract=%q", prepared.CoreContract)
	}
	if len(prepared.FrozenSources) != 1 || prepared.FrozenSources[0].SourceID != req.Source.SourceID || prepared.FrozenSources[0].PackageSHA256 != req.Source.PackageSHA256 {
		t.Fatalf("Core source was not frozen exactly: %#v", prepared.FrozenSources)
	}
	foundDesired := false
	for _, generated := range prepared.Artifacts {
		if generated.TargetPath == coreDesiredTarget {
			foundDesired = true
			break
		}
	}
	if !foundDesired {
		t.Fatalf("compiler-generated Core desired artifact is missing: %#v", prepared.Artifacts)
	}
	manifest := prepared.Bundle.Manifest
	if manifest.PackageSHA256 != req.Source.PackageSHA256 || len(manifest.Sources) != 1 || manifest.Sources[0].ID != req.Source.SourceID {
		t.Fatalf("bundle lost Core source identity: %#v", manifest)
	}
	if len(manifest.Images) != 2 || len(prepared.ImageDigests) != 2 {
		t.Fatalf("Core image identities were not frozen: %#v", manifest.Images)
	}
	if len(manifest.Secrets) != 4 {
		t.Fatalf("Core Authelia secret references were not frozen: %#v", manifest.Secrets)
	}
	want := map[string]string{
		"core-source-id":      req.ObservedCoreID,
		"core-package-sha256": req.ObservedCoreSHA256,
		"artifact-sha256":     req.ObservedArtifacts[coreDesiredTarget],
	}
	for _, pre := range manifest.Preconditions {
		if expected, ok := want[pre.Kind]; ok && pre.Expected == expected {
			delete(want, pre.Kind)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing exact Core preconditions: %#v", want)
	}
}

func TestPrepareCoreRestoreUsesBackedUpImageLocksInsteadOfRegistryResolution(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Restore)
	req.ObservedCoreID = "source-core-newer"
	req.ObservedCoreSHA256 = strings.Repeat("b", 64)
	locks := map[string]FrozenCoreImage{
		"caddy":    {Ref: caddyTestRef, Digest: "sha256:" + strings.Repeat("d", 64)},
		"authelia": {Ref: autheliaTestRef, Digest: "sha256:" + strings.Repeat("e", 64)},
	}

	prepared, err := compiler.PrepareCoreRestore(context.Background(), req, locks)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, image := range prepared.Bundle.Manifest.Images {
		got[image.Name] = image.Digest
	}
	if got["caddy"] != locks["caddy"].Digest || got["authelia"] != locks["authelia"].Digest {
		t.Fatalf("restore did not preserve backed-up image locks: %#v", got)
	}
}

func TestPrepareCoreRestoreRejectsImageLockRefDriftAndNonRestoreUse(t *testing.T) {
	compiler := coreCompiler(t)
	locks := map[string]FrozenCoreImage{
		"caddy":    {Ref: "docker.io/library/caddy:moved", Digest: "sha256:" + strings.Repeat("d", 64)},
		"authelia": {Ref: autheliaTestRef, Digest: "sha256:" + strings.Repeat("e", 64)},
	}
	restore := coreRequest(Restore)
	restore.ObservedCoreID = "source-core-newer"
	restore.ObservedCoreSHA256 = strings.Repeat("b", 64)
	if _, err := compiler.PrepareCoreRestore(context.Background(), restore, locks); err == nil {
		t.Fatal("Core restore accepted image lock ref drift from frozen Core package")
	}

	update := coreRequest(Update)
	update.ObservedCoreID = "source-core-old"
	update.ObservedCoreSHA256 = strings.Repeat("b", 64)
	update.BackupRequired = true
	if _, err := compiler.PrepareCoreRestore(context.Background(), update, locks); err == nil {
		t.Fatal("non-restore Core operation accepted backed-up image locks")
	}
}

func TestPrepareCoreValidationCannotCarryMutation(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Validate)
	req.ObservedCoreID = req.Source.SourceID
	req.ObservedCoreSHA256 = req.Source.PackageSHA256

	prepared, err := compiler.PrepareCore(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.PlanRequired {
		t.Fatal("read-only validation must not require a mutation plan")
	}
	if len(prepared.Artifacts) != 0 || len(prepared.Bundle.Manifest.Artifacts) != 0 {
		t.Fatal("validation bundle must not contain generated target artifacts")
	}
	for _, step := range prepared.Bundle.Manifest.Steps {
		if step.Mutating || step.Kind == "apply-artifact" {
			t.Fatalf("validation bundle contains mutation: %#v", step)
		}
	}
}

func TestPrepareCoreUpdateRequiresVerifiedBackupFlagFromLifecycle(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Update)
	req.ObservedCoreID = "source-core-old"
	req.ObservedCoreSHA256 = strings.Repeat("b", 64)

	if _, err := compiler.PrepareCore(context.Background(), req); err == nil {
		t.Fatal("Core update without verified backup precondition must fail closed")
	}
}

func TestPrepareCoreRejectsDefinitionVersionMismatch(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Install)
	req.Source.Version = "2.0.0"
	if _, err := compiler.PrepareCore(context.Background(), req); err == nil {
		t.Fatal("Core definition/source version mismatch must fail closed")
	}
}

func TestPrepareCoreRejectsIncompleteConfiguration(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Install)
	req.Secrets.AutheliaSession = ""
	if _, err := compiler.PrepareCore(context.Background(), req); err == nil {
		t.Fatal("Core without complete Authelia secret references must fail closed")
	}
}

func TestCompileCoreDefinitionRejectsTrailingJSON(t *testing.T) {
	source := fstest.MapFS{
		"core.json": &fstest.MapFile{Data: []byte(`{"core_version":"1.0.0","core_contract":"1.0","images":{"caddy":{"ref":"caddy"},"authelia":{"ref":"authelia"}}} {}`)},
	}
	if _, err := compileCoreDefinition(source, "1.0.0"); err == nil {
		t.Fatal("trailing Core definition JSON must fail closed")
	}
}
