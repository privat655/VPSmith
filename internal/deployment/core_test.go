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
		"core.json": &fstest.MapFile{Data: []byte(`{"core_version":"1.0.0","core_contract":"1.0","images":{"caddy":{"ref":"` + caddyTestRef + `"},"authelia":{"ref":"` + autheliaTestRef + `"}}}`)},
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
	if len(prepared.FrozenSources) != 1 || prepared.FrozenSources[0].SourceID != req.Source.SourceID || prepared.FrozenSources[0].PackageSHA256 != req.Source.PackageSHA256 {
		t.Fatalf("Core source was not frozen exactly: %#v", prepared.FrozenSources)
	}
	if len(prepared.Artifacts) != 1 || prepared.Artifacts[0].TargetPath != coreDesiredTarget {
		t.Fatalf("expected one compiler-generated Core desired artifact: %#v", prepared.Artifacts)
	}
	manifest := prepared.Bundle.Manifest
	if manifest.PackageSHA256 != req.Source.PackageSHA256 || len(manifest.Sources) != 1 || manifest.Sources[0].ID != req.Source.SourceID {
		t.Fatalf("bundle lost Core source identity: %#v", manifest)
	}
	if len(manifest.Images) != 2 || len(prepared.ImageDigests) != 2 {
		t.Fatalf("Core image identities were not frozen: %#v", manifest.Images)
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
