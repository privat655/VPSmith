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
	req.BackupRef = "backup-core-test"
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
	if manifest.BackupRef != req.BackupRef {
		t.Fatalf("bundle lost verified backup ref: got=%q want=%q", manifest.BackupRef, req.BackupRef)
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
	if got := prepared.ImageDigests["caddy"]; got != locks["caddy"].Digest {
		t.Fatalf("caddy digest=%q want=%q", got, locks["caddy"].Digest)
	}
	if got := prepared.ImageDigests["authelia"]; got != locks["authelia"].Digest {
		t.Fatalf("authelia digest=%q want=%q", got, locks["authelia"].Digest)
	}
}
