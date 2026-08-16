package executionbundle

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func baseInput() Input {
	return Input{
		Kind: Installation, TargetID: "target_1", SubjectKind: "module", SubjectID: "module-inst_1", SubjectIdentity: "n8n", PackageID: "pkg_1", PackageSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Version: "2.3.0",
		Sources:       []SourceIdentity{{Kind: "module", ID: "source_1", Version: "2.3.0", GitCommit: "abc123", PackageSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		Images:        []ImageIdentity{{Name: "app", Ref: "docker.io/n8nio/n8n:2.3.0", Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
		Files:         []File{{Path: "artifacts/app.container", TargetPath: "/var/lib/vpsmith/generated/app.container", Mode: 0o444, Data: []byte("[Container]\n")}},
		Actions:       []File{{Path: "actions/validate.sh", Mode: 0o555, Data: []byte("#!/bin/sh\nexit 0\n")}},
		ActionIDs:     []string{"validate"},
		Secrets:       []SecretReference{{SecretID: "secret_1", Container: "app", Delivery: "environment", Target: "N8N_KEY"}},
		Preconditions: []Precondition{{Kind: "target", Subject: "target_1", Expected: "present"}},
		ExpectedPost:  map[string]any{"version": "2.3.0"},
		Validations:   []ValidationSpec{{ID: "validate", ReadOnly: true}},
		Steps:         []Step{{ID: "write", Kind: "apply-artifact", Artifact: "artifacts/app.container", Mutating: true}, {ID: "validate", Kind: "action", Action: "validate", Mutating: false}},
	}
}

func TestAssemblerDeterministicAndImmutable(t *testing.T) {
	root := t.TempDir()
	a, err := NewAssembler(root)
	if err != nil {
		t.Fatal(err)
	}
	in := baseInput()
	first, err := a.Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.SHA256 != second.SHA256 || !bytes.Equal(first.Bytes, second.Bytes) {
		t.Fatal("same input did not produce byte-identical bundle")
	}
	stored, err := os.ReadFile(filepath.Join(root, first.ID+".tar"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, first.Bytes) {
		t.Fatal("stored bytes differ from returned bundle")
	}
}

func TestAssemblerSemanticOrderingDoesNotChangeBundle(t *testing.T) {
	root := t.TempDir()
	a, _ := NewAssembler(root)
	aIn := baseInput()
	bIn := baseInput()
	bIn.Images = append([]ImageIdentity{{Name: "zzz", Ref: "repo/x:1.0", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}, bIn.Images...)
	aIn.Images = append(aIn.Images, ImageIdentity{Name: "zzz", Ref: "repo/x:1.0", Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"})
	one, err := a.Assemble(aIn)
	if err != nil {
		t.Fatal(err)
	}
	two, err := a.Assemble(bIn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.Bytes, two.Bytes) {
		t.Fatal("set-like ordering changed canonical bundle")
	}
}

func TestAssemblerRelevantChangeChangesHash(t *testing.T) {
	a, _ := NewAssembler(t.TempDir())
	in := baseInput()
	one, _ := a.Assemble(in)
	in.Files[0].Data = []byte("[Container]\nMemory=1G\n")
	two, err := a.Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if one.SHA256 == two.SHA256 || one.ID == two.ID {
		t.Fatal("relevant artifact change did not change identity")
	}
}

func TestAssemblerRejectsMutatingValidationBundle(t *testing.T) {
	a, _ := NewAssembler(t.TempDir())
	in := baseInput()
	in.Kind = Validation
	if _, err := a.Assemble(in); err == nil {
		t.Fatal("expected validation mutation rejection")
	}
}

func TestBundleNeverContainsSecretPlaintext(t *testing.T) {
	a, _ := NewAssembler(t.TempDir())
	in := baseInput()
	secret := []byte("super-secret-test-value")
	bundle, err := a.Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bundle.Bytes, secret) {
		t.Fatal("secret plaintext leaked into bundle")
	}
}

func TestHistoricalBundleCannotBeOverwritten(t *testing.T) {
	root := t.TempDir()
	a, _ := NewAssembler(root)
	in := baseInput()
	b, err := a.Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, b.ID+".tar")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Assemble(in); err == nil {
		t.Fatal("expected immutable-store conflict")
	}
}

func TestVerifyReadsManifestFromHashedBundleBytes(t *testing.T) {
	a, _ := NewAssembler(t.TempDir())
	bundle, err := a.Assemble(baseInput())
	if err != nil {
		t.Fatal(err)
	}
	bundle.Manifest.Runner.Path = "actions/validate.sh"
	bundle.Manifest.Runner.SHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	manifest, err := Verify(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Runner.Path != "runtime/runner.py" || manifest.Runner.SHA256 == bundle.Manifest.Runner.SHA256 {
		t.Fatalf("verify trusted mutable Bundle.Manifest instead of bundle bytes: %#v", manifest.Runner)
	}
}

func TestVerifyRejectsTamperedBundleBytes(t *testing.T) {
	a, _ := NewAssembler(t.TempDir())
	bundle, err := a.Assemble(baseInput())
	if err != nil {
		t.Fatal(err)
	}
	bundle.Bytes[len(bundle.Bytes)/2] ^= 0x01
	if _, err := Verify(bundle); err == nil {
		t.Fatal("expected tampered bundle rejection")
	}
}
