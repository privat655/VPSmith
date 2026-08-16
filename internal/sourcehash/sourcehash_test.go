package sourcehash

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTreeSHA256CanonicalPackageIdentity(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	writeFixture(t, first, "version: 1\n")
	writeFixture(t, second, "version: 1\n")
	if err := os.MkdirAll(filepath.Join(second, ".git", "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, ".git", "config"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(second, ".vscode"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, ".vscode", "settings.json"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, "module.yaml.swp"), []byte("ignored"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := TreeSHA256(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := TreeSHA256(second)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("path/noise changed canonical hash: %s != %s", a, b)
	}

	if err := os.WriteFile(filepath.Join(second, "module.yaml"), []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := TreeSHA256(second)
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Fatal("relevant content change did not change hash")
	}
}

func writeFixture(t *testing.T, root, module string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "actions"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "module.yaml"), []byte(module), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "actions", "migrate.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}
