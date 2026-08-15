package releaseinfo_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/releaseinfo"
)

func TestLoadReturnsVerifiedReleaseIdentity(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "cloud-init", "README.md", "cloud-init scaffold\n")
	writeSource(t, root, "core", "README.md", "core scaffold\n")
	writeSource(t, root, "modules/n8n", "README.md", "n8n scaffold\n")

	writeManifest(t, root, `{
  "schema_version": 1,
  "studio": {"version": "0.1.0-dev.1"},
  "embedded": {
    "cloud_init": {"version": "0.1.0-scaffold.1", "path": "cloud-init", "sha256": "ccf51bd82bc3d31436696469dc8ff59e7b233a255cf830dafb8a2f1a566eb27c"},
    "core": {"version": "0.1.0-scaffold.1", "path": "core", "sha256": "6e79e12b60e57718dd3da3625ef071e03d7618b6467286bc2350c2fb1093ab19"},
    "n8n": {"version": "0.1.0-scaffold.1", "path": "modules/n8n", "sha256": "c64e6feb4673aa2b90093e7195500533082034d1e549f30cbffc241b11089e86"}
  }
}`)

	info, err := releaseinfo.Load(root)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if info.Studio.Version != "0.1.0-dev.1" {
		t.Fatalf("Studio.Version = %q", info.Studio.Version)
	}
	if info.Embedded.N8N.SHA256 != "c64e6feb4673aa2b90093e7195500533082034d1e549f30cbffc241b11089e86" {
		t.Fatalf("n8n SHA256 = %q", info.Embedded.N8N.SHA256)
	}
}

func TestLoadRejectsModifiedEmbeddedSource(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "cloud-init", "README.md", "cloud-init scaffold\n")
	writeSource(t, root, "core", "README.md", "core scaffold\n")
	writeSource(t, root, "modules/n8n", "README.md", "n8n scaffold\n")
	writeManifest(t, root, `{
  "schema_version": 1,
  "studio": {"version": "0.1.0-dev.1"},
  "embedded": {
    "cloud_init": {"version": "0.1.0-scaffold.1", "path": "cloud-init", "sha256": "ccf51bd82bc3d31436696469dc8ff59e7b233a255cf830dafb8a2f1a566eb27c"},
    "core": {"version": "0.1.0-scaffold.1", "path": "core", "sha256": "6e79e12b60e57718dd3da3625ef071e03d7618b6467286bc2350c2fb1093ab19"},
    "n8n": {"version": "0.1.0-scaffold.1", "path": "modules/n8n", "sha256": "c64e6feb4673aa2b90093e7195500533082034d1e549f30cbffc241b11089e86"}
  }
}`)

	if err := os.WriteFile(filepath.Join(root, "core", "README.md"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := releaseinfo.Load(root)
	if err == nil || !strings.Contains(err.Error(), "core") || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("Load() error = %v, want core sha256 mismatch", err)
	}
}

func TestLoadRejectsPermissionDrift(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "cloud-init", "README.md", "cloud-init scaffold\n")
	writeSource(t, root, "core", "README.md", "core scaffold\n")
	writeSource(t, root, "modules/n8n", "README.md", "n8n scaffold\n")
	writeManifest(t, root, `{
  "schema_version": 1,
  "studio": {"version": "0.1.0-dev.1"},
  "embedded": {
    "cloud_init": {"version": "0.1.0-scaffold.1", "path": "cloud-init", "sha256": "ccf51bd82bc3d31436696469dc8ff59e7b233a255cf830dafb8a2f1a566eb27c"},
    "core": {"version": "0.1.0-scaffold.1", "path": "core", "sha256": "6e79e12b60e57718dd3da3625ef071e03d7618b6467286bc2350c2fb1093ab19"},
    "n8n": {"version": "0.1.0-scaffold.1", "path": "modules/n8n", "sha256": "c64e6feb4673aa2b90093e7195500533082034d1e549f30cbffc241b11089e86"}
  }
}`)

	if err := os.Chmod(filepath.Join(root, "core", "README.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := releaseinfo.Load(root)
	if err == nil || !strings.Contains(err.Error(), "core") || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("Load() error = %v, want permission-sensitive core sha256 mismatch", err)
	}
}

func TestLoadRejectsEmbeddedSourceRootEscapingThroughSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "README.md"), []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "core")); err != nil {
		t.Fatal(err)
	}
	writeSource(t, root, "cloud-init", "README.md", "cloud-init scaffold\n")
	writeSource(t, root, "modules/n8n", "README.md", "n8n scaffold\n")
	writeManifest(t, root, `{
  "schema_version": 1,
  "studio": {"version": "0.1.0-dev.1"},
  "embedded": {
    "cloud_init": {"version": "0.1.0-scaffold.1", "path": "cloud-init", "sha256": "ccf51bd82bc3d31436696469dc8ff59e7b233a255cf830dafb8a2f1a566eb27c"},
    "core": {"version": "0.1.0-scaffold.1", "path": "core", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    "n8n": {"version": "0.1.0-scaffold.1", "path": "modules/n8n", "sha256": "c64e6feb4673aa2b90093e7195500533082034d1e549f30cbffc241b11089e86"}
  }
}`)

	_, err := releaseinfo.Load(root)
	if err == nil || !strings.Contains(err.Error(), "escapes embedded root") {
		t.Fatalf("Load() error = %v, want symlink escape error", err)
	}
}

func TestLoadRejectsUnsafeSourcePath(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, root, `{
  "schema_version": 1,
  "studio": {"version": "0.1.0-dev.1"},
  "embedded": {
    "cloud_init": {"version": "x", "path": "../cloud-init", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    "core": {"version": "x", "path": "core", "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
    "n8n": {"version": "x", "path": "modules/n8n", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
  }
}`)

	_, err := releaseinfo.Load(root)
	if err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("Load() error = %v, want unsafe path error", err)
	}
}

func writeSource(t *testing.T, root, dir, name, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(dir), name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeManifest(t *testing.T, root, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
