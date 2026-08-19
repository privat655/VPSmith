package application

import (
	"context"
	"path/filepath"
	"testing"
)

func TestApplicationExposesCanonicalCoreLifecycle(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	app, err := Open(context.Background(), Paths{
		StateDir:      filepath.Join(root, "state"),
		SourcesDir:    filepath.Join(root, "sources"),
		BackupsDir:    filepath.Join(root, "backups"),
		EmbeddedRoot:  filepath.Join("..", "..", "embedded"),
		SSHRuntimeDir: filepath.Join(root, "runtime", "ssh"),
		BundlesDir:    filepath.Join(root, "bundles"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if app.Core() == nil {
		t.Fatal("production composition must expose one canonical Core lifecycle")
	}
}
