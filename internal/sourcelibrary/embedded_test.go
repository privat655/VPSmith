package sourcelibrary

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestCurrentEmbeddedCloudInitReturnsVerifiedReleasedSnapshot(t *testing.T) {
	state, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	embeddedRoot, err := filepath.Abs(filepath.Join("..", "..", "embedded"))
	if err != nil {
		t.Fatal(err)
	}
	library, err := New(t.TempDir(), embeddedRoot, state, NewGithubRemote())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := library.ImportEmbedded(context.Background()); err != nil {
		t.Fatal(err)
	}
	frozen, err := library.CurrentEmbedded(context.Background(), managementstate.SourceCloudInit)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Version != "0.1.0" || frozen.SHA256 == "" || frozen.Kind != managementstate.SourceCloudInit {
		t.Fatalf("unexpected released Cloud-init source: %#v", frozen.Snapshot)
	}
	templateBytes, err := fs.ReadFile(frozen.FS, "cloud-init.yaml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(templateBytes), "#cloud-config\n") || !strings.Contains(string(templateBytes), "{{.SSHPublicKey}}") {
		t.Fatal("released Cloud-init source does not contain the canonical template")
	}
}
