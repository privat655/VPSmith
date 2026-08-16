package deployment

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

func TestPrepareCannotOverwriteHistoricalBundle(t *testing.T) {
	root := t.TempDir()
	assembler, err := executionbundle.NewAssembler(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(fakeRegistry{"docker.io/example/n8n:2.0.0": digestA}, assembler)
	if err != nil {
		t.Fatal(err)
	}
	req := baseRequest()
	prepared, err := c.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, prepared.Bundle.ID+".tar")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered historical bundle"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Prepare(context.Background(), req); err == nil {
		t.Fatal("deployment compiler overwrote a historical bundle")
	}
}
