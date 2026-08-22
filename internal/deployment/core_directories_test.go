package deployment

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

func TestPrepareCoreFreezesTargetDirectoryOwnership(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Install)
	prepared, err := compiler.PrepareCore(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	byPath := make(map[string]executionbundle.Directory, len(prepared.Bundle.Manifest.Directories))
	for _, directory := range prepared.Bundle.Manifest.Directories {
		byPath[directory.Path] = directory
	}
	want := []executionbundle.Directory{
		{Path: "/etc/containers", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o755},
		{Path: "/etc/containers/containers.conf.d", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o755},
		{Path: filepath.Join("/home", req.AdminUser, ".config"), Owner: executionbundle.PrincipalAdmin, Group: executionbundle.PrincipalAdmin, Mode: 0o700},
		{Path: filepath.Join("/home", req.AdminUser, ".config/containers/systemd"), Owner: executionbundle.PrincipalAdmin, Group: executionbundle.PrincipalAdmin, Mode: 0o700},
		{Path: "/var/lib/vpsmith/core", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalAdmin, Mode: 0o750},
		{Path: "/var/lib/vpsmith/secrets", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalAdmin, Mode: 0o750},
	}
	for _, expected := range want {
		if got, ok := byPath[expected.Path]; !ok || got != expected {
			t.Fatalf("directory %s = %#v, want %#v", expected.Path, got, expected)
		}
	}
}

func TestPrepareCoreValidationDoesNotMutateTargetDirectories(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Validate)
	req.ObservedCoreID = req.Source.SourceID
	req.ObservedCoreSHA256 = req.Source.PackageSHA256
	prepared, err := compiler.PrepareCore(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Bundle.Manifest.Directories) != 0 {
		t.Fatalf("validation directory claims = %#v", prepared.Bundle.Manifest.Directories)
	}
}
