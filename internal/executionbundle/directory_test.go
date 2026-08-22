package executionbundle

import (
	"bytes"
	"testing"
)

func TestAssemblerFreezesDeclaredTargetDirectories(t *testing.T) {
	a, err := NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	in := baseInput()
	in.Directories = []Directory{
		{Path: "/home/vpsmith/.config", Owner: PrincipalAdmin, Group: PrincipalAdmin, Mode: 0o700},
		{Path: "/etc/containers", Owner: PrincipalRoot, Group: PrincipalRoot, Mode: 0o755},
	}
	bundle, err := a.Assemble(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Manifest.Directories) != 2 {
		t.Fatalf("directories=%#v", bundle.Manifest.Directories)
	}
	if got := bundle.Manifest.Directories[0]; got.Path != "/etc/containers" || got.Owner != PrincipalRoot || got.Group != PrincipalRoot || got.Mode != 0o755 {
		t.Fatalf("first directory=%#v", got)
	}
	if got := bundle.Manifest.Directories[1]; got.Path != "/home/vpsmith/.config" || got.Owner != PrincipalAdmin || got.Group != PrincipalAdmin || got.Mode != 0o700 {
		t.Fatalf("second directory=%#v", got)
	}

	reordered := baseInput()
	reordered.Directories = []Directory{in.Directories[1], in.Directories[0]}
	second, err := a.Assemble(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundle.Bytes, second.Bytes) {
		t.Fatal("directory declaration ordering changed canonical bundle bytes")
	}
}

func TestAssemblerRejectsUnsafeTargetDirectoryClaims(t *testing.T) {
	a, err := NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cases := []Directory{
		{Path: "relative", Owner: PrincipalRoot, Group: PrincipalRoot, Mode: 0o755},
		{Path: "/tmp/world-writable", Owner: PrincipalRoot, Group: PrincipalRoot, Mode: 0o777},
		{Path: "/tmp/unknown-owner", Owner: "nobody", Group: PrincipalRoot, Mode: 0o755},
	}
	for _, directory := range cases {
		in := baseInput()
		in.Directories = []Directory{directory}
		if _, err := a.Assemble(in); err == nil {
			t.Fatalf("expected rejection for %#v", directory)
		}
	}
}

func TestValidationBundleRejectsDirectoryMutation(t *testing.T) {
	a, err := NewAssembler(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	in := baseInput()
	in.Kind = Validation
	in.Steps = nil
	in.Directories = []Directory{{Path: "/etc/containers", Owner: PrincipalRoot, Group: PrincipalRoot, Mode: 0o755}}
	if _, err := a.Assemble(in); err == nil {
		t.Fatal("expected validation directory mutation rejection")
	}
}
