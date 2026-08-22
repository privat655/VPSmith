package deployment

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestPrepareCoreRuntimeUsesStablePodmanObservationContract(t *testing.T) {
	compiler := coreCompiler(t)
	prepared, err := compiler.PrepareCore(context.Background(), coreRequest(Install))
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Bundle.Manifest.Actions) != 1 {
		t.Fatalf("Core install actions = %#v, want exactly one runtime action", prepared.Bundle.Manifest.Actions)
	}
	runtime := string(bundleEntry(t, prepared.Bundle.Bytes, prepared.Bundle.Manifest.Actions[0].Path))
	for _, required := range []string{
		"podman info --format json",
		".host.security.rootless",
		".host.cgroupVersion",
		"command -v pasta",
		"default_rootless_network_cmd",
	} {
		if !strings.Contains(runtime, required) {
			t.Fatalf("Core runtime does not enforce %q through the production bundle action", required)
		}
	}
	for _, forbidden := range []string{".Host.CgroupVersion", ".Host.RootlessNetworkCmd"} {
		if strings.Contains(runtime, forbidden) {
			t.Fatalf("Core runtime still depends on unstable Podman Go-template field %q", forbidden)
		}
	}
}

func bundleEntry(t *testing.T, payload []byte, name string) []byte {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(payload))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name != name {
			continue
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	t.Fatalf("bundle entry %q is missing", name)
	return nil
}
