package deployment

import (
	"context"
	"reflect"
	"testing"
)

func TestCompilerDerivesActionWriteScopeOnlyFromSubjectPersistentStorage(t *testing.T) {
	req := baseRequest()
	compiler := newCompiler(t, "docker.io/example/n8n:2.0.0")
	prepared, err := compiler.Prepare(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/var/lib/vpsmith/n8n/data"}
	if !reflect.DeepEqual(prepared.Bundle.Manifest.ActionWritablePaths, want) {
		t.Fatalf("action writable paths = %#v want %#v", prepared.Bundle.Manifest.ActionWritablePaths, want)
	}
}
