package deployment

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrepareCoreRestoreKeepsSecretIDsButRequestsNoCurrentSecretMaterial(t *testing.T) {
	compiler := coreCompiler(t)
	req := coreRequest(Restore)
	req.ObservedCoreID = "source-core-newer"
	req.ObservedCoreSHA256 = strings.Repeat("b", 64)
	locks := map[string]FrozenCoreImage{
		"caddy":    {Ref: caddyTestRef, Digest: "sha256:" + strings.Repeat("d", 64)},
		"authelia": {Ref: autheliaTestRef, Digest: "sha256:" + strings.Repeat("e", 64)},
	}

	prepared, err := compiler.PrepareCoreRestore(context.Background(), req, locks)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Bundle.Manifest.Secrets) != 0 {
		t.Fatalf("Core restore requested current Management State secret material: %#v", prepared.Bundle.Manifest.Secrets)
	}

	var desired generatedCoreDesired
	found := false
	for _, artifact := range prepared.Artifacts {
		if artifact.TargetPath != coreDesiredTarget {
			continue
		}
		if err := json.Unmarshal(artifact.Data, &desired); err != nil {
			t.Fatal(err)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("Core restore desired artifact is missing")
	}
	if desired.Secrets.AutheliaSession != req.Secrets.AutheliaSession ||
		desired.Secrets.AutheliaStorage != req.Secrets.AutheliaStorage ||
		desired.Secrets.AutheliaResetPassword != req.Secrets.AutheliaResetPassword ||
		desired.Secrets.AutheliaUsersDatabase != req.Secrets.AutheliaUsersDatabase {
		t.Fatalf("Core restore lost stable secret references: %#v", desired.Secrets)
	}
}
