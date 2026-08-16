package managementstate_test

import (
	"context"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestSecretValueMatchingNormalMetadataIsRejectedAtomically(t *testing.T) {
	ctx := context.Background()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	plaintext := []byte("metadata-leak-sentinel")
	err = store.Change(ctx, func(change *managementstate.Change) error {
		id, err := change.CreateSecret(string(plaintext), managementstate.SecretUser)
		if err != nil {
			return err
		}
		return change.SetSecret(id, plaintext)
	})
	if err == nil {
		t.Fatal("secret value matching normal metadata was accepted")
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Secrets) != 0 {
		t.Fatalf("failed secret write left metadata behind: %#v", snapshot.Secrets)
	}
}
