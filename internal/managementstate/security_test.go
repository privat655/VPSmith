package managementstate

import (
	"context"
	"strings"
	"testing"
)

func TestSecretAuthenticationFailsForTamperedCiphertextAndWrongKey(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var id SecretID
	if err := store.Change(ctx, func(change *Change) error {
		var err error
		id, err = change.CreateSecret("tamper-test", SecretUser)
		if err != nil {
			return err
		}
		return change.SetSecret(id, []byte("tamper-resistant-secret"))
	}); err != nil {
		t.Fatal(err)
	}

	originalKey := append([]byte(nil), store.key...)
	store.key[0] ^= 0xff
	if err := store.ResolveSecret(ctx, id, func(SecretMaterial) error { return nil }); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("wrong-key ResolveSecret() error = %v", err)
	}
	copy(store.key, originalKey)

	var ciphertext []byte
	if err := store.db.QueryRowContext(ctx, `SELECT ciphertext FROM secrets WHERE id=?`, id).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	if _, err := store.db.ExecContext(ctx, `UPDATE secrets SET ciphertext=? WHERE id=?`, ciphertext, id); err != nil {
		t.Fatal(err)
	}
	if err := store.ResolveSecret(ctx, id, func(SecretMaterial) error { return nil }); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("tampered ResolveSecret() error = %v", err)
	}
}

func TestHistoryTablesRejectUpdateAndDeleteAtStorageLayer(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	targetID, err := NewTargetID()
	if err != nil {
		t.Fatal(err)
	}
	bundleID, err := NewExecutionBundleID()
	if err != nil {
		t.Fatal(err)
	}
	recordID, err := NewExecutionRecordID()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Change(ctx, func(change *Change) error {
		if err := change.CreateTarget(TargetRegistration{ID: targetID, Address: "203.0.113.20", SSHUser: "dev"}); err != nil {
			return err
		}
		if err := change.AppendExecutionBundle(ExecutionBundleMetadata{ID: bundleID, TargetID: targetID, Kind: "validation", Version: "1", SHA256: strings.Repeat("a", 64)}); err != nil {
			return err
		}
		return change.AppendExecutionRecord(ExecutionRecordMetadata{ID: recordID, BundleID: bundleID, TargetID: targetID, Outcome: "ok", StartedAt: "2026-08-16T08:00:00Z"})
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE execution_bundles SET version='changed' WHERE id=?`, bundleID); err == nil {
		t.Fatal("execution bundle storage allowed update")
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM execution_records WHERE id=?`, recordID); err == nil {
		t.Fatal("execution record storage allowed delete")
	}
}
