package managementstate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func TestPersistentStateRoundTripKeepsDesiredObservedAndSourcesSeparate(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := managementstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	targetID := mustID(t, managementstate.NewTargetID)
	coreSource := mustID(t, managementstate.NewSourceSnapshotID)
	coreObservedSource := mustID(t, managementstate.NewSourceSnapshotID)
	packageID := mustID(t, managementstate.NewModulePackageID)
	instanceID := mustID(t, managementstate.NewModuleInstanceID)
	var secretID managementstate.SecretID
	err = store.Change(ctx, func(change *managementstate.Change) error {
		var err error
		secretID, err = change.CreateSecret("n8n-encryption-key", managementstate.SecretGenerated)
		if err != nil {
			return err
		}
		if err := change.SetSecret(secretID, []byte("correct-horse-battery-staple")); err != nil {
			return err
		}
		if err := change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "203.0.113.10", SSHUser: "dev", SSHTrust: managementstate.TrustUnknown}); err != nil {
			return err
		}
		if err := change.RegisterSourceArtifact(managementstate.SourceArtifact{ID: coreSource, Kind: managementstate.SourceCore, Version: "1.0.0", SHA256: strings.Repeat("a", 64), StorageRef: "snapshots/sha256/core-a"}); err != nil {
			return err
		}
		if err := change.RegisterSourceArtifact(managementstate.SourceArtifact{ID: coreObservedSource, Kind: managementstate.SourceCore, Version: "0.9.0", SHA256: strings.Repeat("b", 64), StorageRef: "snapshots/sha256/core-b"}); err != nil {
			return err
		}
		return change.SetDesiredState(targetID, managementstate.DesiredState{
			Core:    managementstate.CoreDesiredState{SourceID: coreSource, Version: "1.0.0", Swap: managementstate.SwapDesiredState{Mode: "none"}},
			Modules: []managementstate.ModuleDesiredState{{InstanceID: instanceID, PackageID: packageID, Version: "2.0.0", SecretIDs: []managementstate.SecretID{secretID}, Resources: managementstate.ResourceOverrides{MemoryBytes: 1024}}},
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	beforeObserved, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeDesired := beforeObserved.Targets[0].Desired
	err = store.Change(ctx, func(change *managementstate.Change) error {
		return change.RecordObservedState(targetID, managementstate.ObservedState{ObservedAt: "2026-08-16T08:00:00Z", Core: managementstate.CoreObservedState{SourceID: coreObservedSource, Version: "0.9.0", Running: true}, Modules: []managementstate.ModuleObservedState{{InstanceID: instanceID, PackageID: packageID, Version: "1.9.0", Running: false, Health: "stopped"}}})
	})
	if err != nil {
		t.Fatal(err)
	}
	afterObserved, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeDesired, afterObserved.Targets[0].Desired) {
		t.Fatalf("observed update changed desired state\nbefore=%#v\nafter=%#v", beforeDesired, afterObserved.Targets[0].Desired)
	}
	if afterObserved.Targets[0].Observed.Core.Version != "0.9.0" {
		t.Fatalf("observed core version = %q", afterObserved.Targets[0].Observed.Core.Version)
	}
	if len(afterObserved.Sources.Artifacts) != 2 {
		t.Fatalf("canonical source artifacts = %d, want 2", len(afterObserved.Sources.Artifacts))
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := managementstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	afterRestart, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterObserved, afterRestart) {
		t.Fatalf("snapshot changed after restart\nbefore=%#v\nafter=%#v", afterObserved, afterRestart)
	}
}

func TestAtomicChangeRollsBackAllWrites(t *testing.T) {
	store := mustMemory(t)
	ctx := context.Background()
	targetID := mustID(t, managementstate.NewTargetID)
	wantErr := errors.New("simulated failure")
	err := store.Change(ctx, func(change *managementstate.Change) error {
		if err := change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "203.0.113.11", SSHUser: "dev"}); err != nil {
			return err
		}
		_, err := change.CreateSecret("temporary", managementstate.SecretUser)
		if err != nil {
			return err
		}
		return wantErr
	})
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("Change() error = %v", err)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Targets) != 0 || len(snapshot.Secrets) != 0 {
		t.Fatalf("partial state survived rollback: %#v", snapshot)
	}
}

func TestSecretLifecycleEncryptsAndRedactsMaterial(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := managementstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("SECRET-MATERIAL-THAT-MUST-NEVER-LEAK")
	rotated := []byte("ROTATED-MATERIAL-ALSO-PRIVATE")
	var id managementstate.SecretID
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		var err error
		id, err = change.CreateSecret("database-password", managementstate.SecretUser)
		if err != nil {
			return err
		}
		return change.SetSecret(id, secret)
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.ResolveSecret(ctx, id, func(material managementstate.SecretMaterial) error {
		if string(material.Bytes()) != string(secret) {
			t.Fatalf("resolved secret = %q", material.Bytes())
		}
		if fmt.Sprint(material) != "[REDACTED]" || strings.Contains(fmt.Sprintf("%#v", material), string(secret)) {
			t.Fatal("secret material debug representation leaked plaintext")
		}
		if _, err := json.Marshal(material); err == nil {
			t.Fatal("secret material unexpectedly serialized")
		}
		return errors.New(string(secret))
	}); err == nil || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("consumer error leaked secret: %v", err)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if bytesContainAny(encoded, secret, rotated) {
		t.Fatalf("snapshot contains secret material: %s", encoded)
	}
	dbBytes, err := os.ReadFile(filepath.Join(dir, "vpsmith.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytesContainAny(dbBytes, secret) {
		t.Fatal("database contains secret plaintext")
	}

	if err := store.Change(ctx, func(change *managementstate.Change) error { return change.RotateSecret(id, rotated) }); err != nil {
		t.Fatal(err)
	}
	if err := store.ResolveSecret(ctx, id, func(material managementstate.SecretMaterial) error {
		if string(material.Bytes()) != string(rotated) {
			t.Fatalf("rotated secret = %q", material.Bytes())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Change(ctx, func(change *managementstate.Change) error { return change.DeleteSecret(id) }); err != nil {
		t.Fatal(err)
	}
	if err := store.ResolveSecret(ctx, id, func(managementstate.SecretMaterial) error { return nil }); err == nil {
		t.Fatal("deleted secret still resolves")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSecretCannotLeakIntoNormalStateOrHistory(t *testing.T) {
	store := mustMemory(t)
	ctx := context.Background()
	secret := []byte("history-leak-sentinel")
	targetID := mustID(t, managementstate.NewTargetID)
	var id managementstate.SecretID
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		var err error
		id, err = change.CreateSecret("token", managementstate.SecretUser)
		if err != nil {
			return err
		}
		if err := change.SetSecret(id, secret); err != nil {
			return err
		}
		return change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "203.0.113.12", SSHUser: "dev"})
	}); err != nil {
		t.Fatal(err)
	}
	bundleID := mustID(t, managementstate.NewExecutionBundleID)
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		return change.AppendExecutionBundle(managementstate.ExecutionBundleMetadata{ID: bundleID, TargetID: targetID, Kind: "install", Version: string(secret), SHA256: strings.Repeat("e", 64)})
	}); err == nil || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("history leak was not safely rejected: %v", err)
	}
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		return change.RecordObservedState(targetID, managementstate.ObservedState{Core: managementstate.CoreObservedState{Version: string(secret)}})
	}); err == nil || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("observed leak was not safely rejected: %v", err)
	}
}

func TestReferencedSecretCannotBeDeleted(t *testing.T) {
	store := mustMemory(t)
	ctx := context.Background()
	targetID := mustID(t, managementstate.NewTargetID)
	packageID := mustID(t, managementstate.NewModulePackageID)
	instanceID := mustID(t, managementstate.NewModuleInstanceID)
	var secretID managementstate.SecretID
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		var err error
		secretID, err = change.CreateSecret("module-secret", managementstate.SecretGenerated)
		if err != nil {
			return err
		}
		if err := change.SetSecret(secretID, []byte("reference-protected-secret")); err != nil {
			return err
		}
		if err := change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "203.0.113.13", SSHUser: "dev"}); err != nil {
			return err
		}
		return change.SetDesiredState(targetID, managementstate.DesiredState{Modules: []managementstate.ModuleDesiredState{{InstanceID: instanceID, PackageID: packageID, Version: "1", SecretIDs: []managementstate.SecretID{secretID}}}})
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Change(ctx, func(change *managementstate.Change) error { return change.DeleteSecret(secretID) }); err == nil {
		t.Fatal("referenced secret was deleted")
	}
}

func TestHistoryIsAppendOnlyAndBackupKindsRemainDistinct(t *testing.T) {
	store := mustMemory(t)
	ctx := context.Background()
	targetID := mustID(t, managementstate.NewTargetID)
	instanceID := mustID(t, managementstate.NewModuleInstanceID)
	bundleID := mustID(t, managementstate.NewExecutionBundleID)
	recordID := mustID(t, managementstate.NewExecutionRecordID)
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		if err := change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "203.0.113.14", SSHUser: "dev"}); err != nil {
			return err
		}
		if err := change.AppendExecutionBundle(managementstate.ExecutionBundleMetadata{ID: bundleID, TargetID: targetID, Kind: "migration", Version: "1", SHA256: strings.Repeat("f", 64)}); err != nil {
			return err
		}
		if err := change.AppendExecutionRecord(managementstate.ExecutionRecordMetadata{ID: recordID, BundleID: bundleID, TargetID: targetID, Outcome: "ok", StartedAt: "2026-08-16T08:00:00Z"}); err != nil {
			return err
		}
		for _, kind := range []managementstate.BackupArtifactType{managementstate.BackupRecoveryPackage, managementstate.BackupCore, managementstate.BackupModule, managementstate.BackupSystemRestorePoint} {
			backupID := mustID(t, managementstate.NewBackupArtifactID)
			module := managementstate.ModuleInstanceID("")
			if kind == managementstate.BackupModule || kind == managementstate.BackupSystemRestorePoint {
				module = instanceID
			}
			if err := change.RegisterBackup(managementstate.BackupArtifactMetadata{ID: backupID, Type: kind, TargetID: targetID, ModuleInstanceID: module}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		return change.AppendExecutionBundle(managementstate.ExecutionBundleMetadata{ID: bundleID, TargetID: targetID, Kind: "migration", Version: "changed", SHA256: strings.Repeat("1", 64)})
	}); err == nil {
		t.Fatal("execution bundle with existing id was overwritten")
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ExecutionBundles[0].Version != "1" {
		t.Fatal("execution bundle history changed")
	}
	if len(snapshot.ExecutionRecords) != 1 {
		t.Fatalf("execution records = %d", len(snapshot.ExecutionRecords))
	}
	if len(snapshot.Backups) != 4 {
		t.Fatalf("backup artifact types = %d", len(snapshot.Backups))
	}
	seen := map[managementstate.BackupArtifactType]bool{}
	for _, backup := range snapshot.Backups {
		seen[backup.Type] = true
	}
	for _, kind := range []managementstate.BackupArtifactType{managementstate.BackupRecoveryPackage, managementstate.BackupCore, managementstate.BackupModule, managementstate.BackupSystemRestorePoint} {
		if !seen[kind] {
			t.Fatalf("missing backup kind %s", kind)
		}
	}
}

func TestSourceSyncAndStudioBasisChangesNeverChangeTargetState(t *testing.T) {
	store := mustMemory(t)
	ctx := context.Background()
	targetID := mustID(t, managementstate.NewTargetID)
	oldCore := mustID(t, managementstate.NewCoreSourceID)
	newCore := mustID(t, managementstate.NewCoreSourceID)
	installedPackageID := mustID(t, managementstate.NewModulePackageID)
	remotePackageID := mustID(t, managementstate.NewModulePackageID)
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		if err := change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: "203.0.113.15", SSHUser: "dev"}); err != nil {
			return err
		}
		if err := change.PutCoreSource(managementstate.CoreSource{ID: oldCore, Role: managementstate.CoreSourceTarget, TargetID: targetID, Version: "old", SHA256: strings.Repeat("a", 64)}); err != nil {
			return err
		}
		if err := change.PutModuleSource(managementstate.ModuleSource{PackageID: installedPackageID, Role: managementstate.ModuleSourceTarget, TargetID: targetID, Commit: "installed", Version: "1", PackageSHA256: strings.Repeat("b", 64)}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Snapshot(ctx)
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		if err := change.PutCoreSource(managementstate.CoreSource{ID: newCore, Role: managementstate.CoreSourceEmbedded, Version: "new", SHA256: strings.Repeat("c", 64)}); err != nil {
			return err
		}
		return change.PutModuleSource(managementstate.ModuleSource{PackageID: remotePackageID, Role: managementstate.ModuleSourceRemote, Owner: "owner", Repository: "repo", Ref: "main", Commit: "remote-new", Version: "2", PackageSHA256: strings.Repeat("d", 64)})
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := store.Snapshot(ctx)
	if !reflect.DeepEqual(before.Targets, after.Targets) {
		t.Fatal("source synchronization changed target state")
	}
	var targetCore managementstate.CoreSourceID
	var targetCommit string
	for _, source := range after.CoreSources {
		if source.Role == managementstate.CoreSourceTarget {
			targetCore = source.ID
		}
	}
	for _, source := range after.ModuleSources {
		if source.Role == managementstate.ModuleSourceTarget {
			targetCommit = source.Commit
		}
	}
	if targetCore != oldCore || targetCommit != "installed" {
		t.Fatal("source synchronization changed target source identities")
	}
}

func TestStateFilesUseRestrictivePermissionsAndMissingKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	store, err := managementstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"vpsmith.db": 0o600, "secret-store.key": 0o600} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %04o, want %04o", name, info.Mode().Perm(), want)
		}
	}
	if err := os.Remove(filepath.Join(dir, "secret-store.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := managementstate.Open(dir); err == nil {
		t.Fatal("existing database opened without its secret key")
	}
}

func mustMemory(t *testing.T) *managementstate.Store {
	t.Helper()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func mustID[T ~string](t *testing.T, create func() (T, error)) T {
	t.Helper()
	value, err := create()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func bytesContainAny(haystack []byte, needles ...[]byte) bool {
	text := string(haystack)
	for _, needle := range needles {
		if strings.Contains(text, string(needle)) {
			return true
		}
	}
	return false
}
