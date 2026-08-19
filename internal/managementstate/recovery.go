package managementstate

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// RecoveryState is the portable management-state projection used only inside
// an encrypted VPSmith recovery-package payload. Snapshot contains canonical
// domain state; SecretValues contains plaintext only while the encrypted
// package is being produced or imported.
type RecoveryState struct {
	Snapshot     Snapshot            `json:"snapshot"`
	SecretValues map[SecretID][]byte `json:"secret_values"`
	Omitted      []SecretID          `json:"omitted_secret_ids,omitempty"`
}

func (s *Store) ExportRecovery(ctx context.Context, includeCustomModulePAT bool) (RecoveryState, error) {
	snapshot, err := s.Snapshot(ctx)
	if err != nil {
		return RecoveryState{}, err
	}
	result := RecoveryState{Snapshot: snapshot, SecretValues: make(map[SecretID][]byte)}
	var pat SecretID
	if snapshot.Sources.CustomModuleGithub != nil {
		pat = snapshot.Sources.CustomModuleGithub.PATSecretID
	}
	for _, secret := range snapshot.Secrets {
		if !secret.IsSet {
			continue
		}
		if secret.ID == pat && !includeCustomModulePAT {
			result.Omitted = append(result.Omitted, secret.ID)
			continue
		}
		var value []byte
		if err := s.ResolveSecret(ctx, secret.ID, func(material SecretMaterial) error {
			value = append([]byte(nil), material.Bytes()...)
			return nil
		}); err != nil {
			zeroBytes(value)
			result.Zero()
			return RecoveryState{}, fmt.Errorf("export recovery secret %s: %w", secret.ID, err)
		}
		result.SecretValues[secret.ID] = value
	}
	sort.Slice(result.Omitted, func(i, j int) bool { return result.Omitted[i] < result.Omitted[j] })
	return result, nil
}

func (r *RecoveryState) Zero() {
	if r == nil {
		return
	}
	for id, value := range r.SecretValues {
		zeroBytes(value)
		delete(r.SecretValues, id)
	}
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func (s *Store) ReplaceFromRecovery(ctx context.Context, recovery RecoveryState, imported BackupArtifactMetadata) error {
	if recovery.Snapshot.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported recovery schema version %d", recovery.Snapshot.SchemaVersion)
	}
	if imported.Type != BackupRecoveryPackage || imported.ID == "" || imported.TargetID == "" {
		return errors.New("imported recovery artifact metadata is invalid")
	}
	if err := validateRecoverySnapshot(recovery); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire recovery-state writer: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin recovery import: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	// Embedded source registrations are derived at Studio startup, so they are
	// intentionally replaced below. All user-owned/canonical tables must be
	// empty to prevent recovery import from becoming a merge operation.
	for _, query := range []string{
		`SELECT COUNT(*) FROM targets`,
		`SELECT COUNT(*) FROM secrets`,
		`SELECT COUNT(*) FROM source_workspaces`,
		`SELECT COUNT(*) FROM execution_bundles`,
		`SELECT COUNT(*) FROM execution_records`,
		`SELECT COUNT(*) FROM backups`,
		`SELECT COUNT(*) FROM custom_module_github`,
	} {
		var count int
		if err := conn.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return fmt.Errorf("inspect fresh recovery target: %w", err)
		}
		if count != 0 {
			return errors.New("recovery import requires a fresh VPSmith management state")
		}
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM source_artifacts`); err != nil {
		return fmt.Errorf("reset derived source registrations: %w", err)
	}

	for _, secret := range recovery.Snapshot.Secrets {
		var ciphertext []byte
		if value, ok := recovery.SecretValues[secret.ID]; ok {
			ciphertext, err = encryptSecret(s.key, secret.ID, value)
			if err != nil {
				return fmt.Errorf("encrypt imported secret %s: %w", secret.ID, err)
			}
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO secrets(id,name,origin,created_at,rotated_at,rotation_count,ciphertext) VALUES(?,?,?,?,?,?,?)`,
			secret.ID, secret.Name, secret.Origin, secret.CreatedAt, secret.RotatedAt, secret.RotationCount, ciphertext,
		); err != nil {
			return fmt.Errorf("import secret metadata %s: %w", secret.ID, err)
		}
	}
	for _, artifact := range recovery.Snapshot.Sources.Artifacts {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO source_artifacts(id,kind,package_id,package_path,version,commit_sha,sha256,storage_ref) VALUES(?,?,?,?,?,?,?,?)`,
			artifact.ID, artifact.Kind, artifact.PackageID, artifact.PackagePath, artifact.Version, artifact.Commit, artifact.SHA256, artifact.StorageRef,
		); err != nil {
			return fmt.Errorf("import source artifact %s: %w", artifact.ID, err)
		}
	}
	for _, workspace := range recovery.Snapshot.Sources.Workspaces {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO source_workspaces(id,kind,package_id,package_path,base_source_id,base_commit,current_sha256,storage_ref,synchronized_commit) VALUES(?,?,?,?,?,?,?,?,?)`,
			workspace.ID, workspace.Kind, workspace.PackageID, workspace.PackagePath, workspace.BaseSourceID, workspace.BaseCommit, workspace.CurrentSHA256, workspace.StorageRef, workspace.SynchronizedCommit,
		); err != nil {
			return fmt.Errorf("import source workspace %s: %w", workspace.ID, err)
		}
	}
	if cfg := recovery.Snapshot.Sources.CustomModuleGithub; cfg != nil {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO custom_module_github(singleton,owner,repository,ref,pat_secret_id) VALUES(1,?,?,?,?)`,
			cfg.Owner, cfg.Repository, cfg.Ref, cfg.PATSecretID,
		); err != nil {
			return fmt.Errorf("import custom module github configuration: %w", err)
		}
	}
	for _, target := range recovery.Snapshot.Targets {
		desired, err := marshalDomain(target.Desired)
		if err != nil {
			return err
		}
		observed, err := marshalDomain(target.Observed)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO targets(id,address,ssh_user,ssh_identity_secret_id,ssh_host_key,ssh_host_fingerprint,ssh_trust,desired_json,observed_json) VALUES(?,?,?,?,?,?,?,?,?)`,
			target.ID, target.Address, target.SSHUser, target.SSHIdentitySecretID, target.SSHHostKey, target.SSHHostFingerprint, target.SSHTrust, string(desired), string(observed),
		); err != nil {
			return fmt.Errorf("import target %s: %w", target.ID, err)
		}
	}
	for _, bundle := range recovery.Snapshot.ExecutionBundles {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO execution_bundles(id,target_id,kind,version,sha256,created_at) VALUES(?,?,?,?,?,?)`,
			bundle.ID, bundle.TargetID, bundle.Kind, bundle.Version, bundle.SHA256, bundle.CreatedAt,
		); err != nil {
			return fmt.Errorf("import execution bundle %s: %w", bundle.ID, err)
		}
	}
	for _, record := range recovery.Snapshot.ExecutionRecords {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO execution_records(id,bundle_id,target_id,outcome,started_at,finished_at) VALUES(?,?,?,?,?,?)`,
			record.ID, record.BundleID, record.TargetID, record.Outcome, record.StartedAt, record.FinishedAt,
		); err != nil {
			return fmt.Errorf("import execution record %s: %w", record.ID, err)
		}
	}
	for _, backup := range recovery.Snapshot.Backups {
		if _, err := conn.ExecContext(ctx,
			`INSERT INTO backups(id,artifact_type,target_id,module_instance_id,created_at,location_ref,sha256) VALUES(?,?,?,?,?,?,?)`,
			backup.ID, backup.Type, backup.TargetID, backup.ModuleInstanceID, backup.CreatedAt, backup.LocationRef, backup.SHA256,
		); err != nil {
			return fmt.Errorf("import backup metadata %s: %w", backup.ID, err)
		}
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO backups(id,artifact_type,target_id,module_instance_id,created_at,location_ref,sha256) VALUES(?,?,?,?,?,?,?)`,
		imported.ID, imported.Type, imported.TargetID, imported.ModuleInstanceID, imported.CreatedAt, imported.LocationRef, imported.SHA256,
	); err != nil {
		return fmt.Errorf("register imported recovery artifact: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit recovery import: %w", err)
	}
	committed = true
	return nil
}

func validateRecoverySnapshot(recovery RecoveryState) error {
	snapshot := recovery.Snapshot
	if len(snapshot.Targets) == 0 {
		return errors.New("recovery package contains no target")
	}
	secretByID := make(map[SecretID]SecretMetadata, len(snapshot.Secrets))
	for _, secret := range snapshot.Secrets {
		if secret.ID == "" || secret.Name == "" {
			return errors.New("recovery package contains invalid secret metadata")
		}
		if _, exists := secretByID[secret.ID]; exists {
			return fmt.Errorf("duplicate recovery secret %s", secret.ID)
		}
		secretByID[secret.ID] = secret
	}

	var pat SecretID
	if snapshot.Sources.CustomModuleGithub != nil {
		pat = snapshot.Sources.CustomModuleGithub.PATSecretID
	}
	omitted := make(map[SecretID]struct{}, len(recovery.Omitted))
	for _, id := range recovery.Omitted {
		if id == "" || id != pat {
			return fmt.Errorf("recovery may omit only the configured Custom Module Github PAT, got %s", id)
		}
		if _, duplicate := omitted[id]; duplicate {
			return fmt.Errorf("duplicate omitted recovery secret %s", id)
		}
		omitted[id] = struct{}{}
	}
	for _, secret := range snapshot.Secrets {
		_, hasValue := recovery.SecretValues[secret.ID]
		_, isOmitted := omitted[secret.ID]
		if secret.IsSet && !hasValue && !isOmitted {
			return fmt.Errorf("recovery secret %s is missing", secret.ID)
		}
		if !secret.IsSet && hasValue {
			return fmt.Errorf("unset recovery secret %s unexpectedly has material", secret.ID)
		}
		if isOmitted && !secret.IsSet {
			return fmt.Errorf("unset recovery secret %s cannot be omitted", secret.ID)
		}
	}
	for id := range recovery.SecretValues {
		if _, ok := secretByID[id]; !ok {
			return fmt.Errorf("recovery contains material for unknown secret %s", id)
		}
	}

	for _, target := range snapshot.Targets {
		if target.ID == "" || target.Address == "" || target.SSHUser == "" {
			return errors.New("recovery package contains incomplete target identity")
		}
		if target.SSHIdentitySecretID != "" {
			secret, ok := secretByID[target.SSHIdentitySecretID]
			if !ok {
				return fmt.Errorf("target %s references missing ssh identity secret", target.ID)
			}
			if !secret.IsSet {
				return fmt.Errorf("target %s ssh identity secret is unset", target.ID)
			}
			if _, ok := recovery.SecretValues[target.SSHIdentitySecretID]; !ok {
				return fmt.Errorf("target %s ssh identity secret material is missing", target.ID)
			}
		}
		if err := validateDesired(target.Desired); err != nil {
			return fmt.Errorf("target %s desired state: %w", target.ID, err)
		}
	}
	cfg := snapshot.Sources.CustomModuleGithub
	if cfg != nil {
		if cfg.Owner == "" || cfg.Repository == "" || cfg.Ref == "" || cfg.PATSecretID == "" {
			return errors.New("recovery custom module github configuration is incomplete")
		}
		if _, ok := secretByID[cfg.PATSecretID]; !ok {
			return errors.New("recovery custom module github PAT metadata is missing")
		}
	}
	return nil
}

func (c *Change) DeleteBackup(id BackupArtifactID) error {
	if id == "" {
		return errors.New("backup artifact id is required")
	}
	result, err := c.conn.ExecContext(c.ctx, `DELETE FROM backups WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("delete backup artifact metadata: %w", err)
	}
	return requireOne(result, "backup artifact")
}
