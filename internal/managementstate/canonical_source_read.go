package managementstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// readCanonicalSources reads Source Library metadata without taking Store.mu.
// Callers either hold the read lock already (Snapshot) or are themselves the
// locked public Sources method. Keeping one query implementation prevents the
// aggregate management snapshot and Source Library from drifting apart.
func (s *Store) readCanonicalSources(ctx context.Context) (SourceState, error) {
	var out SourceState
	rows, err := s.db.QueryContext(ctx, `SELECT id,kind,package_id,package_path,version,commit_sha,sha256,storage_ref FROM source_artifacts ORDER BY id`)
	if err != nil { return out, fmt.Errorf("read source artifacts: %w", err) }
	for rows.Next() {
		var v SourceArtifact
		if err := rows.Scan(&v.ID, &v.Kind, &v.PackageID, &v.PackagePath, &v.Version, &v.Commit, &v.SHA256, &v.StorageRef); err != nil {
			rows.Close(); return out, err
		}
		out.Artifacts = append(out.Artifacts, v)
	}
	if err := rows.Close(); err != nil { return out, err }
	rows, err = s.db.QueryContext(ctx, `SELECT id,kind,package_id,package_path,base_source_id,base_commit,current_sha256,storage_ref,synchronized_commit FROM source_workspaces ORDER BY id`)
	if err != nil { return out, fmt.Errorf("read source workspaces: %w", err) }
	for rows.Next() {
		var v SourceWorkspace
		if err := rows.Scan(&v.ID, &v.Kind, &v.PackageID, &v.PackagePath, &v.BaseSourceID, &v.BaseCommit, &v.CurrentSHA256, &v.StorageRef, &v.SynchronizedCommit); err != nil {
			rows.Close(); return out, err
		}
		out.Workspaces = append(out.Workspaces, v)
	}
	if err := rows.Close(); err != nil { return out, err }
	var cfg CustomModuleGithubConfig
	err = s.db.QueryRowContext(ctx, `SELECT owner,repository,ref,pat_secret_id FROM custom_module_github WHERE singleton=1`).Scan(&cfg.Owner, &cfg.Repository, &cfg.Ref, &cfg.PATSecretID)
	if err == nil { out.CustomModuleGithub = &cfg } else if !errors.Is(err, sql.ErrNoRows) { return out, fmt.Errorf("read custom module github configuration: %w", err) }
	if out.Artifacts == nil { out.Artifacts = []SourceArtifact{} }
	if out.Workspaces == nil { out.Workspaces = []SourceWorkspace{} }
	return out, nil
}
