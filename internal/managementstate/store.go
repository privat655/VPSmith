package managementstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	databaseName  = "vpsmith.db"
	secretKeyName = "secret-store.key"
)

type Store struct {
	db  *sql.DB
	key []byte
}

type TargetRegistration struct {
	ID                  TargetID
	Address             string
	SSHUser             string
	SSHIdentitySecretID SecretID
	SSHHostKey          string
	SSHHostFingerprint  string
	SSHTrust            TrustStatus
}

func Open(stateDir string) (*Store, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create management-state directory: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("secure management-state directory: %w", err)
	}
	dbPath := filepath.Join(stateDir, databaseName)
	_, statErr := os.Stat(dbPath)
	dbExisted := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect management-state database: %w", statErr)
	}
	key, err := loadOrCreateKey(filepath.Join(stateDir, secretKeyName), dbExisted)
	if err != nil {
		return nil, err
	}
	store, err := openSQLite("file:"+filepath.ToSlash(dbPath), key)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("secure management-state database: %w", err)
	}
	return store, nil
}

func NewMemory() (*Store, error) {
	var key [secretKeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("generate memory secret key: %w", err)
	}
	id, err := newID("memory")
	if err != nil {
		return nil, err
	}
	return openSQLite("file:"+id+"?mode=memory&cache=shared", key[:])
}

func openSQLite(dsn string, key []byte) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open management-state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect management-state database: %w", err)
	}
	for _, pragma := range []string{"PRAGMA foreign_keys = ON", "PRAGMA journal_mode = DELETE", "PRAGMA synchronous = FULL", "PRAGMA busy_timeout = 5000"} {
		if _, err := conn.ExecContext(ctx, pragma); err != nil {
			_ = conn.Close()
			_ = db.Close()
			return nil, fmt.Errorf("configure management-state database: %w", err)
		}
	}
	if err := migrate(ctx, conn); err != nil {
		_ = conn.Close()
		_ = db.Close()
		return nil, err
	}
	if err := conn.Close(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("release management-state connection: %w", err)
	}
	return &Store{db: db, key: append([]byte(nil), key...)}, nil
}

func loadOrCreateKey(path string, databaseExisted bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, fmt.Errorf("inspect secret-store key: %w", statErr)
		}
		if info.Mode().Perm() != 0o600 {
			return nil, fmt.Errorf("secret-store key permissions must be 0600, got %04o", info.Mode().Perm())
		}
		if len(data) != secretKeySize {
			return nil, errors.New("secret-store key has invalid length")
		}
		return data, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read secret-store key: %w", err)
	}
	if databaseExisted {
		return nil, errors.New("management-state database exists but secret-store key is missing")
	}
	data = make([]byte, secretKeySize)
	if _, err := rand.Read(data); err != nil {
		return nil, fmt.Errorf("generate secret-store key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create secret-store key: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write secret-store key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync secret-store key: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close secret-store key: %w", err)
	}
	return data, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	for i := range s.key {
		s.key[i] = 0
	}
	return s.db.Close()
}

func (s *Store) Change(ctx context.Context, fn func(*Change) error) error {
	if fn == nil {
		return errors.New("management-state change function is required")
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire management-state writer: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin management-state change: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	change := &Change{store: s, conn: conn, ctx: ctx}
	if err := fn(change); err != nil {
		return fmt.Errorf("management-state change aborted: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit management-state change: %w", err)
	}
	committed = true
	return nil
}

type Change struct {
	store *Store
	conn  *sql.Conn
	ctx   context.Context
}

func (c *Change) CreateTarget(value TargetRegistration) error {
	if value.ID == "" || strings.TrimSpace(value.Address) == "" || strings.TrimSpace(value.SSHUser) == "" {
		return errors.New("target id, address, and ssh user are required")
	}
	if value.SSHTrust == "" {
		value.SSHTrust = TrustUnknown
	}
	if value.SSHTrust != TrustUnknown && value.SSHTrust != TrustConfirmed && value.SSHTrust != TrustBlocked {
		return errors.New("invalid ssh trust status")
	}
	if value.SSHIdentitySecretID != "" {
		if err := c.requireSecret(value.SSHIdentitySecretID); err != nil {
			return err
		}
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO targets(id,address,ssh_user,ssh_identity_secret_id,ssh_host_key,ssh_host_fingerprint,ssh_trust,desired_json,observed_json) VALUES(?,?,?,?,?,?,?,'{}','{}')`, value.ID, value.Address, value.SSHUser, value.SSHIdentitySecretID, value.SSHHostKey, value.SSHHostFingerprint, value.SSHTrust)
	if err != nil {
		return fmt.Errorf("create target %s: %w", value.ID, err)
	}
	return nil
}

func (c *Change) SetSSHTrust(targetID TargetID, hostKey, fingerprint string, trust TrustStatus) error {
	if trust != TrustUnknown && trust != TrustConfirmed && trust != TrustBlocked {
		return errors.New("invalid ssh trust status")
	}
	if err := c.rejectKnownSecretMaterial(struct{ HostKey, Fingerprint string }{hostKey, fingerprint}); err != nil {
		return err
	}
	result, err := c.conn.ExecContext(c.ctx, `UPDATE targets SET ssh_host_key=?, ssh_host_fingerprint=?, ssh_trust=? WHERE id=?`, hostKey, fingerprint, trust, targetID)
	if err != nil {
		return fmt.Errorf("update target ssh trust: %w", err)
	}
	return requireOne(result, "target")
}

func (c *Change) SetDesiredState(targetID TargetID, value DesiredState) error {
	if err := validateDesired(value); err != nil {
		return err
	}
	for _, module := range value.Modules {
		for _, id := range module.SecretIDs {
			if err := c.requireSecret(id); err != nil {
				return err
			}
		}
	}
	if err := c.rejectKnownSecretMaterial(value); err != nil {
		return err
	}
	data, err := marshalDomain(value)
	if err != nil {
		return err
	}
	result, err := c.conn.ExecContext(c.ctx, `UPDATE targets SET desired_json=? WHERE id=?`, string(data), targetID)
	if err != nil {
		return fmt.Errorf("set desired state: %w", err)
	}
	return requireOne(result, "target")
}

func (c *Change) RecordObservedState(targetID TargetID, value ObservedState) error {
	if err := c.rejectKnownSecretMaterial(value); err != nil {
		return err
	}
	data, err := marshalDomain(value)
	if err != nil {
		return err
	}
	result, err := c.conn.ExecContext(c.ctx, `UPDATE targets SET observed_json=? WHERE id=?`, string(data), targetID)
	if err != nil {
		return fmt.Errorf("record observed state: %w", err)
	}
	return requireOne(result, "target")
}

func (c *Change) PutCoreSource(value CoreSource) error {
	if value.ID == "" || strings.TrimSpace(value.Version) == "" || strings.TrimSpace(value.SHA256) == "" {
		return errors.New("core source id, version, and sha256 are required")
	}
	if value.Role != CoreSourceEmbedded && value.Role != CoreSourceLocal && value.Role != CoreSourceTarget {
		return errors.New("invalid core source role")
	}
	if value.Role == CoreSourceTarget && value.TargetID == "" {
		return errors.New("target core source requires target id")
	}
	if value.Role != CoreSourceTarget && value.TargetID != "" {
		return errors.New("only target core source may have target id")
	}
	if err := c.rejectKnownSecretMaterial(value); err != nil {
		return err
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO core_sources(id,role,target_id,version,sha256,base_source_id) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET role=excluded.role,target_id=excluded.target_id,version=excluded.version,sha256=excluded.sha256,base_source_id=excluded.base_source_id`, value.ID, value.Role, value.TargetID, value.Version, value.SHA256, value.BaseSourceID)
	if err != nil {
		return fmt.Errorf("put core source: %w", err)
	}
	return nil
}

func (c *Change) PutModuleSource(value ModuleSource) error {
	if value.PackageID == "" || strings.TrimSpace(value.Version) == "" || strings.TrimSpace(value.PackageSHA256) == "" {
		return errors.New("module source package id, version, and package sha256 are required")
	}
	if value.Role != ModuleSourceRemote && value.Role != ModuleSourceLocal && value.Role != ModuleSourceTarget {
		return errors.New("invalid module source role")
	}
	if value.Role == ModuleSourceTarget && value.TargetID == "" {
		return errors.New("target module source requires target id")
	}
	if value.Role != ModuleSourceTarget && value.TargetID != "" {
		return errors.New("only target module source may have target id")
	}
	if err := c.rejectKnownSecretMaterial(value); err != nil {
		return err
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO module_sources(package_id,role,target_id,owner,repository,ref,commit_sha,base_commit,version,package_sha256) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(package_id,role,target_id) DO UPDATE SET owner=excluded.owner,repository=excluded.repository,ref=excluded.ref,commit_sha=excluded.commit_sha,base_commit=excluded.base_commit,version=excluded.version,package_sha256=excluded.package_sha256`, value.PackageID, value.Role, value.TargetID, value.Owner, value.Repository, value.Ref, value.Commit, value.BaseCommit, value.Version, value.PackageSHA256)
	if err != nil {
		return fmt.Errorf("put module source: %w", err)
	}
	return nil
}

func (c *Change) CreateSecret(name string, origin SecretOrigin) (SecretID, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("secret name is required")
	}
	if origin != SecretGenerated && origin != SecretUser && origin != SecretSystem {
		return "", errors.New("invalid secret origin")
	}
	id, err := NewSecretID()
	if err != nil {
		return "", err
	}
	if err := c.rejectKnownSecretMaterial(name); err != nil {
		return "", err
	}
	_, err = c.conn.ExecContext(c.ctx, `INSERT INTO secrets(id,name,origin,created_at) VALUES(?,?,?,?)`, id, name, origin, nowUTC())
	if err != nil {
		return "", fmt.Errorf("create secret metadata: %w", err)
	}
	return id, nil
}

func (c *Change) SetSecret(id SecretID, value []byte) error {
	if len(value) == 0 {
		return errors.New("secret value must not be empty")
	}
	var exists int
	if err := c.conn.QueryRowContext(c.ctx, `SELECT COUNT(*) FROM secrets WHERE id=? AND ciphertext IS NULL`, id).Scan(&exists); err != nil {
		return fmt.Errorf("inspect secret: %w", err)
	}
	if exists != 1 {
		return errors.New("secret is missing or already set; use rotate for an existing value")
	}
	if err := c.assertMaterialAbsentFromDomain(value); err != nil {
		return err
	}
	ciphertext, err := encryptSecret(c.store.key, id, value)
	if err != nil {
		return err
	}
	_, err = c.conn.ExecContext(c.ctx, `UPDATE secrets SET ciphertext=? WHERE id=?`, ciphertext, id)
	if err != nil {
		return fmt.Errorf("set secret: %w", err)
	}
	return nil
}

func (c *Change) RotateSecret(id SecretID, value []byte) error {
	if len(value) == 0 {
		return errors.New("secret value must not be empty")
	}
	if err := c.assertMaterialAbsentFromDomain(value); err != nil {
		return err
	}
	ciphertext, err := encryptSecret(c.store.key, id, value)
	if err != nil {
		return err
	}
	result, err := c.conn.ExecContext(c.ctx, `UPDATE secrets SET ciphertext=?, rotated_at=?, rotation_count=rotation_count+1 WHERE id=? AND ciphertext IS NOT NULL`, ciphertext, nowUTC(), id)
	if err != nil {
		return fmt.Errorf("rotate secret: %w", err)
	}
	return requireOne(result, "set secret")
}

func (c *Change) DeleteSecret(id SecretID) error {
	referenced, err := c.secretReferenced(id)
	if err != nil {
		return err
	}
	if referenced {
		return fmt.Errorf("secret %s is still referenced", id)
	}
	result, err := c.conn.ExecContext(c.ctx, `DELETE FROM secrets WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return requireOne(result, "secret")
}

func (c *Change) AppendExecutionBundle(value ExecutionBundleMetadata) error {
	if value.ID == "" || value.TargetID == "" || strings.TrimSpace(value.Kind) == "" || strings.TrimSpace(value.Version) == "" || strings.TrimSpace(value.SHA256) == "" {
		return errors.New("execution bundle metadata is incomplete")
	}
	if value.CreatedAt == "" {
		value.CreatedAt = nowUTC()
	}
	if err := c.rejectKnownSecretMaterial(value); err != nil {
		return err
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO execution_bundles(id,target_id,kind,version,sha256,created_at) VALUES(?,?,?,?,?,?)`, value.ID, value.TargetID, value.Kind, value.Version, value.SHA256, value.CreatedAt)
	if err != nil {
		return fmt.Errorf("append execution bundle: %w", err)
	}
	return nil
}

func (c *Change) AppendExecutionRecord(value ExecutionRecordMetadata) error {
	if value.ID == "" || value.BundleID == "" || value.TargetID == "" || strings.TrimSpace(value.Outcome) == "" || value.StartedAt == "" {
		return errors.New("execution record metadata is incomplete")
	}
	if err := c.rejectKnownSecretMaterial(value); err != nil {
		return err
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO execution_records(id,bundle_id,target_id,outcome,started_at,finished_at) VALUES(?,?,?,?,?,?)`, value.ID, value.BundleID, value.TargetID, value.Outcome, value.StartedAt, value.FinishedAt)
	if err != nil {
		return fmt.Errorf("append execution record: %w", err)
	}
	return nil
}

func (c *Change) RegisterBackup(value BackupArtifactMetadata) error {
	if value.ID == "" || value.TargetID == "" || !validBackupType(value.Type) {
		return errors.New("backup artifact metadata is incomplete")
	}
	if value.Type == BackupModule || value.Type == BackupSystemRestorePoint {
		if value.ModuleInstanceID == "" {
			return errors.New("module backup artifact requires module instance id")
		}
	}
	if value.CreatedAt == "" {
		value.CreatedAt = nowUTC()
	}
	if err := c.rejectKnownSecretMaterial(value); err != nil {
		return err
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO backups(id,artifact_type,target_id,module_instance_id,created_at,location_ref,sha256) VALUES(?,?,?,?,?,?,?)`, value.ID, value.Type, value.TargetID, value.ModuleInstanceID, value.CreatedAt, value.LocationRef, value.SHA256)
	if err != nil {
		return fmt.Errorf("register backup artifact: %w", err)
	}
	return nil
}

func (c *Change) requireSecret(id SecretID) error {
	var count int
	if err := c.conn.QueryRowContext(c.ctx, `SELECT COUNT(*) FROM secrets WHERE id=?`, id).Scan(&count); err != nil {
		return fmt.Errorf("inspect secret reference: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("secret reference %s does not exist", id)
	}
	return nil
}

func (c *Change) secretReferenced(id SecretID) (bool, error) {
	var count int
	if err := c.conn.QueryRowContext(c.ctx, `SELECT COUNT(*) FROM targets WHERE ssh_identity_secret_id=?`, id).Scan(&count); err != nil {
		return false, fmt.Errorf("inspect ssh secret references: %w", err)
	}
	if count > 0 {
		return true, nil
	}
	rows, err := c.conn.QueryContext(c.ctx, `SELECT desired_json FROM targets`)
	if err != nil {
		return false, fmt.Errorf("inspect desired secret references: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return false, err
		}
		var desired DesiredState
		if err := json.Unmarshal([]byte(raw), &desired); err != nil {
			return false, fmt.Errorf("decode desired state: %w", err)
		}
		for _, module := range desired.Modules {
			for _, candidate := range module.SecretIDs {
				if candidate == id {
					return true, nil
				}
			}
		}
	}
	return false, rows.Err()
}

func (c *Change) rejectKnownSecretMaterial(value any) error {
	data, err := marshalDomain(value)
	if err != nil {
		return err
	}
	rows, err := c.conn.QueryContext(c.ctx, `SELECT id,ciphertext FROM secrets WHERE ciphertext IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("inspect secret material: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id SecretID
		var encrypted []byte
		if err := rows.Scan(&id, &encrypted); err != nil {
			return err
		}
		plain, err := decryptSecret(c.store.key, id, encrypted)
		if err != nil {
			return fmt.Errorf("verify secret %s before domain write: %w", id, err)
		}
		if len(plain) > 0 && bytes.Contains(data, plain) {
			return errors.New("domain write rejected because it contains secret material")
		}
	}
	return rows.Err()
}

func (c *Change) assertMaterialAbsentFromDomain(material []byte) error {
	if len(material) == 0 {
		return nil
	}
	rows, err := c.conn.QueryContext(c.ctx, `SELECT address,ssh_user,ssh_host_key,ssh_host_fingerprint,desired_json,observed_json FROM targets`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var fields [6]string
		if err := rows.Scan(&fields[0], &fields[1], &fields[2], &fields[3], &fields[4], &fields[5]); err != nil {
			return err
		}
		for _, field := range fields {
			if bytes.Contains([]byte(field), material) {
				return errors.New("secret value is already present in normal domain state")
			}
		}
	}
	for _, query := range []string{
		`SELECT name FROM secrets`,
		`SELECT version||sha256||base_source_id FROM core_sources`,
		`SELECT owner||repository||ref||commit_sha||base_commit||version||package_sha256 FROM module_sources`,
		`SELECT kind||version||sha256 FROM execution_bundles`,
		`SELECT outcome FROM execution_records`,
		`SELECT location_ref||sha256 FROM backups`,
	} {
		checkRows, err := c.conn.QueryContext(c.ctx, query)
		if err != nil {
			return err
		}
		for checkRows.Next() {
			var field string
			if err := checkRows.Scan(&field); err != nil {
				checkRows.Close()
				return err
			}
			if bytes.Contains([]byte(field), material) {
				checkRows.Close()
				return errors.New("secret value is already present in normal domain state")
			}
		}
		if err := checkRows.Close(); err != nil {
			return err
		}
	}
	return nil
}

func requireOne(result sql.Result, name string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("%s does not exist", name)
	}
	return nil
}

func (s *Store) ResolveSecret(ctx context.Context, id SecretID, consume func(SecretMaterial) error) error {
	if consume == nil {
		return errors.New("secret consumer is required")
	}
	var ciphertext []byte
	if err := s.db.QueryRowContext(ctx, `SELECT ciphertext FROM secrets WHERE id=?`, id).Scan(&ciphertext); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("secret %s does not exist", id)
		}
		return fmt.Errorf("read secret %s: %w", id, err)
	}
	if len(ciphertext) == 0 {
		return fmt.Errorf("secret %s has no value", id)
	}
	plain, err := decryptSecret(s.key, id, ciphertext)
	if err != nil {
		return fmt.Errorf("resolve secret %s: %w", id, err)
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	if err := consume(newSecretMaterial(plain)); err != nil {
		return errors.New("secret consumer failed")
	}
	return nil
}

func (s *Store) Snapshot(ctx context.Context) (Snapshot, error) {
	result := Snapshot{SchemaVersion: CurrentSchemaVersion}
	rows, err := s.db.QueryContext(ctx, `SELECT id,address,ssh_user,ssh_identity_secret_id,ssh_host_key,ssh_host_fingerprint,ssh_trust,desired_json,observed_json FROM targets ORDER BY id`)
	if err != nil {
		return result, fmt.Errorf("read targets: %w", err)
	}
	for rows.Next() {
		var item Target
		var desiredRaw, observedRaw string
		if err := rows.Scan(&item.ID, &item.Address, &item.SSHUser, &item.SSHIdentitySecretID, &item.SSHHostKey, &item.SSHHostFingerprint, &item.SSHTrust, &desiredRaw, &observedRaw); err != nil {
			rows.Close()
			return result, err
		}
		if err := json.Unmarshal([]byte(desiredRaw), &item.Desired); err != nil {
			rows.Close()
			return result, fmt.Errorf("decode desired state: %w", err)
		}
		if err := json.Unmarshal([]byte(observedRaw), &item.Observed); err != nil {
			rows.Close()
			return result, fmt.Errorf("decode observed state: %w", err)
		}
		result.Targets = append(result.Targets, item)
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	if err := s.readCoreSources(ctx, &result); err != nil {
		return result, err
	}
	if err := s.readModuleSources(ctx, &result); err != nil {
		return result, err
	}
	if err := s.readSecrets(ctx, &result); err != nil {
		return result, err
	}
	if err := s.readHistory(ctx, &result); err != nil {
		return result, err
	}
	if err := s.readBackups(ctx, &result); err != nil {
		return result, err
	}
	result.normalize()
	return result, nil
}

func (s *Store) readCoreSources(ctx context.Context, out *Snapshot) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,role,target_id,version,sha256,base_source_id FROM core_sources ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v CoreSource
		if err := rows.Scan(&v.ID, &v.Role, &v.TargetID, &v.Version, &v.SHA256, &v.BaseSourceID); err != nil {
			return err
		}
		out.CoreSources = append(out.CoreSources, v)
	}
	return rows.Err()
}
func (s *Store) readModuleSources(ctx context.Context, out *Snapshot) error {
	rows, err := s.db.QueryContext(ctx, `SELECT package_id,role,target_id,owner,repository,ref,commit_sha,base_commit,version,package_sha256 FROM module_sources ORDER BY package_id,role,target_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v ModuleSource
		if err := rows.Scan(&v.PackageID, &v.Role, &v.TargetID, &v.Owner, &v.Repository, &v.Ref, &v.Commit, &v.BaseCommit, &v.Version, &v.PackageSHA256); err != nil {
			return err
		}
		out.ModuleSources = append(out.ModuleSources, v)
	}
	return rows.Err()
}
func (s *Store) readSecrets(ctx context.Context, out *Snapshot) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,origin,created_at,rotated_at,rotation_count,ciphertext IS NOT NULL FROM secrets ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v SecretMetadata
		if err := rows.Scan(&v.ID, &v.Name, &v.Origin, &v.CreatedAt, &v.RotatedAt, &v.RotationCount, &v.IsSet); err != nil {
			return err
		}
		out.Secrets = append(out.Secrets, v)
	}
	return rows.Err()
}
func (s *Store) readHistory(ctx context.Context, out *Snapshot) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,target_id,kind,version,sha256,created_at FROM execution_bundles ORDER BY id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v ExecutionBundleMetadata
		if err := rows.Scan(&v.ID, &v.TargetID, &v.Kind, &v.Version, &v.SHA256, &v.CreatedAt); err != nil {
			rows.Close()
			return err
		}
		out.ExecutionBundles = append(out.ExecutionBundles, v)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT id,bundle_id,target_id,outcome,started_at,finished_at FROM execution_records ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v ExecutionRecordMetadata
		if err := rows.Scan(&v.ID, &v.BundleID, &v.TargetID, &v.Outcome, &v.StartedAt, &v.FinishedAt); err != nil {
			return err
		}
		out.ExecutionRecords = append(out.ExecutionRecords, v)
	}
	return rows.Err()
}
func (s *Store) readBackups(ctx context.Context, out *Snapshot) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,artifact_type,target_id,module_instance_id,created_at,location_ref,sha256 FROM backups ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v BackupArtifactMetadata
		if err := rows.Scan(&v.ID, &v.Type, &v.TargetID, &v.ModuleInstanceID, &v.CreatedAt, &v.LocationRef, &v.SHA256); err != nil {
			return err
		}
		out.Backups = append(out.Backups, v)
	}
	return rows.Err()
}
