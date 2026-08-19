package backuprestore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const FormatVersion = 1

type ArtifactIdentity struct {
	SubjectKind             string                     `yaml:"subject_kind"`
	SubjectID               string                     `yaml:"subject_id"`
	Version                 string                     `yaml:"version"`
	GitCommit               string                     `yaml:"git_commit,omitempty"`
	PackageSHA256           string                     `yaml:"package_sha256"`
	Images                  []ImageIdentity            `yaml:"images,omitempty"`
	StoragePaths            []string                   `yaml:"storage_paths,omitempty"`
	SecretIDs               []managementstate.SecretID `yaml:"secret_ids,omitempty"`
	PreviousDesiredStateRef string                     `yaml:"previous_desired_state_ref,omitempty"`
	ExecutionBundleRef      string                     `yaml:"execution_bundle_ref,omitempty"`
}

type ImageIdentity struct {
	Name   string `yaml:"name"`
	Digest string `yaml:"digest"`
}

type Manifest struct {
	FormatVersion    int                                `yaml:"format_version"`
	ArtifactType     managementstate.BackupArtifactType `yaml:"artifact_type"`
	ArtifactID       managementstate.BackupArtifactID   `yaml:"artifact_id"`
	CreatedAt        string                             `yaml:"created_at"`
	TargetID         managementstate.TargetID           `yaml:"target_id"`
	ModuleInstanceID managementstate.ModuleInstanceID   `yaml:"module_instance_id,omitempty"`
	Identity         *ArtifactIdentity                  `yaml:"identity,omitempty"`
	SourceRefs       []string                           `yaml:"source_refs,omitempty"`
	BundleRefs       []string                           `yaml:"bundle_refs,omitempty"`
	PayloadInventory []PayloadItem                      `yaml:"payload_inventory"`
	RestoreRefs      []string                           `yaml:"restore_refs,omitempty"`
}

type PayloadItem struct {
	Path     string `yaml:"path"`
	Kind     string `yaml:"kind"`
	LinkName string `yaml:"link_name,omitempty"`
}

type PayloadDescriptor struct {
	Identity    *ArtifactIdentity
	SourceRefs  []string
	BundleRefs  []string
	RestoreRefs []string
}

type PayloadProducer interface {
	Produce(context.Context, string) (PayloadDescriptor, error)
}

type CreateRequest struct {
	Type             managementstate.BackupArtifactType
	TargetID         managementstate.TargetID
	ModuleInstanceID managementstate.ModuleInstanceID
	Passphrase       []byte
	Producer         PayloadProducer
}

type Artifact struct {
	Metadata managementstate.BackupArtifactMetadata `json:"metadata"`
	Manifest Manifest                               `json:"manifest"`
	Path     string                                 `json:"-"`
}

type Inspection struct {
	Manifest    Manifest
	PayloadPath string
	workDir     string
}

func (i *Inspection) Close() error {
	if i == nil || i.workDir == "" {
		return nil
	}
	err := os.RemoveAll(i.workDir)
	i.workDir = ""
	i.PayloadPath = ""
	return err
}

type PreparedRestore struct {
	Manifest      Manifest
	CandidateRoot string
	workDir       string
}

func (p *PreparedRestore) Close() error {
	if p == nil || p.workDir == "" {
		return nil
	}
	err := os.RemoveAll(p.workDir)
	p.workDir = ""
	p.CandidateRoot = ""
	return err
}

type Manager struct {
	root    string
	scratch string
	state   *managementstate.Store
	now     func() time.Time
}

// New creates the backup catalogue and its volatile work area. scratch must be
// a separate absolute path; production composes it below /run/vpsmith so
// decrypted payloads and target storage copies never land in persistent backup
// storage.
func New(root, scratch string, state *managementstate.Store) (*Manager, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("absolute backup store path is required")
	}
	if scratch == "" || !filepath.IsAbs(scratch) {
		return nil, errors.New("absolute backup scratch path is required")
	}
	if sameOrWithin(root, scratch) || sameOrWithin(scratch, root) {
		return nil, errors.New("backup store and scratch paths must be separate")
	}
	if state == nil {
		return nil, errors.New("management state is required")
	}
	for label, path := range map[string]string{"backup store": root, "backup scratch": scratch} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", label, err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return nil, fmt.Errorf("secure %s: %w", label, err)
		}
	}
	return &Manager{root: root, scratch: scratch, state: state, now: time.Now}, nil
}

func (m *Manager) Create(ctx context.Context, request CreateRequest) (Artifact, error) {
	if err := validateCreateRequest(request); err != nil {
		return Artifact{}, err
	}
	id, err := managementstate.NewBackupArtifactID()
	if err != nil {
		return Artifact{}, err
	}
	work, err := m.newWorkDir("create")
	if err != nil {
		return Artifact{}, err
	}
	defer os.RemoveAll(work)

	payloadRoot := filepath.Join(work, "payload")
	if err := os.Mkdir(payloadRoot, 0o700); err != nil {
		return Artifact{}, err
	}
	descriptor, err := request.Producer.Produce(ctx, payloadRoot)
	if err != nil {
		return Artifact{}, fmt.Errorf("produce backup payload: %w", err)
	}
	payloadName := "payload.tar.zst"
	if request.Type == managementstate.BackupSystemRestorePoint {
		payloadName = "storage.tar.zst"
	}
	payloadArchive := filepath.Join(work, payloadName)
	if err := CreateTarZst(payloadRoot, payloadArchive); err != nil {
		return Artifact{}, err
	}
	entries, err := InspectTarZst(payloadArchive)
	if err != nil {
		return Artifact{}, err
	}
	manifest := Manifest{
		FormatVersion:    FormatVersion,
		ArtifactType:     request.Type,
		ArtifactID:       id,
		CreatedAt:        m.now().UTC().Format(time.RFC3339Nano),
		TargetID:         request.TargetID,
		ModuleInstanceID: request.ModuleInstanceID,
		Identity:         normalizeArtifactIdentity(descriptor.Identity),
		SourceRefs:       sortedUnique(descriptor.SourceRefs),
		BundleRefs:       sortedUnique(descriptor.BundleRefs),
		RestoreRefs:      sortedUnique(descriptor.RestoreRefs),
		PayloadInventory: inventory(entries),
	}
	if err := validateManifest(manifest, request.Type); err != nil {
		return Artifact{}, fmt.Errorf("validate backup manifest: %w", err)
	}
	if request.Type == managementstate.BackupSystemRestorePoint {
		return m.publishRestorePoint(ctx, payloadArchive, manifest)
	}
	return m.publishLongTerm(ctx, work, payloadArchive, manifest, request.Passphrase)
}

func (m *Manager) Inspect(ctx context.Context, filename string, expected managementstate.BackupArtifactType, passphrase []byte) (*Inspection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if filename == "" || !filepath.IsAbs(filename) {
		return nil, errors.New("absolute backup artifact path is required")
	}
	if expected == managementstate.BackupSystemRestorePoint {
		return inspectRestorePoint(filename, expected)
	}
	if !isLongTermType(expected) {
		return nil, errors.New("unknown backup artifact type")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("recovery passphrase is required")
	}
	work, err := m.newWorkDir("inspect")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Inspection, error) {
		_ = os.RemoveAll(work)
		return nil, err
	}
	outer := filepath.Join(work, "envelope.tar.zst")
	if err := decryptAge(filename, outer, passphrase); err != nil {
		return fail(err)
	}
	envelope := filepath.Join(work, "envelope")
	if err := ExtractTarZst(outer, envelope, ArchiveOptions{}); err != nil {
		return fail(fmt.Errorf("extract backup envelope: %w", err))
	}
	if err := requireExactEnvelope(envelope, "payload.tar.zst"); err != nil {
		return fail(err)
	}
	manifest, err := verifyEnvelope(envelope, "payload.tar.zst", expected)
	if err != nil {
		return fail(err)
	}
	payload := filepath.Join(envelope, "payload.tar.zst")
	entries, err := InspectTarZst(payload)
	if err != nil {
		return fail(fmt.Errorf("inspect backup payload: %w", err))
	}
	if !sameInventory(manifest.PayloadInventory, inventory(entries)) {
		return fail(errors.New("payload inventory does not match manifest"))
	}
	return &Inspection{Manifest: manifest, PayloadPath: payload, workDir: work}, nil
}

func (m *Manager) PrepareRestore(ctx context.Context, filename string, expected managementstate.BackupArtifactType, passphrase []byte) (*PreparedRestore, error) {
	inspection, err := m.Inspect(ctx, filename, expected, passphrase)
	if err != nil {
		return nil, err
	}
	work := inspection.workDir
	candidate := filepath.Join(work, "restore-candidate")
	if err := ExtractTarZst(inspection.PayloadPath, candidate, ArchiveOptions{}); err != nil {
		_ = inspection.Close()
		return nil, fmt.Errorf("prepare replace-not-merge candidate: %w", err)
	}
	manifest := inspection.Manifest
	inspection.workDir = ""
	return &PreparedRestore{Manifest: manifest, CandidateRoot: candidate, workDir: work}, nil
}

func (m *Manager) Export(ctx context.Context, id managementstate.BackupArtifactID, destination string) error {
	artifact, err := m.catalogEntry(ctx, id)
	if err != nil {
		return err
	}
	source, err := m.locationPath(artifact.LocationRef)
	if err != nil {
		return err
	}
	if destination == "" || !filepath.IsAbs(destination) {
		return errors.New("absolute export destination is required")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("only portable long-term backup files can be exported with this operation")
	}
	return copyFileExclusive(source, destination, 0o600)
}

func (m *Manager) Delete(ctx context.Context, id managementstate.BackupArtifactID) error {
	artifact, err := m.catalogEntry(ctx, id)
	if err != nil {
		return err
	}
	artifactPath, err := m.locationPath(artifact.LocationRef)
	if err != nil {
		return err
	}
	tombstone := filepath.Join(m.root, ".delete-"+string(id))
	if _, err := os.Lstat(tombstone); err == nil {
		return errors.New("backup deletion tombstone already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(artifactPath, tombstone); err != nil {
		return fmt.Errorf("stage backup artifact deletion: %w", err)
	}
	if err := m.state.Change(ctx, func(change *managementstate.Change) error {
		return change.DeleteBackup(id)
	}); err != nil {
		if rollbackErr := os.Rename(tombstone, artifactPath); rollbackErr != nil {
			return fmt.Errorf("delete backup catalogue entry: %w; restore artifact after failed catalogue delete: %v", err, rollbackErr)
		}
		return err
	}
	if err := os.RemoveAll(tombstone); err != nil {
		return fmt.Errorf("cleanup deleted backup artifact bytes: %w", err)
	}
	return nil
}

func (m *Manager) Root() string { return m.root }

func (m *Manager) publishLongTerm(ctx context.Context, work, payloadArchive string, manifest Manifest, passphrase []byte) (Artifact, error) {
	manifestBytes, err := yaml.Marshal(manifest)
	if err != nil {
		return Artifact{}, err
	}
	manifestFile := filepath.Join(work, "manifest.yaml")
	if err := os.WriteFile(manifestFile, manifestBytes, 0o600); err != nil {
		return Artifact{}, err
	}
	sums, err := checksumDocument(work, []string{"manifest.yaml", "payload.tar.zst"})
	if err != nil {
		return Artifact{}, err
	}
	if err := os.WriteFile(filepath.Join(work, "SHA256SUMS"), sums, 0o600); err != nil {
		return Artifact{}, err
	}
	envelopeRoot := filepath.Join(work, "envelope-root")
	if err := os.Mkdir(envelopeRoot, 0o700); err != nil {
		return Artifact{}, err
	}
	for _, name := range []string{"manifest.yaml", "payload.tar.zst", "SHA256SUMS"} {
		if err := copyFileExclusive(filepath.Join(work, name), filepath.Join(envelopeRoot, name), 0o600); err != nil {
			return Artifact{}, err
		}
	}
	outerTar := filepath.Join(work, "envelope.tar.zst")
	if err := CreateTarZst(envelopeRoot, outerTar); err != nil {
		return Artifact{}, err
	}
	candidate := filepath.Join(work, fmt.Sprintf("%s-%s.tar.zst.age.candidate", manifest.ArtifactType, manifest.ArtifactID))
	if err := encryptAge(outerTar, candidate, passphrase); err != nil {
		return Artifact{}, err
	}
	if err := m.verifyLongTermCandidate(ctx, candidate, manifest.ArtifactType, passphrase); err != nil {
		return Artifact{}, fmt.Errorf("verify encrypted backup candidate: %w", err)
	}
	name := fmt.Sprintf("%s-%s.tar.zst.age", manifest.ArtifactType, manifest.ArtifactID)
	final := filepath.Join(m.root, name)
	if err := publishFileExclusive(candidate, final, 0o600); err != nil {
		return Artifact{}, fmt.Errorf("publish encrypted backup: %w", err)
	}
	sha, err := fileSHA256(final)
	if err != nil {
		_ = os.Remove(final)
		return Artifact{}, err
	}
	metadata := managementstate.BackupArtifactMetadata{
		ID:               manifest.ArtifactID,
		Type:             manifest.ArtifactType,
		TargetID:         manifest.TargetID,
		ModuleInstanceID: manifest.ModuleInstanceID,
		CreatedAt:        manifest.CreatedAt,
		LocationRef:      name,
		SHA256:           sha,
	}
	if err := m.state.Change(ctx, func(change *managementstate.Change) error {
		return change.RegisterBackup(metadata)
	}); err != nil {
		_ = os.Remove(final)
		return Artifact{}, err
	}
	return Artifact{Metadata: metadata, Manifest: manifest, Path: final}, nil
}

func (m *Manager) publishRestorePoint(ctx context.Context, payloadArchive string, manifest Manifest) (Artifact, error) {
	name := fmt.Sprintf("%s-%s", manifest.ArtifactType, manifest.ArtifactID)
	final := filepath.Join(m.root, name)
	candidate, err := os.MkdirTemp(m.scratch, ".restore-point-*")
	if err != nil {
		return Artifact{}, err
	}
	defer os.RemoveAll(candidate)

	manifestBytes, err := yaml.Marshal(manifest)
	if err != nil {
		return Artifact{}, err
	}
	if err := os.WriteFile(filepath.Join(candidate, "manifest.yaml"), manifestBytes, 0o600); err != nil {
		return Artifact{}, err
	}
	if err := copyFileExclusive(payloadArchive, filepath.Join(candidate, "storage.tar.zst"), 0o600); err != nil {
		return Artifact{}, err
	}
	sums, err := checksumDocument(candidate, []string{"manifest.yaml", "storage.tar.zst"})
	if err != nil {
		return Artifact{}, err
	}
	if err := os.WriteFile(filepath.Join(candidate, "SHA256SUMS"), sums, 0o600); err != nil {
		return Artifact{}, err
	}
	inspection, err := inspectRestorePoint(candidate, manifest.ArtifactType)
	if err != nil {
		return Artifact{}, fmt.Errorf("verify system restore point candidate: %w", err)
	}
	_ = inspection.Close()
	sha, err := treeEnvelopeSHA(candidate, []string{"manifest.yaml", "storage.tar.zst", "SHA256SUMS"})
	if err != nil {
		return Artifact{}, err
	}
	if err := publishDirectoryExclusive(candidate, final); err != nil {
		return Artifact{}, fmt.Errorf("publish system restore point: %w", err)
	}
	metadata := managementstate.BackupArtifactMetadata{
		ID:               manifest.ArtifactID,
		Type:             manifest.ArtifactType,
		TargetID:         manifest.TargetID,
		ModuleInstanceID: manifest.ModuleInstanceID,
		CreatedAt:        manifest.CreatedAt,
		LocationRef:      name,
		SHA256:           sha,
	}
	if err := m.state.Change(ctx, func(change *managementstate.Change) error {
		return change.RegisterBackup(metadata)
	}); err != nil {
		_ = os.RemoveAll(final)
		return Artifact{}, err
	}
	return Artifact{Metadata: metadata, Manifest: manifest, Path: final}, nil
}

func (m *Manager) verifyLongTermCandidate(ctx context.Context, candidate string, expected managementstate.BackupArtifactType, passphrase []byte) error {
	inspection, err := m.Inspect(ctx, candidate, expected, passphrase)
	if err != nil {
		return err
	}
	return inspection.Close()
}

func (m *Manager) newWorkDir(kind string) (string, error) {
	work, err := os.MkdirTemp(m.scratch, "."+kind+"-*")
	if err != nil {
		return "", fmt.Errorf("create volatile backup work directory: %w", err)
	}
	if err := os.Chmod(work, 0o700); err != nil {
		_ = os.RemoveAll(work)
		return "", fmt.Errorf("secure volatile backup work directory: %w", err)
	}
	return work, nil
}

func normalizeArtifactIdentity(value *ArtifactIdentity) *ArtifactIdentity {
	if value == nil {
		return nil
	}
	out := *value
	out.StoragePaths = sortedUnique(value.StoragePaths)
	out.Images = append([]ImageIdentity(nil), value.Images...)
	out.SecretIDs = append([]managementstate.SecretID(nil), value.SecretIDs...)
	return &out
}
