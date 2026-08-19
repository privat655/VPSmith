package backuprestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"go.yaml.in/yaml/v3"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const FormatVersion = 1

type Manifest struct {
	FormatVersion    int                                `yaml:"format_version"`
	ArtifactType     managementstate.BackupArtifactType `yaml:"artifact_type"`
	ArtifactID       managementstate.BackupArtifactID   `yaml:"artifact_id"`
	CreatedAt        string                             `yaml:"created_at"`
	TargetID         managementstate.TargetID           `yaml:"target_id"`
	ModuleInstanceID managementstate.ModuleInstanceID   `yaml:"module_instance_id,omitempty"`
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
	root  string
	state *managementstate.Store
	now   func() time.Time
}

func New(root string, state *managementstate.Store) (*Manager, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("absolute backup store path is required")
	}
	if state == nil {
		return nil, errors.New("management state is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create backup store: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("secure backup store: %w", err)
	}
	return &Manager{root: root, state: state, now: time.Now}, nil
}

func (m *Manager) Create(ctx context.Context, request CreateRequest) (Artifact, error) {
	if err := validateCreateRequest(request); err != nil {
		return Artifact{}, err
	}
	id, err := managementstate.NewBackupArtifactID()
	if err != nil {
		return Artifact{}, err
	}
	createdAt := m.now().UTC().Format(time.RFC3339Nano)
	work, err := os.MkdirTemp(m.root, ".create-*")
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
		FormatVersion: FormatVersion, ArtifactType: request.Type, ArtifactID: id,
		CreatedAt: createdAt, TargetID: request.TargetID, ModuleInstanceID: request.ModuleInstanceID,
		SourceRefs: sortedUnique(descriptor.SourceRefs), BundleRefs: sortedUnique(descriptor.BundleRefs),
		RestoreRefs: sortedUnique(descriptor.RestoreRefs), PayloadInventory: inventory(entries),
	}
	if request.Type == managementstate.BackupSystemRestorePoint {
		return m.publishRestorePoint(ctx, work, payloadArchive, manifest)
	}
	return m.publishLongTerm(ctx, work, payloadArchive, manifest, request.Passphrase)
}

func (m *Manager) Inspect(ctx context.Context, filename string, expected managementstate.BackupArtifactType, passphrase []byte) (*Inspection, error) {
	_ = ctx
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
	work, err := os.MkdirTemp(m.root, ".inspect-*")
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
	_ = ctx
	artifact, err := m.catalogEntry(context.Background(), id)
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
	return copyFileExclusive(source, destination, 0o600)
}

func (m *Manager) Delete(ctx context.Context, id managementstate.BackupArtifactID) error {
	artifact, err := m.catalogEntry(ctx, id)
	if err != nil {
		return err
	}
	path, err := m.locationPath(artifact.LocationRef)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("delete backup artifact bytes: %w", err)
	}
	return m.state.Change(ctx, func(change *managementstate.Change) error {
		return change.DeleteBackup(id)
	})
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
	candidateName := fmt.Sprintf("%s-%s.tar.zst.age.candidate", manifest.ArtifactType, manifest.ArtifactID)
	candidate := filepath.Join(work, candidateName)
	if err := encryptAge(outerTar, candidate, passphrase); err != nil {
		return Artifact{}, err
	}
	// Verify the exact ciphertext candidate before it becomes a cataloged
artifact.
	if _, err := m.inspectCandidate(candidate, manifest.ArtifactType, passphrase); err != nil {
		return Artifact{}, fmt.Errorf("verify encrypted backup candidate: %w", err)
	}
	name := fmt.Sprintf("%s-%s.tar.zst.age", manifest.ArtifactType, manifest.ArtifactID)
	final := filepath.Join(m.root, name)
	if err := os.Rename(candidate, final); err != nil {
		return Artifact{}, fmt.Errorf("publish encrypted backup: %w", err)
	}
	sha, err := fileSHA256(final)
	if err != nil {
		_ = os.Remove(final)
		return Artifact{}, err
	}
	metadata := managementstate.BackupArtifactMetadata{
		ID: manifest.ArtifactID, Type: manifest.ArtifactType, TargetID: manifest.TargetID, ModuleInstanceID: manifest.ModuleInstanceID,
		CreatedAt: manifest.CreatedAt, LocationRef: name, SHA256: sha,
	}
	if err := m.state.Change(ctx, func(change *managementstate.Change) error {
		return change.RegisterBackup(metadata)
	}); err != nil {
		_ = os.Remove(final)
		return Artifact{}, err
	}
	return Artifact{Metadata: metadata, Manifest: manifest, Path: final}, nil
}

func (m *Manager) publishRestorePoint(ctx context.Context, work, payloadArchive string, manifest Manifest) (Artifact, error) {
	manifestBytes, err := yaml.Marshal(manifest)
	if err != nil {
		return Artifact{}, err
	}
	name := fmt.Sprintf("%s-%s", manifest.ArtifactType, manifest.ArtifactID)
	final := filepath.Join(m.root, name)
	if err := os.Mkdir(final, 0o700); err != nil {
		return Artifact{}, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(final)
		}
	}()
	if err := os.WriteFile(filepath.Join(final, "manifest.yaml"), manifestBytes, 0o600); err != nil {
		return Artifact{}, err
	}
	if err := copyFileExclusive(payloadArchive, filepath.Join(final, "storage.tar.zst"), 0o600); err != nil {
		return Artifact{}, err
	}
	sums, err := checksumDocument(final, []string{"manifest.yaml", "storage.tar.zst"})
	if err != nil {
		return Artifact{}, err
	}
	if err := os.WriteFile(filepath.Join(final, "SHA256SUMS"), sums, 0o600); err != nil {
		return Artifact{}, err
	}
	if _, err := inspectRestorePoint(final, manifest.ArtifactType); err != nil {
		return Artifact{}, fmt.Errorf("verify system restore point candidate: %w", err)
	}
	sha, err := treeEnvelopeSHA(final, []string{"manifest.yaml", "storage.tar.zst", "SHA256SUMS"})
	if err != nil {
		return Artifact{}, err
	}
	metadata := managementstate.BackupArtifactMetadata{ID: manifest.ArtifactID, Type: manifest.ArtifactType, TargetID: manifest.TargetID, ModuleInstanceID: manifest.ModuleInstanceID, CreatedAt: manifest.CreatedAt, LocationRef: name, SHA256: sha}
	if err := m.state.Change(ctx, func(change *managementstate.Change) error {
		return change.RegisterBackup(metadata)
	}); err != nil {
		return Artifact{}, err
	}
	ok = true
	return Artifact{Metadata: metadata, Manifest: manifest, Path: final}, nil
}
