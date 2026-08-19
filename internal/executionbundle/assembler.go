package executionbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/targetrunner"
)

type Assembler struct {
	root string
}

func NewAssembler(root string) (*Assembler, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("absolute bundle store path is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create bundle store: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("secure bundle store: %w", err)
	}
	return &Assembler{root: root}, nil
}

func (a *Assembler) Assemble(in Input) (Bundle, error) {
	if err := validateInput(in); err != nil {
		return Bundle{}, err
	}
	files, artifacts, actions, err := normalizeFiles(in)
	if err != nil {
		return Bundle{}, err
	}
	post, err := canonicalJSON(in.ExpectedPost)
	if err != nil {
		return Bundle{}, fmt.Errorf("encode expected post state: %w", err)
	}
	runnerBytes := targetrunner.Bytes()
	runnerSum := targetrunner.SHA256()
	files = append(files, File{Path: targetrunner.Path, Mode: 0o555, Data: runnerBytes})
	m := Manifest{
		FormatVersion: 2, Runner: RunnerIdentity{Version: targetrunner.Version, Path: targetrunner.Path, SHA256: runnerSum}, Kind: in.Kind, TargetID: in.TargetID, SubjectKind: in.SubjectKind, SubjectID: in.SubjectID,
		SubjectIdentity: in.SubjectIdentity, PackageID: in.PackageID, PackageSHA256: in.PackageSHA256, Version: in.Version,
		Sources: append([]SourceIdentity(nil), in.Sources...), Images: append([]ImageIdentity(nil), in.Images...), Artifacts: artifacts,
		Actions: actions, ActionWritablePaths: append([]string(nil), in.ActionWritablePaths...), Secrets: append([]SecretReference(nil), in.Secrets...), Preconditions: append([]Precondition(nil), in.Preconditions...),
		ExpectedPost: post, Validations: append([]ValidationSpec(nil), in.Validations...), Steps: append([]Step(nil), in.Steps...), BackupRequired: in.BackupRequired,
	}
	normalizeManifest(&m)
	identityBytes, err := canonicalJSON(m)
	if err != nil {
		return Bundle{}, err
	}
	identity := sha256.Sum256(identityBytes)
	m.BundleID = "bundle_" + hex.EncodeToString(identity[:16])
	manifestBytes, err := canonicalJSON(m)
	if err != nil {
		return Bundle{}, err
	}
	files = append(files, File{Path: "manifest.json", Mode: 0o444, Data: append(manifestBytes, '\n')})
	files = append(files, File{Path: "SHA256SUMS", Mode: 0o444, Data: checksumDocument(files)})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	payload, err := deterministicTar(files)
	if err != nil {
		return Bundle{}, err
	}
	sum := sha256.Sum256(payload)
	bundle := Bundle{ID: m.BundleID, Kind: in.Kind, SHA256: hex.EncodeToString(sum[:]), Bytes: payload, Manifest: m}
	if err := a.store(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (a *Assembler) Open(id string) (Bundle, error) {
	if !strings.HasPrefix(id, "bundle_") || strings.ContainsAny(id, "/\\\x00") {
		return Bundle{}, errors.New("invalid bundle id")
	}
	data, err := os.ReadFile(filepath.Join(a.root, id+".tar"))
	if err != nil {
		return Bundle{}, err
	}
	sum := sha256.Sum256(data)
	bundle := Bundle{ID: id, SHA256: hex.EncodeToString(sum[:]), Bytes: data}
	manifest, err := Verify(bundle)
	if err != nil {
		return Bundle{}, fmt.Errorf("verify stored execution bundle: %w", err)
	}
	bundle.Kind = manifest.Kind
	bundle.Manifest = manifest
	return bundle, nil
}

func (a *Assembler) store(bundle Bundle) error {
	name := filepath.Join(a.root, bundle.ID+".tar")
	if existing, err := os.ReadFile(name); err == nil {
		if bytes.Equal(existing, bundle.Bytes) {
			return nil
		}
		return fmt.Errorf("historical bundle %s already exists with different bytes", bundle.ID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return fmt.Errorf("create immutable bundle: %w", err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(bundle.Bytes); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(a.root)
	if err != nil {
		return fmt.Errorf("open bundle store directory: %w", err)
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return fmt.Errorf("sync bundle store directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("close bundle store directory: %w", err)
	}
	ok = true
	return nil
}
