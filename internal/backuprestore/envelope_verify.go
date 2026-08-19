package backuprestore

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/privat655/VPSmith/internal/managementstate"
)

func checksumDocument(root string, names []string) ([]byte, error) {
	var buffer bytes.Buffer
	for _, name := range names {
		if name == "" || filepath.Base(name) != name {
			return nil, errors.New("checksum entry name must be a simple filename")
		}
		digest, err := fileSHA256(filepath.Join(root, name))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&buffer, "%s  %s\n", digest, name)
	}
	return buffer.Bytes(), nil
}

func verifyChecksums(root string, expectedNames []string) error {
	data, err := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
	if err != nil {
		return fmt.Errorf("read SHA256SUMS: %w", err)
	}
	expected := make(map[string]struct{}, len(expectedNames))
	for _, name := range expectedNames {
		expected[name] = struct{}{}
	}
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 2 || !validSHA256(fields[0]) || filepath.Base(fields[1]) != fields[1] {
			return errors.New("invalid SHA256SUMS entry")
		}
		if _, ok := expected[fields[1]]; !ok {
			return fmt.Errorf("unexpected checksum entry %q", fields[1])
		}
		if _, ok := seen[fields[1]]; ok {
			return fmt.Errorf("duplicate checksum entry %q", fields[1])
		}
		actual, err := fileSHA256(filepath.Join(root, fields[1]))
		if err != nil {
			return err
		}
		if actual != fields[0] {
			return fmt.Errorf("checksum mismatch for %s", fields[1])
		}
		seen[fields[1]] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return errors.New("SHA256SUMS is incomplete")
	}
	return nil
}

func requireExactEnvelope(root, payloadName string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	expected := map[string]struct{}{"manifest.yaml": {}, payloadName: {}, "SHA256SUMS": {}}
	if len(entries) != len(expected) {
		return errors.New("backup envelope contains unexpected entries")
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("backup envelope contains unexpected entry %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("backup envelope entry %q is not a regular file", entry.Name())
		}
	}
	return nil
}

func verifyEnvelope(root, payloadName string, expected managementstate.BackupArtifactType) (Manifest, error) {
	if err := requireExactEnvelope(root, payloadName); err != nil {
		return Manifest{}, err
	}
	if err := verifyChecksums(root, []string{"manifest.yaml", payloadName}); err != nil {
		return Manifest{}, err
	}
	manifest, err := readManifest(filepath.Join(root, "manifest.yaml"))
	if err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(manifest, expected); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func readManifest(filename string) (Manifest, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode backup manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Manifest{}, errors.New("backup manifest contains multiple YAML documents")
		}
		return Manifest{}, fmt.Errorf("decode trailing backup manifest data: %w", err)
	}
	return manifest, nil
}

func validateManifest(manifest Manifest, expected managementstate.BackupArtifactType) error {
	if manifest.FormatVersion != FormatVersion {
		return fmt.Errorf("unsupported backup format version %d", manifest.FormatVersion)
	}
	if manifest.ArtifactType != expected {
		return fmt.Errorf("backup artifact type %q does not match expected %q", manifest.ArtifactType, expected)
	}
	if manifest.ArtifactID == "" || manifest.TargetID == "" || strings.TrimSpace(manifest.CreatedAt) == "" {
		return errors.New("backup manifest identity is incomplete")
	}
	if expected == managementstate.BackupModule || expected == managementstate.BackupSystemRestorePoint {
		if manifest.ModuleInstanceID == "" {
			return errors.New("module backup manifest is missing module instance id")
		}
		if err := validateModuleArtifactIdentity(manifest); err != nil {
			return err
		}
	} else if manifest.ModuleInstanceID != "" {
		return errors.New("non-module backup manifest carries module instance id")
	}
	for _, item := range manifest.PayloadInventory {
		if item.Path == "" || item.Kind == "unknown" {
			return errors.New("backup payload inventory is invalid")
		}
	}
	return nil
}

func validateModuleArtifactIdentity(manifest Manifest) error {
	identity := manifest.Identity
	if identity == nil {
		return errors.New("module backup manifest is missing exact artifact identity")
	}
	if identity.SubjectKind != "module" || strings.TrimSpace(identity.SubjectID) == "" || strings.TrimSpace(identity.Version) == "" || !validGitCommit(identity.GitCommit) || !validSHA256(identity.PackageSHA256) {
		return errors.New("module backup manifest has incomplete module identity")
	}
	if len(identity.Images) == 0 {
		return errors.New("module backup manifest is missing image identities")
	}
	seenImages := map[string]struct{}{}
	for _, image := range identity.Images {
		if strings.TrimSpace(image.Name) == "" || !strings.HasPrefix(image.Digest, "sha256:") || !validSHA256(strings.TrimPrefix(image.Digest, "sha256:")) {
			return errors.New("module backup manifest has invalid image identity")
		}
		if _, exists := seenImages[image.Name]; exists {
			return errors.New("module backup manifest has duplicate image identity")
		}
		seenImages[image.Name] = struct{}{}
	}
	if len(identity.StoragePaths) == 0 {
		return errors.New("module backup manifest is missing declared storage paths")
	}
	for _, storagePath := range identity.StoragePaths {
		if storagePath == "" || !strings.HasPrefix(storagePath, "/") || filepath.Clean(storagePath) != storagePath || storagePath == "/" {
			return errors.New("module backup manifest has invalid storage path")
		}
	}
	seenSecrets := map[managementstate.SecretID]struct{}{}
	for _, secretID := range identity.SecretIDs {
		if secretID == "" {
			return errors.New("module backup manifest has empty secret id")
		}
		if _, exists := seenSecrets[secretID]; exists {
			return errors.New("module backup manifest has duplicate secret id")
		}
		seenSecrets[secretID] = struct{}{}
	}
	if manifest.ArtifactType == managementstate.BackupSystemRestorePoint && strings.TrimSpace(identity.PreviousDesiredStateRef) == "" && strings.TrimSpace(identity.ExecutionBundleRef) == "" {
		return errors.New("system restore point is missing previous desired state or execution bundle reference")
	}
	return nil
}

func validGitCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func inspectRestorePoint(filename string, expected managementstate.BackupArtifactType) (*Inspection, error) {
	if expected != managementstate.BackupSystemRestorePoint {
		return nil, errors.New("restore point inspection requires system restore point type")
	}
	if filename == "" || !filepath.IsAbs(filename) {
		return nil, errors.New("absolute restore point path is required")
	}
	if err := requireExactEnvelope(filename, "storage.tar.zst"); err != nil {
		return nil, err
	}
	manifest, err := verifyEnvelope(filename, "storage.tar.zst", expected)
	if err != nil {
		return nil, err
	}
	payload := filepath.Join(filename, "storage.tar.zst")
	entries, err := InspectTarZst(payload)
	if err != nil {
		return nil, err
	}
	if !sameInventory(manifest.PayloadInventory, inventory(entries)) {
		return nil, errors.New("restore point inventory does not match manifest")
	}
	return &Inspection{Manifest: manifest, PayloadPath: payload}, nil
}
