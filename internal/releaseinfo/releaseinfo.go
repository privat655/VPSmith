package releaseinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/privat655/VPSmith/internal/sourcehash"
)

const manifestName = "manifest.json"

type Info struct {
	SchemaVersion int      `json:"schema_version"`
	Studio        Studio   `json:"studio"`
	Embedded      Embedded `json:"embedded"`
}

type Studio struct {
	Version string `json:"version"`
}

type Embedded struct {
	CloudInit Source `json:"cloud_init"`
	Core      Source `json:"core"`
	N8N       Source `json:"n8n"`
}

type Source struct {
	Version string `json:"version"`
	Path    string `json:"path,omitempty"`
	SHA256  string `json:"sha256"`
}

func Load(root string) (Info, error) {
	data, err := os.ReadFile(filepath.Join(root, manifestName))
	if err != nil {
		return Info{}, fmt.Errorf("read release manifest: %w", err)
	}
	var info Info
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&info); err != nil {
		return Info{}, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Info{}, err
	}
	if err := validateManifest(info); err != nil {
		return Info{}, err
	}
	for name, source := range map[string]Source{
		"cloud-init": info.Embedded.CloudInit,
		"core":       info.Embedded.Core,
		"n8n":        info.Embedded.N8N,
	} {
		path, err := sourceRoot(root, source.Path)
		if err != nil {
			return Info{}, fmt.Errorf("%s embedded source path: %w", name, err)
		}
		actual, err := TreeSHA256(path)
		if err != nil {
			return Info{}, fmt.Errorf("hash %s embedded source: %w", name, err)
		}
		if actual != source.SHA256 {
			return Info{}, fmt.Errorf("%s embedded source sha256 mismatch: manifest=%s actual=%s", name, source.SHA256, actual)
		}
	}
	return info, nil
}

func Refresh(root string, info Info) (Info, error) {
	if err := validateManifestMetadata(info); err != nil {
		return Info{}, err
	}
	for name, source := range map[string]*Source{
		"cloud-init": &info.Embedded.CloudInit,
		"core":       &info.Embedded.Core,
		"n8n":        &info.Embedded.N8N,
	} {
		path, err := sourceRoot(root, source.Path)
		if err != nil {
			return Info{}, fmt.Errorf("%s embedded source path: %w", name, err)
		}
		digest, err := TreeSHA256(path)
		if err != nil {
			return Info{}, fmt.Errorf("hash %s embedded source: %w", name, err)
		}
		source.SHA256 = digest
	}
	return info, nil
}

// TreeSHA256 is the release-tooling entry point into the single canonical VPSmith source hashing pipeline.
func TreeSHA256(root string) (string, error) {
	return sourcehash.TreeSHA256(root)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("release manifest contains trailing JSON data")
		}
		return fmt.Errorf("decode trailing release manifest data: %w", err)
	}
	return nil
}

func validateManifest(info Info) error {
	if err := validateManifestMetadata(info); err != nil {
		return err
	}
	for name, source := range map[string]Source{
		"cloud-init": info.Embedded.CloudInit,
		"core":       info.Embedded.Core,
		"n8n":        info.Embedded.N8N,
	} {
		if err := validateSHA256(source.SHA256); err != nil {
			return fmt.Errorf("%s sha256: %w", name, err)
		}
	}
	return nil
}

func validateManifestMetadata(info Info) error {
	if info.SchemaVersion != 1 {
		return fmt.Errorf("unsupported release manifest schema_version %d", info.SchemaVersion)
	}
	if strings.TrimSpace(info.Studio.Version) == "" {
		return errors.New("studio version is required")
	}
	for name, source := range map[string]Source{
		"cloud-init": info.Embedded.CloudInit,
		"core":       info.Embedded.Core,
		"n8n":        info.Embedded.N8N,
	} {
		if strings.TrimSpace(source.Version) == "" {
			return fmt.Errorf("%s version is required", name)
		}
		if err := validateRelativePath(source.Path); err != nil {
			return fmt.Errorf("%s path: %w", name, err)
		}
	}
	return nil
}

func sourceRoot(root, relative string) (string, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve embedded root: %w", err)
	}
	candidate := filepath.Join(root, filepath.FromSlash(relative))
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedCandidate)
	if err != nil {
		return "", err
	}
	if pathEscapesRoot(rel) {
		return "", fmt.Errorf("path %q escapes embedded root", relative)
	}
	return resolvedCandidate, nil
}

func validateRelativePath(value string) error {
	if value == "" {
		return errors.New("path is required")
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if filepath.IsAbs(clean) || clean == "." || pathEscapesRoot(clean) {
		return fmt.Errorf("path %q must stay inside embedded root", value)
	}
	if filepath.ToSlash(clean) != value {
		return fmt.Errorf("path %q must use a clean POSIX relative path", value)
	}
	return nil
}

func pathEscapesRoot(relative string) bool {
	return relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateSHA256(value string) error {
	if len(value) != sha256.Size*2 {
		return fmt.Errorf("must contain %d lowercase hexadecimal characters", sha256.Size*2)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return errors.New("must be lowercase hexadecimal")
	}
	return nil
}
