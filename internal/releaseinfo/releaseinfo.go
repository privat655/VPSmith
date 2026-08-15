package releaseinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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

// Load reads the release manifest and verifies every embedded source tree against
// its declared SHA-256 identity before returning it to callers.
func Load(root string) (Info, error) {
	manifestPath := filepath.Join(root, manifestName)
	data, err := os.ReadFile(manifestPath)
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
		sourcePath, err := sourceRoot(root, source.Path)
		if err != nil {
			return Info{}, fmt.Errorf("%s embedded source path: %w", name, err)
		}
		actual, err := TreeSHA256(sourcePath)
		if err != nil {
			return Info{}, fmt.Errorf("hash %s embedded source: %w", name, err)
		}
		if actual != source.SHA256 {
			return Info{}, fmt.Errorf("%s embedded source sha256 mismatch: manifest=%s actual=%s", name, source.SHA256, actual)
		}
	}

	return info, nil
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

// Refresh recalculates the SHA-256 identities of the three embedded source
// trees while preserving their declared versions and paths. It is used only by
// the external build/release tooling that prepares the image inputs.
func Refresh(root string, info Info) (Info, error) {
	if err := validateManifestMetadata(info); err != nil {
		return Info{}, err
	}
	for name, source := range map[string]*Source{
		"cloud-init": &info.Embedded.CloudInit,
		"core":       &info.Embedded.Core,
		"n8n":        &info.Embedded.N8N,
	} {
		sourcePath, err := sourceRoot(root, source.Path)
		if err != nil {
			return Info{}, fmt.Errorf("%s embedded source path: %w", name, err)
		}
		digest, err := TreeSHA256(sourcePath)
		if err != nil {
			return Info{}, fmt.Errorf("hash %s embedded source: %w", name, err)
		}
		source.SHA256 = digest
	}
	return info, nil
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
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes embedded root", relative)
	}
	return resolvedCandidate, nil
}

func validateRelativePath(value string) error {
	if value == "" {
		return errors.New("path is required")
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q must stay inside embedded root", value)
	}
	if filepath.ToSlash(clean) != value {
		return fmt.Errorf("path %q must use a clean POSIX relative path", value)
	}
	return nil
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

// TreeSHA256 calculates the canonical identity of a source tree. Directory
// entries are omitted; regular files and symlinks are sorted by POSIX path.
// Each regular file contributes its path, Unix permissions, size, and content SHA-256. Symlinks
// contribute their path and target and are never followed.
func TreeSHA256(root string) (string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if rootInfo.Mode()&fs.ModeSymlink != 0 {
		return "", fmt.Errorf("%s must not be a symlink", root)
	}
	if !rootInfo.IsDir() {
		return "", fmt.Errorf("%s is not a directory", root)
	}

	type entry struct {
		path   string
		mode   fs.FileMode
		size   int64
		target string
		digest string
	}
	var entries []entry

	err = filepath.WalkDir(root, func(path string, dirEntry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || dirEntry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)

		info, err := dirEntry.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode().IsRegular():
			digest, err := fileSHA256(path)
			if err != nil {
				return err
			}
			entries = append(entries, entry{path: relative, mode: info.Mode(), size: info.Size(), digest: digest})
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			entries = append(entries, entry{path: relative, mode: info.Mode(), target: filepath.ToSlash(target)})
		default:
			return fmt.Errorf("unsupported source entry %s with mode %s", relative, info.Mode())
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", errors.New("source tree contains no files")
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	hash := sha256.New()
	for _, current := range entries {
		if current.mode&fs.ModeSymlink != 0 {
			writeCanonicalField(hash, "symlink")
			writeCanonicalField(hash, current.path)
			writeCanonicalField(hash, current.target)
			continue
		}
		writeCanonicalField(hash, "file")
		writeCanonicalField(hash, current.path)
		writeCanonicalField(hash, fmt.Sprintf("%04o", current.mode.Perm()))
		writeCanonicalField(hash, strconv.FormatInt(current.size, 10))
		writeCanonicalField(hash, current.digest)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeCanonicalField(writer io.Writer, value string) {
	_, _ = io.WriteString(writer, value)
	_, _ = writer.Write([]byte{0})
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
