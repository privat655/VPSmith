package executionbundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// Verify treats Bundle.Bytes as the only trust source. It validates the outer
// digest, safe archive shape, payload checksums and manifest identity, then
// returns the manifest parsed from those verified bytes. Bundle.Manifest is a
// convenience view and is deliberately not trusted by this function.
func Verify(bundle Bundle) (Manifest, error) {
	if bundle.ID == "" || bundle.SHA256 == "" || len(bundle.Bytes) == 0 {
		return Manifest{}, errors.New("complete execution bundle is required")
	}
	outer := sha256.Sum256(bundle.Bytes)
	if hex.EncodeToString(outer[:]) != bundle.SHA256 {
		return Manifest{}, errors.New("execution bundle sha256 does not match bytes")
	}

	files := map[string][]byte{}
	reader := tar.NewReader(bytes.NewReader(bundle.Bytes))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("read execution bundle archive: %w", err)
		}
		if !safeArchivePath(header.Name) || header.Typeflag != tar.TypeReg {
			return Manifest{}, fmt.Errorf("unsafe execution bundle member %q", header.Name)
		}
		if _, exists := files[header.Name]; exists {
			return Manifest{}, fmt.Errorf("duplicate execution bundle member %s", header.Name)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return Manifest{}, fmt.Errorf("read execution bundle member %s: %w", header.Name, err)
		}
		files[header.Name] = data
	}

	manifestBytes, ok := files["manifest.json"]
	if !ok {
		return Manifest{}, errors.New("execution bundle manifest is missing")
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode execution bundle manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Manifest{}, err
	}
	if manifest.FormatVersion != 2 {
		return Manifest{}, fmt.Errorf("unsupported execution bundle format version %d", manifest.FormatVersion)
	}
	if manifest.BundleID != bundle.ID {
		return Manifest{}, errors.New("execution bundle id does not match manifest")
	}
	if manifest.Runner.Version == "" || !safeArchivePath(manifest.Runner.Path) || !validSHA256(manifest.Runner.SHA256) {
		return Manifest{}, errors.New("execution bundle runner identity is invalid")
	}
	if err := verifyPayloadChecksums(files); err != nil {
		return Manifest{}, err
	}
	runnerBytes, ok := files[manifest.Runner.Path]
	if !ok {
		return Manifest{}, errors.New("execution bundle runner payload is missing")
	}
	runnerSum := sha256.Sum256(runnerBytes)
	if hex.EncodeToString(runnerSum[:]) != manifest.Runner.SHA256 {
		return Manifest{}, errors.New("execution bundle runner sha256 does not match payload")
	}

	identityManifest := manifest
	identityManifest.BundleID = ""
	identityBytes, err := canonicalJSON(identityManifest)
	if err != nil {
		return Manifest{}, fmt.Errorf("canonicalize execution bundle identity: %w", err)
	}
	identity := sha256.Sum256(identityBytes)
	if want := "bundle_" + hex.EncodeToString(identity[:16]); want != bundle.ID {
		return Manifest{}, errors.New("execution bundle content-derived id is invalid")
	}
	return manifest, nil
}

func safeArchivePath(value string) bool {
	return value != "" && path.Clean(value) == value && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && !strings.ContainsAny(value, "\\\r\n\x00")
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode execution bundle manifest trailer: %w", err)
	}
	return errors.New("execution bundle manifest contains multiple JSON values")
}

func verifyPayloadChecksums(files map[string][]byte) error {
	document, ok := files["SHA256SUMS"]
	if !ok {
		return errors.New("execution bundle SHA256SUMS is missing")
	}
	listed := map[string]struct{}{}
	for _, line := range strings.Split(strings.TrimSuffix(string(document), "\n"), "\n") {
		if line == "" {
			continue
		}
		digest, name, ok := strings.Cut(line, "  ")
		if !ok || !validSHA256(digest) || !safeArchivePath(name) || name == "SHA256SUMS" {
			return errors.New("execution bundle SHA256SUMS is invalid")
		}
		if _, duplicate := listed[name]; duplicate {
			return fmt.Errorf("duplicate execution bundle checksum for %s", name)
		}
		data, exists := files[name]
		if !exists {
			return fmt.Errorf("execution bundle checksum references missing member %s", name)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			return fmt.Errorf("execution bundle member hash mismatch: %s", name)
		}
		listed[name] = struct{}{}
	}
	for name := range files {
		if name == "SHA256SUMS" {
			continue
		}
		if _, ok := listed[name]; !ok {
			return fmt.Errorf("execution bundle payload is not covered by SHA256SUMS: %s", name)
		}
	}
	return nil
}
