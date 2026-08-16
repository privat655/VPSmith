package sourcehash

import (
	"crypto/sha256"
	"encoding/hex"
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

// TreeSHA256 computes the canonical VPSmith package identity. Paths are sorted
// POSIX-relative names. Regular files contribute path, mode, byte size and
// content SHA-256; safe relative symlinks contribute path and target. Git
// metadata and local editor/OS noise are excluded before hashing.
func TreeSHA256(root string) (string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if rootInfo.Mode()&fs.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", fmt.Errorf("%s must be a real directory", root)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve source root: %w", err)
	}
	type entry struct {
		path           string
		mode           fs.FileMode
		size           int64
		target, digest string
	}
	var entries []entry
	err = filepath.WalkDir(root, func(path string, de fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if ignored(rel, de.IsDir()) {
			if de.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if de.IsDir() {
			return nil
		}
		info, err := de.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode().IsRegular():
			digest, err := fileSHA(path)
			if err != nil {
				return err
			}
			entries = append(entries, entry{path: rel, mode: info.Mode(), size: info.Size(), digest: digest})
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := validateSymlink(resolvedRoot, path, target); err != nil {
				return fmt.Errorf("unsafe source symlink %s: %w", rel, err)
			}
			entries = append(entries, entry{path: rel, mode: info.Mode(), target: filepath.ToSlash(target)})
		default:
			return fmt.Errorf("unsupported source entry %s with mode %s", rel, info.Mode())
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", errors.New("source tree contains no relevant files")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	h := sha256.New()
	for _, e := range entries {
		if e.mode&fs.ModeSymlink != 0 {
			field(h, "symlink")
			field(h, e.path)
			field(h, e.target)
			continue
		}
		field(h, "file")
		field(h, e.path)
		field(h, fmt.Sprintf("%04o", e.mode.Perm()))
		field(h, strconv.FormatInt(e.size, 10))
		field(h, e.digest)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ignored(rel string, isDir bool) bool {
	base := filepath.Base(filepath.FromSlash(rel))
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		if p == ".git" {
			return true
		}
	}
	if isDir && (base == ".idea" || base == ".vscode") {
		return true
	}
	if base == ".DS_Store" || base == "Thumbs.db" || strings.HasSuffix(base, "~") || strings.HasSuffix(base, ".swp") || strings.HasSuffix(base, ".swo") || strings.HasPrefix(base, ".#") {
		return true
	}
	return false
}

func validateSymlink(root, path, target string) error {
	if filepath.IsAbs(target) {
		return errors.New("target must be relative")
	}
	candidate := filepath.Clean(filepath.Join(filepath.Dir(path), target))
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("target escapes source tree")
	}
	return nil
}

func fileSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func field(w io.Writer, v string) {
	_, _ = io.WriteString(w, v)
	_, _ = w.Write([]byte{0})
}
