package backuprestore

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

const (
	xattrPAXPrefix         = "VPSMITH.xattr."
	standardXattrPAXPrefix = "SCHILY.xattr."
)

type ArchiveOptions struct {
	PreserveOwnership bool
}

type archiveEntry struct {
	Name     string
	Type     byte
	LinkName string
}

// CreateTarZst creates one tar.zst using numeric uid/gid from lstat. Linux
// xattrs, including POSIX ACL xattrs, are preserved as private PAX records so
// they survive a VPSmith create/extract round trip without user/group lookup.
func CreateTarZst(root, destination string) error {
	if root == "" || destination == "" || !filepath.IsAbs(root) || !filepath.IsAbs(destination) {
		return errors.New("absolute archive root and destination are required")
	}
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create tar.zst: %w", err)
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	encoder, err := zstd.NewWriter(out, zstd.WithEncoderCRC(true))
	if err != nil {
		return fmt.Errorf("create zstd encoder: %w", err)
	}
	tw := tar.NewWriter(encoder)
	inodes := map[[2]uint64]string{}
	var paths []string
	if err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == root {
			return nil
		}
		paths = append(paths, name)
		return nil
	}); err != nil {
		_ = tw.Close()
		_ = encoder.Close()
		return fmt.Errorf("walk archive root: %w", err)
	}
	sort.Slice(paths, func(i, j int) bool {
		a, _ := filepath.Rel(root, paths[i])
		b, _ := filepath.Rel(root, paths[j])
		return filepath.ToSlash(a) < filepath.ToSlash(b)
	})
	for _, name := range paths {
		info, err := os.Lstat(name)
		if err != nil {
			return fmt.Errorf("lstat archive input: %w", err)
		}
		rel, err := filepath.Rel(root, name)
		if err != nil || !filepath.IsLocal(rel) {
			return errors.New("archive input escaped root")
		}
		rel = filepath.ToSlash(rel)
		var link string
		if info.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(name)
			if err != nil {
				return err
			}
		}
		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return fmt.Errorf("create tar header: %w", err)
		}
		header.Name = rel
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			header.Uid = int(stat.Uid)
			header.Gid = int(stat.Gid)
			if info.Mode().IsRegular() && stat.Nlink > 1 {
				key := [2]uint64{uint64(stat.Dev), stat.Ino}
				if first, found := inodes[key]; found {
					header.Typeflag = tar.TypeLink
					header.Linkname = first
					header.Size = 0
				} else {
					inodes[key] = rel
				}
			}
		}
		xattrs, err := readXattrs(name)
		if err != nil {
			return fmt.Errorf("read xattrs for %s: %w", rel, err)
		}
		if len(xattrs) > 0 {
			header.PAXRecords = map[string]string{}
			for key, value := range xattrs {
				encodedName := base64.RawURLEncoding.EncodeToString([]byte(key))
				header.PAXRecords[xattrPAXPrefix+encodedName] = base64.StdEncoding.EncodeToString(value)
			}
		}
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header: %w", err)
		}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			file, err := os.Open(name)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, file)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar stream: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("close zstd stream: %w", err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync tar.zst: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close tar.zst: %w", err)
	}
	ok = true
	return nil
}

func InspectTarZst(filename string) ([]archiveEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder, err := zstd.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("open zstd payload: %w", err)
	}
	defer decoder.Close()
	tr := tar.NewReader(decoder)
	seen := map[string]struct{}{}
	var entries []archiveEntry
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("inspect tar payload: %w", err)
		}
		if err := validateArchiveHeader(header); err != nil {
			return nil, err
		}
		if _, exists := seen[header.Name]; exists {
			return nil, fmt.Errorf("duplicate archive path %q", header.Name)
		}
		seen[header.Name] = struct{}{}
		entries = append(entries, archiveEntry{Name: header.Name, Type: header.Typeflag, LinkName: header.Linkname})
	}
	return entries, nil
}

func ExtractTarZst(filename, root string, options ArchiveOptions) error {
	if _, err := InspectTarZst(filename); err != nil {
		return err
	}
	if root == "" || !filepath.IsAbs(root) {
		return errors.New("absolute extraction root is required")
	}
	if entries, err := os.ReadDir(root); err == nil && len(entries) != 0 {
		return errors.New("safe extraction requires an empty destination")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder, err := zstd.NewReader(file)
	if err != nil {
		return err
	}
	defer decoder.Close()
	tr := tar.NewReader(decoder)
	var directories []*tar.Header
	var hardlinks []*tar.Header
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if err := validateArchiveHeader(header); err != nil {
			return err
		}
		destination := filepath.Join(root, filepath.FromSlash(header.Name))
		if err := ensureNoSymlinkParent(root, destination); err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
				return err
			}
			if err := os.Mkdir(destination, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			copyHeader := *header
			directories = append(directories, &copyHeader)
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
				return err
			}
			out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(header.Mode)&0o7777)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(out, tr, header.Size)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if err := restoreMetadata(destination, header, options, false); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
				return err
			}
			if err := os.Symlink(header.Linkname, destination); err != nil {
				return err
			}
			if err := restoreMetadata(destination, header, options, true); err != nil {
				return err
			}
		case tar.TypeLink:
			copyHeader := *header
			hardlinks = append(hardlinks, &copyHeader)
		default:
			return fmt.Errorf("unsupported archive entry type %d", header.Typeflag)
		}
	}
	for _, header := range hardlinks {
		destination := filepath.Join(root, filepath.FromSlash(header.Name))
		target := filepath.Join(root, filepath.FromSlash(header.Linkname))
		if err := ensureNoSymlinkParent(root, destination); err != nil {
			return err
		}
		if err := ensureNoSymlinkParent(root, target); err != nil {
			return err
		}
		info, err := os.Lstat(target)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("hardlink target %q is not an extracted regular file", header.Linkname)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return err
		}
		if err := os.Link(target, destination); err != nil {
			return err
		}
	}
	for i := len(directories) - 1; i >= 0; i-- {
		header := directories[i]
		destination := filepath.Join(root, filepath.FromSlash(header.Name))
		if err := restoreMetadata(destination, header, options, false); err != nil {
			return err
		}
	}
	return nil
}

func validateArchiveHeader(header *tar.Header) error {
	if header == nil || header.Name == "" || strings.ContainsRune(header.Name, '\x00') || strings.Contains(header.Name, "\\") {
		return errors.New("archive contains invalid path")
	}
	if header.Typeflag == tar.TypeDir {
		header.Name = strings.TrimRight(header.Name, "/")
		if header.Name == "" {
			return errors.New("archive contains invalid directory path")
		}
	}
	clean := path.Clean(header.Name)
	if clean != header.Name || clean == "." || !filepath.IsLocal(filepath.FromSlash(clean)) || path.IsAbs(clean) {
		return fmt.Errorf("archive path %q is not local", header.Name)
	}
	switch header.Typeflag {
	case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
		return nil
	case tar.TypeSymlink:
		if header.Linkname == "" || path.IsAbs(header.Linkname) || strings.ContainsRune(header.Linkname, '\x00') || strings.Contains(header.Linkname, "\\") {
			return fmt.Errorf("unsafe symlink %q", header.Name)
		}
		resolved := path.Clean(path.Join(path.Dir(header.Name), header.Linkname))
		if !filepath.IsLocal(filepath.FromSlash(resolved)) || resolved == "." {
			return fmt.Errorf("symlink %q escapes archive root", header.Name)
		}
		return nil
	case tar.TypeLink:
		if header.Linkname == "" || path.IsAbs(header.Linkname) || path.Clean(header.Linkname) != header.Linkname || !filepath.IsLocal(filepath.FromSlash(header.Linkname)) {
			return fmt.Errorf("hardlink %q escapes archive root", header.Name)
		}
		return nil
	default:
		return fmt.Errorf("special archive entry %q is forbidden", header.Name)
	}
}

func ensureNoSymlinkParent(root, destination string) error {
	rel, err := filepath.Rel(root, destination)
	if err != nil || !filepath.IsLocal(rel) {
		return errors.New("extraction destination escapes root")
	}
	current := root
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("archive path traverses non-directory %q", current)
		}
	}
	return nil
}

func restoreMetadata(name string, header *tar.Header, options ArchiveOptions, symlink bool) error {
	if options.PreserveOwnership {
		var err error
		if symlink {
			err = os.Lchown(name, header.Uid, header.Gid)
		} else {
			err = os.Chown(name, header.Uid, header.Gid)
		}
		if err != nil {
			return fmt.Errorf("restore numeric ownership: %w", err)
		}
	}
	if !symlink {
		if err := os.Chmod(name, fs.FileMode(header.Mode)&0o7777); err != nil {
			return fmt.Errorf("restore mode: %w", err)
		}
		if !header.ModTime.IsZero() {
			if err := os.Chtimes(name, time.Now(), header.ModTime); err != nil {
				return fmt.Errorf("restore modification time: %w", err)
			}
		}
	}
	xattrs, err := archivedXattrs(header)
	if err != nil {
		return err
	}
	for attrName, value := range xattrs {
		if err := unix.Lsetxattr(name, attrName, value, 0); err != nil {
			return fmt.Errorf("restore xattr %s: %w", attrName, err)
		}
	}
	return nil
}

func archivedXattrs(header *tar.Header) (map[string][]byte, error) {
	result := map[string][]byte{}
	add := func(name string, value []byte) error {
		if name == "" || strings.ContainsRune(name, '\x00') {
			return errors.New("invalid archived xattr name")
		}
		if existing, ok := result[name]; ok && !bytes.Equal(existing, value) {
			return fmt.Errorf("conflicting archived xattr %s", name)
		}
		result[name] = append([]byte(nil), value...)
		return nil
	}
	for key, value := range header.PAXRecords {
		switch {
		case strings.HasPrefix(key, xattrPAXPrefix):
			rawName, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, xattrPAXPrefix))
			if err != nil || len(rawName) == 0 {
				return nil, errors.New("invalid archived xattr name")
			}
			rawValue, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return nil, errors.New("invalid archived xattr value")
			}
			if err := add(string(rawName), rawValue); err != nil {
				return nil, err
			}
		case strings.HasPrefix(key, standardXattrPAXPrefix):
			if err := add(strings.TrimPrefix(key, standardXattrPAXPrefix), []byte(value)); err != nil {
				return nil, err
			}
		}
	}
	for key, value := range header.Xattrs {
		if err := add(key, []byte(value)); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func readXattrs(name string) (map[string][]byte, error) {
	size, err := unix.Llistxattr(name, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			return nil, nil
		}
		return nil, err
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	size, err = unix.Llistxattr(name, buf)
	if err != nil {
		return nil, err
	}
	result := map[string][]byte{}
	for _, raw := range strings.Split(string(buf[:size]), "\x00") {
		if raw == "" {
			continue
		}
		valueSize, err := unix.Lgetxattr(name, raw, nil)
		if err != nil {
			return nil, err
		}
		value := make([]byte, valueSize)
		if valueSize > 0 {
			if _, err := unix.Lgetxattr(name, raw, value); err != nil {
				return nil, err
			}
		}
		result[raw] = value
	}
	return result, nil
}
