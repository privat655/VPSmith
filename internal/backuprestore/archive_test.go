package backuprestore

import (
	"archive/tar"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

func TestTarZstRoundTripPreservesFilesystemContract(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("numeric ownership verification requires root")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "empty"), 0o751); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "data")
	if err := os.WriteFile(file, []byte("bytes\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(file, 12345, 12346); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, filepath.Join(root, "hard")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("data", filepath.Join(root, "sym")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(file, "user.vpsmith", []byte("xattr-value"), 0); err != nil && err != unix.ENOTSUP {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "payload.tar.zst")
	if err := CreateTarZst(root, archive); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "restore")
	if err := ExtractTarZst(archive, out, ArchiveOptions{PreserveOwnership: true}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(out, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "bytes\n" {
		t.Fatalf("content=%q", got)
	}
	info, err := os.Lstat(filepath.Join(out, "data"))
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != 12345 || stat.Gid != 12346 || info.Mode().Perm() != 0o640 {
		t.Fatalf("metadata uid=%d gid=%d mode=%o", stat.Uid, stat.Gid, info.Mode().Perm())
	}
	hard, err := os.Lstat(filepath.Join(out, "hard"))
	if err != nil {
		t.Fatal(err)
	}
	if hard.Sys().(*syscall.Stat_t).Ino != stat.Ino {
		t.Fatal("hardlink relationship was not preserved")
	}
	link, err := os.Readlink(filepath.Join(out, "sym"))
	if err != nil || link != "data" {
		t.Fatalf("symlink=%q err=%v", link, err)
	}
	if empty, err := os.Stat(filepath.Join(out, "empty")); err != nil || !empty.IsDir() {
		t.Fatalf("empty directory missing: %v", err)
	}
	value := make([]byte, 64)
	if n, err := unix.Getxattr(filepath.Join(out, "data"), "user.vpsmith", value); err == nil && string(value[:n]) != "xattr-value" {
		t.Fatalf("xattr=%q", value[:n])
	}
}

func TestSafeExtractionRejectsTraversalLinksAndSpecialFiles(t *testing.T) {
	cases := []struct {
		name   string
		header tar.Header
	}{
		{"dotdot", tar.Header{Name: "../escape", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}},
		{"absolute", tar.Header{Name: "/escape", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg}},
		{"symlink-escape", tar.Header{Name: "safe/link", Linkname: "../../escape", Typeflag: tar.TypeSymlink}},
		{"hardlink-escape", tar.Header{Name: "safe/hard", Linkname: "../escape", Typeflag: tar.TypeLink}},
		{"device", tar.Header{Name: "dev", Typeflag: tar.TypeChar}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "bad.tar.zst")
			writeRawTarZst(t, archive, tc.header)
			if _, err := InspectTarZst(archive); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func writeRawTarZst(t *testing.T, filename string, header tar.Header) {
	t.Helper()
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	zw, err := zstd.NewWriter(file)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&header); err != nil {
		t.Fatal(err)
	}
	if header.Size > 0 {
		if _, err := tw.Write(make([]byte, header.Size)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSafeExtractionAcceptsForwardHardlinkWithinArchiveRoot(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "forward-hardlink.tar.zst")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw, err := zstd.NewWriter(file)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	if err := tw.WriteHeader(&tar.Header{Name: "hard", Linkname: "data", Typeflag: tar.TypeLink}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "data", Mode: 0o600, Size: 4, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "restore")
	if err := ExtractTarZst(archive, root, ArchiveOptions{}); err != nil {
		t.Fatal(err)
	}
	first, err := os.Lstat(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.Lstat(filepath.Join(root, "hard"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Sys().(*syscall.Stat_t).Ino != second.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("forward hardlink relationship was not preserved")
	}
}
