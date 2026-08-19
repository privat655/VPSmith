//go:build execution_sandbox

package execution_sandbox

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

func TestRealSSHStorageCopyPreservesOfflineFilesystemContract(t *testing.T) {
	if os.Getenv("VPSMITH_EXECUTION_SANDBOX") != "1" {
		t.Skip("execution sandbox is opt-in")
	}
	ctx := context.Background()
	image := "vpsmith-storage-copy-sandbox:" + time.Now().UTC().Format("150405.000000000")
	run(t, "docker", "build", "-f", "tests/execution_sandbox/Containerfile", "-t", image, ".")
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", image).Run() })
	cid := strings.TrimSpace(run(t, "docker", "run", "-d", "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-p", "127.0.0.1::22", image))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", cid).Run() })
	portLine := strings.TrimSpace(run(t, "docker", "port", cid, "22/tcp"))
	address := portLine
	if i := strings.LastIndex(portLine, ":"); i >= 0 {
		address = "127.0.0.1:" + portLine[i+1:]
	}
	waitTCP(t, address)
	waitCommand(t, 20*time.Second, func() bool {
		return exec.Command("docker", "exec", cid, "systemctl", "is-active", "--quiet", "ssh.service").Run() == nil
	}, "sshd did not become active")

	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	targetID := managementstate.TargetID("target-storage-sandbox")
	if err := store.Change(ctx, func(change *managementstate.Change) error {
		return change.CreateTarget(managementstate.TargetRegistration{ID: targetID, Address: address, SSHUser: "dev", SSHTrust: managementstate.TrustUnknown})
	}); err != nil {
		t.Fatal(err)
	}
	gateway, err := targetgateway.New(store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := gateway.EnsureIdentity(ctx, targetID)
	if err != nil {
		t.Fatal(err)
	}
	dockerInput(t, cid, []byte(identity.PublicKey+"\n"), "sh", "-c", "cat >/home/dev/.ssh/authorized_keys && chown dev:dev /home/dev/.ssh/authorized_keys && chmod 0600 /home/dev/.ssh/authorized_keys")
	observedKey, err := gateway.ObserveHostKey(ctx, targetID)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, targetID, observedKey); err != nil {
		t.Fatal(err)
	}

	run(t, "docker", "exec", cid, "sh", "-eu", "-c", `
install -d -m 0751 /srv/vpsmith-storage-fixture/empty
printf 'payload\n' >/srv/vpsmith-storage-fixture/data
chmod 0640 /srv/vpsmith-storage-fixture/data
chown 12345:12346 /srv/vpsmith-storage-fixture/data
ln /srv/vpsmith-storage-fixture/data /srv/vpsmith-storage-fixture/hard
ln -s data /srv/vpsmith-storage-fixture/sym
setfattr -n user.vpsmith -v storage-xattr /srv/vpsmith-storage-fixture/data
setfacl -m u:12347:r-- /srv/vpsmith-storage-fixture/data
`)

	storageTarget, err := targetgateway.NewStorageBackupTarget(gateway)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := backuprestore.New(t.TempDir(), t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	copyResult, err := manager.CopyOfflineStorage(ctx, storageTarget, string(targetID), []string{"/srv/vpsmith-storage-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	defer copyResult.Close()
	if copyResult.Token != "" {
		t.Fatalf("successful copy retained cleanup token %q", copyResult.Token)
	}
	if got := strings.TrimSpace(run(t, "docker", "exec", cid, "sh", "-c", "find /var/lib/vpsmith/tmp/storage-copy -type f -print 2>/dev/null || true")); got != "" {
		t.Fatalf("verified target plaintext was not cleaned up: %q", got)
	}

	assertNumericArchiveOwner(t, copyResult.ArchivePath, "srv/vpsmith-storage-fixture/data", 12345, 12346)
	restored := filepath.Join(t.TempDir(), "restored")
	if err := backuprestore.ExtractTarZst(copyResult.ArchivePath, restored, backuprestore.ArchiveOptions{}); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(restored, "srv", "vpsmith-storage-fixture")
	dataInfo, err := os.Lstat(filepath.Join(base, "data"))
	if err != nil {
		t.Fatal(err)
	}
	hardInfo, err := os.Lstat(filepath.Join(base, "hard"))
	if err != nil {
		t.Fatal(err)
	}
	if dataInfo.Sys().(*syscall.Stat_t).Ino != hardInfo.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("hardlink relationship was not preserved through real SSH storage copy")
	}
	if link, err := os.Readlink(filepath.Join(base, "sym")); err != nil || link != "data" {
		t.Fatalf("symlink=%q err=%v", link, err)
	}
	if info, err := os.Stat(filepath.Join(base, "empty")); err != nil || !info.IsDir() || info.Mode().Perm() != 0o751 {
		t.Fatalf("empty directory contract not preserved: info=%v err=%v", info, err)
	}
	value := make([]byte, 128)
	n, err := unix.Getxattr(filepath.Join(base, "data"), "user.vpsmith", value)
	if err != nil {
		t.Fatalf("xattr missing after real storage copy: %v", err)
	}
	if string(value[:n]) != "storage-xattr" {
		t.Fatalf("xattr=%q", value[:n])
	}
	if _, err := unix.Getxattr(filepath.Join(base, "data"), "system.posix_acl_access", value); err != nil {
		t.Fatalf("ACL xattr missing after real storage copy: %v", err)
	}
}

func assertNumericArchiveOwner(t *testing.T, filename, wanted string, uid, gid int) {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zr, err := zstd.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == wanted {
			if header.Uid != uid || header.Gid != gid || header.Mode&0o7777 != 0o640 {
				t.Fatalf("archive metadata uid=%d gid=%d mode=%o", header.Uid, header.Gid, header.Mode&0o7777)
			}
			return
		}
	}
	t.Fatalf("archive entry %q not found", wanted)
}