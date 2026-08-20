package targetgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const coreRestoreRoot = "/var/lib/vpsmith/tmp/core-restore"

type coreRestorePayloadTransport interface {
	StageCoreRestorePayload(context.Context, session, string, io.Reader, string, int64) error
	CleanupCoreRestorePayload(context.Context, session, string) error
}

func (a *StorageBackupTarget) StageCoreRestorePayload(ctx context.Context, targetID, bundleID string, input io.Reader, sha256 string, size int64) error {
	if targetID == "" {
		return errors.New("target id is required")
	}
	sess, err := a.gateway.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := a.gateway.transport.(coreRestorePayloadTransport)
	if !ok {
		return errors.New("target transport does not support Core restore payload staging")
	}
	return transport.StageCoreRestorePayload(ctx, sess, bundleID, input, sha256, size)
}

func (a *StorageBackupTarget) CleanupCoreRestorePayload(ctx context.Context, targetID, bundleID string) error {
	if targetID == "" {
		return errors.New("target id is required")
	}
	sess, err := a.gateway.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := a.gateway.transport.(coreRestorePayloadTransport)
	if !ok {
		return errors.New("target transport does not support Core restore payload cleanup")
	}
	return transport.CleanupCoreRestorePayload(ctx, sess, bundleID)
}

func (t *sshTransport) StageCoreRestorePayload(ctx context.Context, sess session, bundleID string, input io.Reader, sha256 string, size int64) error {
	if !safeExecutionID(bundleID) || !validSHA256(sha256) || size <= 0 || input == nil {
		return errors.New("invalid Core restore payload identity")
	}
	root := coreRestoreRoot + "/" + bundleID
	script := `set -eu
umask 077
root=` + shellQuote(root) + `
dest="$root/payload.tar.zst"
tmp="$dest.upload.$$"
cleanup() { sudo -n rm -f -- "$tmp"; }
trap cleanup EXIT HUP INT TERM
sudo -n install -d -o root -g root -m 0700 ` + shellQuote(coreRestoreRoot) + ` "$root"
sudo -n sh -eu -c 'cat > "$1"' sh "$tmp"
got=$(sudo -n sha256sum -- "$tmp"); got=${got%% *}
size=$(sudo -n stat -c %s -- "$tmp")
[ "$got" = ` + shellQuote(sha256) + ` ] || { echo 'Core restore payload sha256 mismatch' >&2; exit 61; }
[ "$size" = ` + shellQuote(strconv.FormatInt(size, 10)) + ` ] || { echo 'Core restore payload size mismatch' >&2; exit 62; }
sudo -n chmod 0400 "$tmp"
if sudo -n test -e "$dest"; then
  old=$(sudo -n sha256sum -- "$dest"); old=${old%% *}
  old_size=$(sudo -n stat -c %s -- "$dest")
  [ "$old" = "$got" ] && [ "$old_size" = "$size" ] || { echo 'Core restore staging collision' >&2; exit 63; }
  sudo -n rm -f -- "$tmp"
else
  sudo -n mv -- "$tmp" "$dest"
fi
sudo -n test -f "$dest"
sudo -n test "$(sudo -n stat -c %a -- "$dest")" = 400
`
	_, stderr, err := t.runRemoteInputStream(ctx, sess, script, input)
	if err != nil {
		return fmt.Errorf("stage Core restore payload: %w%s", err, boundedRemoteError(stderr))
	}
	return nil
}

func (t *sshTransport) CleanupCoreRestorePayload(ctx context.Context, sess session, bundleID string) error {
	if !safeExecutionID(bundleID) {
		return errors.New("invalid Core restore bundle identity")
	}
	root := coreRestoreRoot + "/" + bundleID
	if _, err := t.runRemote(ctx, sess, "sudo -n rm -rf -- "+shellQuote(root)); err != nil {
		return fmt.Errorf("cleanup Core restore payload: %w", err)
	}
	return nil
}
