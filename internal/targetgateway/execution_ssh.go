package targetgateway

import (
	"context"
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/executionbundle"
)

func (t *sshTransport) UploadExecution(ctx context.Context, sess session, bundle executionbundle.Bundle) error {
	if !safeExecutionID(bundle.ID) || !validSHA256(bundle.SHA256) {
		return errors.New("invalid execution bundle identity")
	}
	script := `set -eu
umask 077
root=/var/tmp/vpsmith-execution
if [ -f /var/lib/vpsmith/execution/.active ]; then root=/var/lib/vpsmith/execution; fi
install -d -m 0700 "$root" "$root/bundles" "$root/proofs" "$root/locks" "$root/claims"
dest="$root/bundles/` + bundle.ID + `.tar"
tmp="$dest.upload.$$"
cleanup() { if [ -n "${tmp:-}" ]; then rm -f -- "$tmp"; fi; }
trap cleanup EXIT HUP INT TERM
cat > "$tmp"
got=$(sha256sum "$tmp"); got=${got%% *}
[ "$got" = "` + bundle.SHA256 + `" ] || { echo 'bundle sha256 mismatch' >&2; exit 41; }
if [ -e "$dest" ]; then
  old=$(sha256sum "$dest"); old=${old%% *}
  [ "$old" = "$got" ] || { echo 'historical bundle collision' >&2; exit 42; }
else
  chmod 0400 "$tmp"
  mv "$tmp" "$dest"
  tmp=''
  sync -f "$dest"
fi`
	_, stderr, err := t.runRemoteInput(ctx, sess, "sudo -n sh -eu -c "+shellQuote(script), bundle.Bytes)
	if err != nil {
		return fmt.Errorf("upload immutable execution bundle: %w%s", err, boundedRemoteError(stderr))
	}
	return nil
}

func (t *sshTransport) StartExecution(ctx context.Context, sess session, request execution.StartRequest) error {
	if !safeExecutionID(request.RunID) || !safeExecutionID(request.BundleID) || !validSHA256(request.BundleSHA256) || !validSHA256(request.Runner.SHA256) {
		return errors.New("invalid execution start request")
	}
	if !safeBundlePath(request.Runner.Path) {
		return errors.New("invalid target runner path")
	}
	unit := "vpsmith-exec-" + request.RunID
	runtime := "/run/vpsmith-execution/" + request.RunID
	workRoot := "/var/tmp/vpsmith-execution-work"
	work := workRoot + "/" + request.RunID
	fifo := runtime + "/secrets.pipe"
	script := `set -eu
umask 077
root=/var/tmp/vpsmith-execution
if [ -f /var/lib/vpsmith/execution/.active ]; then root=/var/lib/vpsmith/execution; fi
bundle="$root/bundles/` + request.BundleID + `.tar"
[ -r "$bundle" ] || { echo 'execution bundle missing' >&2; exit 43; }
got=$(sha256sum "$bundle"); got=${got%% *}
[ "$got" = "` + request.BundleSHA256 + `" ] || { echo 'execution bundle sha256 mismatch' >&2; exit 44; }
python=$(command -v python3) || { echo 'python3 missing' >&2; exit 45; }
"$python" -c 'import json,sys,tarfile; tf=tarfile.open(sys.argv[1], "r:"); m=json.load(tf.extractfile("manifest.json")); r=m.get("runner") or {}; ok=(r.get("path")==sys.argv[2] and r.get("sha256")==sys.argv[3] and r.get("version")==sys.argv[4]); sys.exit(0 if ok else 1)' "$bundle" ` + shellQuote(request.Runner.Path) + ` ` + shellQuote(request.Runner.SHA256) + ` ` + shellQuote(request.Runner.Version) + ` || { echo 'target runner identity does not match manifest' >&2; exit 48; }
command -v systemd-run >/dev/null 2>&1 || { echo 'systemd-run missing' >&2; exit 46; }
command -v tar >/dev/null 2>&1 || { echo 'tar missing' >&2; exit 47; }
command -v flock >/dev/null 2>&1 || { echo 'flock missing' >&2; exit 48; }
install -d -m 0700 ` + shellQuote(runtime) + `
install -d -m 0711 ` + shellQuote(workRoot) + ` ` + shellQuote(work) + `
runner=` + shellQuote(runtime+"/runner.py") + `
tar -xOf "$bundle" ` + shellQuote(request.Runner.Path) + ` > "$runner"
rgot=$(sha256sum "$runner"); rgot=${rgot%% *}
[ "$rgot" = "` + request.Runner.SHA256 + `" ] || { echo 'target runner sha256 mismatch' >&2; exit 48; }
chmod 0500 "$runner"
systemd-run --quiet --collect --unit=` + shellQuote(unit) + ` --property=Type=exec --property=UMask=0077 --property=StandardOutput=null --property=StandardError=null "$python" "$runner" --bundle "$bundle" --bundle-id ` + shellQuote(request.BundleID) + ` --bundle-sha256 ` + shellQuote(request.BundleSHA256) + ` --target-id ` + shellQuote(request.TargetID) + ` --run-id ` + shellQuote(request.RunID) + ` --admin-user ` + shellQuote(sess.SSHUser) + ` --secret-fifo ` + shellQuote(fifo) + ` --work-dir ` + shellQuote(work)
	_, stderr, err := t.runRemoteInput(ctx, sess, "sudo -n sh -eu -c "+shellQuote(script), nil)
	if err != nil {
		return fmt.Errorf("start detached execution runner: %w%s", err, boundedRemoteError(stderr))
	}
	return nil
}

func (t *sshTransport) ObserveExecution(ctx context.Context, sess session, runID string) (execution.Observation, error) {
	if !safeExecutionID(runID) {
		return execution.Observation{}, errors.New("invalid execution run id")
	}
	unit := "vpsmith-exec-" + runID + ".service"
	script := `set -eu
root=/var/tmp/vpsmith-execution
if [ -f /var/lib/vpsmith/execution/.active ]; then root=/var/lib/vpsmith/execution; fi
proof="$root/proofs/` + runID + `.json"
if [ -r "$proof" ]; then printf 'PROOF\t'; cat "$proof"; else printf 'PROOF\t\n'; fi
lock=0
if [ -e "$root/locks/structural.lock" ]; then
  if flock -n "$root/locks/structural.lock" -c true >/dev/null 2>&1; then lock=0; else lock=1; fi
fi
printf 'LOCK\t%s\n' "$lock"
if systemctl is-active --quiet ` + shellQuote(unit) + `; then printf 'UNIT\t1\n'; else printf 'UNIT\t0\n'; fi`
	stdout, stderr, err := t.runRemoteInput(ctx, sess, "sudo -n sh -eu -c "+shellQuote(script), nil)
	if err != nil {
		return execution.Observation{}, fmt.Errorf("observe execution runner: %w%s", err, boundedRemoteError(stderr))
	}
	return parseExecutionObservation(stdout)
}

func (t *sshTransport) SendExecutionSecrets(ctx context.Context, sess session, runID string, values []execution.SecretValue) error {
	if !safeExecutionID(runID) {
		return errors.New("invalid execution run id")
	}
	payload, err := encodeSecretStream(values)
	if err != nil {
		return err
	}
	defer zero(payload)
	fifo := "/run/vpsmith-execution/" + runID + "/secrets.pipe"
	script := `set -eu
fifo=` + shellQuote(fifo) + `
[ -p "$fifo" ] || { echo 'secret fifo missing' >&2; exit 49; }
cat > "$fifo"`
	_, stderr, err := t.runRemoteInput(ctx, sess, "sudo -n sh -eu -c "+shellQuote(script), payload)
	if err != nil {
		return fmt.Errorf("deliver execution secret stream: %w%s", err, boundedRemoteError(stderr))
	}
	return nil
}

type inputProcessRunner interface {
	RunInput(context.Context, []byte, string, ...string) ([]byte, []byte, error)
}
