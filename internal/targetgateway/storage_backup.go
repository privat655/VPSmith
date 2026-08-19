package targetgateway

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const storageCopyRoot = "/var/lib/vpsmith/tmp/storage-copy"

type StorageCopyProcessError struct {
	Operation string
	ExitCode  int
}

func (e *StorageCopyProcessError) Error() string {
	return fmt.Sprintf("target storage-copy %s failed with exit code %d", e.Operation, e.ExitCode)
}

func (g *Gateway) PrepareStorageCopy(ctx context.Context, targetID string, declaredPaths []string) (token, sha256 string, size int64, err error) {
	if targetID == "" {
		return "", "", 0, errors.New("target id is required")
	}
	paths, err := validateStoragePaths(declaredPaths)
	if err != nil {
		return "", "", 0, err
	}
	sess, err := g.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return "", "", 0, err
	}
	defer zero(sess.IdentitySeed)
	if adapter, ok := g.transport.(interface {
		PrepareStorageCopy(context.Context, session, []string) (string, string, int64, error)
	}); ok {
		return adapter.PrepareStorageCopy(ctx, sess, paths)
	}
	return "", "", 0, errors.New("target transport does not support storage copy")
}

func (g *Gateway) TransferStorageCopy(ctx context.Context, targetID, token string) ([]byte, error) {
	if targetID == "" || !safeStorageToken(token) {
		return nil, errors.New("invalid target storage-copy identity")
	}
	sess, err := g.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return nil, err
	}
	defer zero(sess.IdentitySeed)
	if adapter, ok := g.transport.(interface {
		TransferStorageCopy(context.Context, session, string) ([]byte, error)
	}); ok {
		return adapter.TransferStorageCopy(ctx, sess, token)
	}
	return nil, errors.New("target transport does not support storage-copy transfer")
}

func (g *Gateway) CleanupStorageCopy(ctx context.Context, targetID, token string) error {
	if targetID == "" || !safeStorageToken(token) {
		return errors.New("invalid target storage-copy identity")
	}
	sess, err := g.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return err
	}
	defer zero(sess.IdentitySeed)
	if adapter, ok := g.transport.(interface {
		CleanupStorageCopy(context.Context, session, string) error
	}); ok {
		return adapter.CleanupStorageCopy(ctx, sess, token)
	}
	return errors.New("target transport does not support storage-copy cleanup")
}

func (t *sshTransport) PrepareStorageCopy(ctx context.Context, sess session, declaredPaths []string) (string, string, int64, error) {
	var args strings.Builder
	for _, item := range declaredPaths {
		args.WriteByte(' ')
		args.WriteString(shellQuote(strings.TrimPrefix(item, "/")))
	}
	command := "set -eu; " +
		"root=" + shellQuote(storageCopyRoot) + "; " +
		"sudo -n install -d -m 0700 -o root -g root \"$root\"; " +
		"token=copy-$(date +%s)-$$; file=\"$root/$token.tar.zst\"; " +
		"set +e; sudo -n tar --format=pax --numeric-owner --acls --xattrs --xattrs-include='*' --zstd -C / -cf \"$file\" --" + args.String() + "; rc=$?; set -e; " +
		"if [ \"$rc\" -ne 0 ]; then sudo -n rm -f -- \"$file\"; printf 'error\\t%s\\n' \"$rc\"; exit 0; fi; " +
		"sha=$(sudo -n sha256sum -- \"$file\" | awk '{print $1}'); size=$(sudo -n stat -c %s -- \"$file\"); " +
		"printf 'ok\\t%s\\t%s\\t%s\\n' \"$token\" \"$sha\" \"$size\""
	stdout, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return "", "", 0, err
	}
	fields := strings.Fields(strings.TrimSpace(string(stdout)))
	if len(fields) == 2 && fields[0] == "error" {
		code, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil || code <= 0 {
			return "", "", 0, errors.New("invalid target storage-copy failure response")
		}
		return "", "", 0, &StorageCopyProcessError{Operation: "archive", ExitCode: code}
	}
	if len(fields) != 4 || fields[0] != "ok" || !safeStorageToken(fields[1]) || !validSHA256(fields[2]) {
		return "", "", 0, errors.New("invalid target storage-copy response")
	}
	size, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || size < 0 {
		return "", "", 0, errors.New("invalid target storage-copy size")
	}
	return fields[1], fields[2], size, nil
}

func (t *sshTransport) TransferStorageCopy(ctx context.Context, sess session, token string) ([]byte, error) {
	if !safeStorageToken(token) {
		return nil, errors.New("invalid storage-copy token")
	}
	filename := path.Join(storageCopyRoot, token+".tar.zst")
	command := "sudo -n test -f " + shellQuote(filename) + " && sudo -n cat -- " + shellQuote(filename)
	data, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return nil, fmt.Errorf("transfer target storage-copy: %w", err)
	}
	return data, nil
}

func (t *sshTransport) CleanupStorageCopy(ctx context.Context, sess session, token string) error {
	if !safeStorageToken(token) {
		return errors.New("invalid storage-copy token")
	}
	filename := path.Join(storageCopyRoot, token+".tar.zst")
	if _, err := t.runRemote(ctx, sess, "sudo -n rm -f -- "+shellQuote(filename)); err != nil {
		return fmt.Errorf("cleanup target storage-copy: %w", err)
	}
	return nil
}

func validateStoragePaths(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, errors.New("declared storage list is empty")
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("invalid declared storage path %q", value)
		}
		clean := path.Clean(value)
		if clean != value || clean == "/" {
			return nil, fmt.Errorf("declared storage path %q must be canonical and narrower than root", value)
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("duplicate declared storage path %q", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func safeStorageToken(value string) bool {
	if !strings.HasPrefix(value, "copy-") || len(value) > 96 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}
