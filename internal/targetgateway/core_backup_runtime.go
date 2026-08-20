package targetgateway

import (
	"context"
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type coreBackupRuntimeTransport interface {
	QuiesceCoreRuntime(context.Context, session) error
	ResumeAndValidateCoreRuntime(context.Context, session) error
}

// QuiesceCoreRuntime stops only the fixed Core user services needed for a
// consistent long-term Core backup. Callers cannot inject unit names or shell
// commands through this interface.
func (a *StorageBackupTarget) QuiesceCoreRuntime(ctx context.Context, targetID string) error {
	if targetID == "" {
		return errors.New("target id is required")
	}
	sess, err := a.gateway.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := a.gateway.transport.(coreBackupRuntimeTransport)
	if !ok {
		return errors.New("target transport does not support Core backup runtime control")
	}
	return transport.QuiesceCoreRuntime(ctx, sess)
}

// ResumeAndValidateCoreRuntime restarts the same fixed Core services and
// verifies Caddy configuration, Authelia configuration, and the public HTTPS
// auth endpoint before a Core backup may be persisted.
func (a *StorageBackupTarget) ResumeAndValidateCoreRuntime(ctx context.Context, targetID string) error {
	if targetID == "" {
		return errors.New("target id is required")
	}
	sess, err := a.gateway.strictSession(ctx, managementstate.TargetID(targetID))
	if err != nil {
		return err
	}
	defer zero(sess.IdentitySeed)
	transport, ok := a.gateway.transport.(coreBackupRuntimeTransport)
	if !ok {
		return errors.New("target transport does not support Core backup runtime control")
	}
	return transport.ResumeAndValidateCoreRuntime(ctx, sess)
}

func (t *sshTransport) QuiesceCoreRuntime(ctx context.Context, sess session) error {
	command := "set -eu; " +
		"systemctl --user is-active --quiet caddy.service; " +
		"systemctl --user is-active --quiet authelia.service; " +
		"systemctl --user stop caddy.service authelia.service; " +
		"! systemctl --user is-active --quiet caddy.service; " +
		"! systemctl --user is-active --quiet authelia.service"
	if _, err := t.runRemote(ctx, sess, command); err != nil {
		return fmt.Errorf("quiesce Core runtime for backup: %w", err)
	}
	return nil
}

func (t *sshTransport) ResumeAndValidateCoreRuntime(ctx context.Context, sess session) error {
	command := "set -eu; " +
		"systemctl --user start authelia.service caddy.service; " +
		"systemctl --user is-active --quiet authelia.service caddy.service; " +
		"podman exec caddy caddy validate --config /etc/caddy/Caddyfile >/dev/null; " +
		"podman exec authelia /bin/sh -c 'bin=$(command -v authelia 2>/dev/null || find / -xdev -type f -name authelia -perm -111 2>/dev/null | head -n 1); [ -n \"$bin\" ]; \"$bin\" config validate --config /config/configuration.yml' >/dev/null; " +
		"domain=$(sudo -n jq -er '.domain | select(type == \"string\" and length > 0)' /var/lib/vpsmith/core/desired.json); " +
		"curl -fsSI --max-time 10 \"https://auth.${domain}\" >/dev/null"
	if _, err := t.runRemote(ctx, sess, command); err != nil {
		return fmt.Errorf("resume and validate Core runtime after backup: %w", err)
	}
	return nil
}
