package deployment

import (
	"path/filepath"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

func coreTargetDirectories(adminUser string, operation OperationKind) []executionbundle.Directory {
	if operation == Validate {
		return nil
	}
	adminHome := filepath.Join("/home", adminUser)
	return []executionbundle.Directory{
		{Path: "/etc/audit", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o750},
		{Path: "/etc/audit/rules.d", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o750},
		{Path: "/etc/containers", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o755},
		{Path: "/etc/containers/containers.conf.d", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o755},
		{Path: "/etc/systemd/coredump.conf.d", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o755},
		{Path: "/etc/systemd/journald.conf.d", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o755},
		{Path: filepath.Join(adminHome, ".config"), Owner: executionbundle.PrincipalAdmin, Group: executionbundle.PrincipalAdmin, Mode: 0o700},
		{Path: filepath.Join(adminHome, ".config/containers"), Owner: executionbundle.PrincipalAdmin, Group: executionbundle.PrincipalAdmin, Mode: 0o700},
		{Path: filepath.Join(adminHome, ".config/containers/systemd"), Owner: executionbundle.PrincipalAdmin, Group: executionbundle.PrincipalAdmin, Mode: 0o700},
		{Path: "/var/lib/vpsmith/core", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalAdmin, Mode: 0o750},
		{Path: "/var/lib/vpsmith/core/authelia", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalAdmin, Mode: 0o750},
		{Path: "/var/lib/vpsmith/core/caddy", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalAdmin, Mode: 0o750},
		{Path: "/var/lib/vpsmith/core/generated", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalAdmin, Mode: 0o750},
		{Path: "/var/lib/vpsmith/inventory", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalRoot, Mode: 0o750},
		{Path: "/var/lib/vpsmith/secrets", Owner: executionbundle.PrincipalRoot, Group: executionbundle.PrincipalAdmin, Mode: 0o750},
	}
}
