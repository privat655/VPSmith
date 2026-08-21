package targetgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type step9RuntimeInventory struct {
	AuthDomain   string `json:"auth_domain"`
	PublicRoutes []struct {
		Hostname   string `json:"hostname"`
		PathPrefix string `json:"path_prefix"`
		AuthMode   string `json:"auth_mode"`
	} `json:"public_routes"`
}

func (t *sshTransport) enrichStep9Runtime(ctx context.Context, sess session, observed *managementstate.ObservedState) error {
	if observed == nil || !observed.Core.Present {
		return nil
	}

	backupBytes, err := t.coreBackupSourceBytes(ctx, sess)
	if err != nil {
		return fmt.Errorf("measure Core backup source: %w", err)
	}
	observed.Host.CoreBackupSourceBytes = backupBytes

	raw, err := t.readOptional(ctx, sess, coreInventoryPath)
	if err != nil {
		return fmt.Errorf("read Core runtime inventory: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return errors.New("installed Core has no runtime inventory")
	}
	var inventory step9RuntimeInventory
	if err := json.Unmarshal(raw, &inventory); err != nil {
		return fmt.Errorf("decode Core runtime inventory: %w", err)
	}
	if !safeRuntimeHostname(inventory.AuthDomain) {
		return errors.New("Core runtime inventory has invalid auth domain")
	}

	for i := range observed.Core.Containers {
		container := &observed.Core.Containers[i]
		if container.Name != "caddy" && container.Name != "authelia" {
			continue
		}
		ref, digest, err := t.containerImageIdentity(ctx, sess, container.Name)
		if err != nil {
			return err
		}
		container.ImageRef = ref
		container.ImageDigest = digest
	}

	authStatus, authTLS, err := t.httpsStatus(ctx, sess, inventory.AuthDomain, "/")
	if err != nil {
		return fmt.Errorf("probe Core HTTPS endpoint: %w", err)
	}
	observed.Core.HTTPS = authTLS && healthyHTTPSStatus(authStatus)

	routes := make([]managementstate.PublicRouteObservedState, 0, len(inventory.PublicRoutes))
	seen := map[string]struct{}{}
	for _, route := range inventory.PublicRoutes {
		if !safeRuntimeHostname(route.Hostname) || !safeRuntimePath(route.PathPrefix) {
			return errors.New("Core runtime inventory has invalid public route")
		}
		if route.AuthMode != "public" && route.AuthMode != "protected" {
			return errors.New("Core runtime inventory has invalid public route auth mode")
		}
		key := route.Hostname + "\x00" + route.PathPrefix
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("Core runtime inventory contains duplicate public route %s%s", route.Hostname, route.PathPrefix)
		}
		seen[key] = struct{}{}
		status, tlsOK, err := t.httpsStatus(ctx, sess, route.Hostname, route.PathPrefix)
		if err != nil {
			return fmt.Errorf("probe public route %s%s: %w", route.Hostname, route.PathPrefix, err)
		}
		routes = append(routes, managementstate.PublicRouteObservedState{
			Hostname:     route.Hostname,
			PathPrefix:   route.PathPrefix,
			AuthMode:     route.AuthMode,
			StatusCode:   status,
			HTTPS:        tlsOK && healthyHTTPSStatus(status),
			AuthEnforced: route.AuthMode != "protected" || protectedRouteStatus(status),
		})
	}
	observed.Core.PublicRoutes = routes
	return nil
}

func (t *sshTransport) coreBackupSourceBytes(ctx context.Context, sess session) (int64, error) {
	const command = `sudo -n du -s -B1 -- /var/lib/vpsmith/core/desired.json /var/lib/vpsmith/core/authelia/data /var/lib/vpsmith/secrets/core /var/lib/vpsmith/inventory/core.json /var/lib/vpsmith/execution | awk '{sum += $1} END {print sum}'`
	stdout, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(stdout)), 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("invalid Core backup source size")
	}
	return value, nil
}

func (t *sshTransport) containerImageIdentity(ctx context.Context, sess session, name string) (string, string, error) {
	if !safeObjectName(name) {
		return "", "", errors.New("invalid Core container name")
	}
	command := "podman inspect --format '{{.ImageName}}\\t{{.ImageDigest}}' " + shellQuote(name) + " 2>/dev/null || true"
	stdout, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return "", "", err
	}
	fields := strings.Split(strings.TrimSpace(string(stdout)), "\t")
	if len(fields) != 2 || strings.TrimSpace(fields[0]) == "" || !validRuntimeDigest(fields[1]) {
		return "", "", fmt.Errorf("running %s image identity is incomplete", name)
	}
	return strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1]), nil
}

func (t *sshTransport) httpsStatus(ctx context.Context, sess session, hostname, path string) (int, bool, error) {
	if !safeRuntimeHostname(hostname) || !safeRuntimePath(path) {
		return 0, false, errors.New("invalid HTTPS probe target")
	}
	resolve := hostname + ":443:127.0.0.1"
	url := "https://" + hostname + path
	command := "code=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' --connect-timeout 5 --max-time 10 --resolve " + shellQuote(resolve) + " " + shellQuote(url) + " 2>/dev/null || true); printf '%s\\n' \"$code\""
	stdout, err := t.runRemote(ctx, sess, command)
	if err != nil {
		return 0, false, err
	}
	text := strings.TrimSpace(string(stdout))
	if text == "" || text == "000" {
		return 0, false, nil
	}
	status, err := strconv.Atoi(text)
	if err != nil || status < 100 || status > 599 {
		return 0, false, errors.New("invalid HTTPS probe status")
	}
	return status, true, nil
}

func safeRuntimeHostname(value string) bool {
	if value == "" || value != strings.ToLower(value) || len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func safeRuntimePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "\r\n\x00")
}

func validRuntimeDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, r := range strings.TrimPrefix(value, "sha256:") {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}

func healthyHTTPSStatus(status int) bool {
	return status >= 200 && status < 500 && status != 404
}

func protectedRouteStatus(status int) bool {
	return (status >= 300 && status < 400) || status == 401 || status == 403
}
