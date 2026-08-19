package targetgateway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const (
	cloudInitStatusPath = "/var/lib/vpsmith/cloud-init/status"
	coreInventoryPath   = "/var/lib/vpsmith/inventory/core.json"
	moduleInventoryPath = "/var/lib/vpsmith/inventory/modules.json"
	linkInventoryPath   = "/var/lib/vpsmith/inventory/link-networks.json"
)

type processRunner interface {
	Run(context.Context, string, ...string) ([]byte, []byte, error)
}

type outputProcessRunner interface {
	RunOutput(context.Context, io.Writer, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func (execRunner) RunOutput(ctx context.Context, output io.Writer, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = output
	var stderr bytes.Buffer
	command.Stderr = &stderr
	err := command.Run()
	return stderr.Bytes(), err
}

type sshTransport struct {
	runner     processRunner
	runtimeDir string
}

func newSSHTransport(runtimeDir string) *sshTransport {
	return &sshTransport{runner: execRunner{}, runtimeDir: runtimeDir}
}

func newSSHTransportAt(runtimeDir string, runner processRunner) *sshTransport {
	return &sshTransport{runner: runner, runtimeDir: runtimeDir}
}

type parsedEndpoint struct {
	host string
	port string
}

func (t *sshTransport) ObserveHostKey(ctx context.Context, target endpoint) (HostKeyObservation, error) {
	parsed, err := parseEndpoint(target.Address)
	if err != nil {
		return HostKeyObservation{}, err
	}
	stdout, _, err := t.runner.Run(ctx, "ssh-keyscan", "-T", "5", "-p", parsed.port, "-t", "ed25519,ecdsa,rsa", parsed.host)
	if err != nil && len(bytes.TrimSpace(stdout)) == 0 {
		return HostKeyObservation{}, errors.New("ssh-keyscan failed")
	}
	return selectHostKey(stdout)
}

func (t *sshTransport) Inspect(ctx context.Context, sess session) (managementstate.ObservedState, error) {
	result := managementstate.ObservedState{}
	host, err := t.hostFacts(ctx, sess)
	if err != nil {
		return result, err
	}
	cloudInit, err := t.cloudInitFacts(ctx, sess)
	if err != nil {
		return result, err
	}
	if cloudInit.Present && cloudInit.Status == "ok" {
		hardening, err := t.InspectPrimaryHardening(ctx, sess)
		if err != nil {
			return result, fmt.Errorf("inspect primary hardening: %w", err)
		}
		host.PrimaryHardening = hardening
	}
	result.Host = host
	result.CloudInit = cloudInit
	core, err := t.coreFacts(ctx, sess)
	if err != nil {
		return result, err
	}
	result.Core = core
	modules, err := t.moduleFacts(ctx, sess)
	if err != nil {
		return result, err
	}
	result.Modules = modules
	links, err := t.linkFacts(ctx, sess)
	if err != nil {
		return result, err
	}
	networks, links, err := t.planningNetworkFacts(ctx, sess, links)
	if err != nil {
		return result, err
	}
	result.PodmanNetworks = networks
	result.LinkNetworks = links
	return result, nil
}

func (t *sshTransport) Logs(ctx context.Context, sess session, request LogRequest, consume func(LogChunk) error) error {
	var command string
	switch request.Kind {
	case LogJournalUnit:
		scope := request.Scope
		if scope == "" {
			scope = "user"
		}
		if scope != "user" && scope != "system" {
			return errors.New("journal scope must be user or system")
		}
		prefix := "journalctl"
		if scope == "user" {
			prefix += " --user"
		}
		command = prefix + " --no-pager -n " + strconv.Itoa(request.Lines) + " -o short-iso-precise -u " + shellQuote(request.Name)
	case LogPodmanContainer:
		command = "podman logs --tail " + strconv.Itoa(request.Lines) + " " + shellQuote(request.Name)
	default:
		return errors.New("unsupported log kind")
	}
	stdout, stderr, err := t.runRemoteStreams(ctx, sess, command)
	if err != nil {
		return err
	}
	for _, stream := range []struct {
		name string
		data []byte
	}{{name: "stdout", data: stdout}, {name: "stderr", data: stderr}} {
		const chunkSize = 32 * 1024
		for len(stream.data) > 0 {
			n := len(stream.data)
			if n > chunkSize {
				n = chunkSize
			}
			chunk := append([]byte(nil), stream.data[:n]...)
			if err := consume(LogChunk{Stream: stream.name, Data: chunk}); err != nil {
				return err
			}
			stream.data = stream.data[n:]
		}
	}
	return nil
}

func (t *sshTransport) readOptional(ctx context.Context, sess session, path string) ([]byte, error) {
	command := "if [ -r " + shellQuote(path) + " ]; then cat -- " + shellQuote(path) + "; fi"
	return t.runRemote(ctx, sess, command)
}

func (t *sshTransport) runRemote(ctx context.Context, sess session, remoteCommand string) ([]byte, error) {
	stdout, _, err := t.runRemoteStreams(ctx, sess, remoteCommand)
	return stdout, err
}

func (t *sshTransport) runRemoteStreams(ctx context.Context, sess session, remoteCommand string) ([]byte, []byte, error) {
	args, cleanup, err := t.prepareSSHInvocation(sess, remoteCommand)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()
	stdout, stderr, err := t.runner.Run(ctx, "ssh", args...)
	if err != nil {
		return nil, nil, errors.New("strict ssh read operation failed")
	}
	return stdout, stderr, nil
}

func (t *sshTransport) runRemoteOutput(ctx context.Context, sess session, remoteCommand string, output io.Writer) ([]byte, error) {
	if output == nil {
		return nil, errors.New("ssh output writer is required")
	}
	args, cleanup, err := t.prepareSSHInvocation(sess, remoteCommand)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	runner, ok := t.runner.(outputProcessRunner)
	if !ok {
		return nil, errors.New("ssh process runner does not support streamed stdout")
	}
	stderr, err := runner.RunOutput(ctx, output, "ssh", args...)
	if err != nil {
		return stderr, errors.New("strict ssh streamed operation failed")
	}
	return stderr, nil
}

func (t *sshTransport) prepareSSHInvocation(sess session, remoteCommand string) ([]string, func(), error) {
	parsed, err := parseEndpoint(sess.Address)
	if err != nil {
		return nil, nil, err
	}
	if !safeSSHUser(sess.SSHUser) {
		return nil, nil, errors.New("invalid ssh user")
	}
	if t.runtimeDir == "" {
		return nil, nil, errors.New("ssh runtime directory is required")
	}
	if err := os.MkdirAll(t.runtimeDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create ssh runtime directory: %w", err)
	}
	if err := os.Chmod(t.runtimeDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("secure ssh runtime directory: %w", err)
	}
	privateKey, err := marshalOpenSSHPrivateKey("vpsmith:"+sess.SSHUser+"@"+parsed.host, sess.IdentitySeed)
	if err != nil {
		return nil, nil, err
	}
	identityFile, err := writeExclusiveTemp(t.runtimeDir, "identity-", privateKey, 0o600)
	zero(privateKey)
	if err != nil {
		return nil, nil, err
	}
	knownHost := knownHostsName(parsed) + " " + strings.TrimSpace(sess.HostKey) + "\n"
	knownHostsFile, err := writeExclusiveTemp(t.runtimeDir, "known-hosts-", []byte(knownHost), 0o600)
	if err != nil {
		_ = os.Remove(identityFile)
		return nil, nil, err
	}
	cleanup := func() {
		_ = os.Remove(identityFile)
		_ = os.Remove(knownHostsFile)
	}
	args := []string{
		"-F", "none", "-a", "-x", "-T",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHostsFile,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UpdateHostKeys=no",
		"-o", "CheckHostIP=no",
		"-o", "VerifyHostKeyDNS=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PubkeyAuthentication=yes",
		"-o", "ClearAllForwardings=yes",
		"-o", "PermitLocalCommand=no",
		"-o", "ConnectTimeout=8",
		"-o", "ConnectionAttempts=1",
		"-i", identityFile,
		"-p", parsed.port,
		sess.SSHUser + "@" + parsed.host,
		remoteCommand,
	}
	return args, cleanup, nil
}

func writeExclusiveTemp(dir, pattern string, content []byte, mode os.FileMode) (string, error) {
	file, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("create ssh runtime file: %w", err)
	}
	name := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return "", fmt.Errorf("secure ssh runtime file: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		return "", fmt.Errorf("write ssh runtime file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync ssh runtime file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close ssh runtime file: %w", err)
	}
	ok = true
	return name, nil
}

func parseEndpoint(address string) (parsedEndpoint, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return parsedEndpoint{}, errors.New("target address is required")
	}
	if ip := net.ParseIP(address); ip != nil {
		return parsedEndpoint{host: ip.String(), port: "22"}, nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return parsedEndpoint{}, errors.New("target address must be an IP address or IP:port")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return parsedEndpoint{}, errors.New("target address must contain an IP address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return parsedEndpoint{}, errors.New("target ssh port is invalid")
	}
	return parsedEndpoint{host: ip.String(), port: strconv.Itoa(portNumber)}, nil
}

func knownHostsName(value parsedEndpoint) string {
	if value.port == "22" {
		return value.host
	}
	return "[" + value.host + "]:" + value.port
}

func selectHostKey(stdout []byte) (HostKeyObservation, error) {
	byAlgorithm := map[string]map[string]HostKeyObservation{}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		key := fields[1] + " " + fields[2]
		algorithm, _, fingerprint, err := parsePublicKey(key)
		if err != nil {
			return HostKeyObservation{}, err
		}
		if byAlgorithm[algorithm] == nil {
			byAlgorithm[algorithm] = map[string]HostKeyObservation{}
		}
		byAlgorithm[algorithm][key] = HostKeyObservation{Algorithm: algorithm, PublicKey: key, Fingerprint: fingerprint}
	}
	if err := scanner.Err(); err != nil {
		return HostKeyObservation{}, err
	}
	for _, algorithm := range []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"} {
		candidates := byAlgorithm[algorithm]
		if len(candidates) == 0 {
			continue
		}
		if len(candidates) != 1 {
			return HostKeyObservation{}, fmt.Errorf("ambiguous %s host keys", algorithm)
		}
		for _, candidate := range candidates {
			return candidate, nil
		}
	}
	return HostKeyObservation{}, errors.New("no supported ssh host key observed")
}

func parseTabFacts(raw []byte) (map[string]string, error) {
	result := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "\t")
		if !ok || key == "" {
			return nil, errors.New("invalid host fact output")
		}
		result[key] = value
	}
	return result, scanner.Err()
}

func parseEqualsFacts(raw []byte) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			result[key] = value
		}
	}
	return result
}

func int64Fact(values map[string]string, key string) (int64, error) {
	value, ok := values[key]
	if !ok {
		return 0, fmt.Errorf("host fact %s is missing", key)
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("host fact %s is invalid", key)
	}
	return parsed, nil
}

func safeSSHUser(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9') || (i > 0 && (r == '-' || r == '_')) {
			continue
		}
		return false
	}
	return true
}

func safeObjectName(value string) bool {
	if value == "" || len(value) > 255 || value[0] == '-' {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._@:-", r) {
			continue
		}
		return false
	}
	return true
}

func safeArtifactPath(value string) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, prefix := range []string{"/etc/vpsmith/", "/var/lib/vpsmith/", "/home/"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func isHex(value string) bool {
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

var _ transport = (*sshTransport)(nil)
