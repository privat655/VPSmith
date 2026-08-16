package targetgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/privat655/VPSmith/internal/execution"
)

func (execRunner) RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func (t *sshTransport) runRemoteInput(ctx context.Context, sess session, remoteCommand string, input []byte) ([]byte, []byte, error) {
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
	defer zero(privateKey)
	identityFile, err := writeExclusiveTemp(t.runtimeDir, "identity-", privateKey, 0o600)
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(identityFile)
	knownHost := knownHostsName(parsed) + " " + strings.TrimSpace(sess.HostKey) + "\n"
	knownHostsFile, err := writeExclusiveTemp(t.runtimeDir, "known-hosts-", []byte(knownHost), 0o600)
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(knownHostsFile)
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
	runner, ok := t.runner.(inputProcessRunner)
	if !ok {
		return nil, nil, errors.New("ssh process runner does not support stdin")
	}
	stdout, stderr, err := runner.RunInput(ctx, input, "ssh", args...)
	if err != nil {
		return stdout, stderr, errors.New("strict ssh execution transport failed")
	}
	return stdout, stderr, nil
}

func parseExecutionObservation(raw []byte) (execution.Observation, error) {
	var out execution.Observation
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	seen := map[string]bool{}
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "\t")
		if !ok || seen[key] {
			return execution.Observation{}, errors.New("invalid execution observation output")
		}
		seen[key] = true
		switch key {
		case "PROOF":
			if value == "" {
				continue
			}
			var proof execution.Proof
			if err := json.Unmarshal([]byte(value), &proof); err != nil {
				return execution.Observation{}, fmt.Errorf("decode execution proof: %w", err)
			}
			out.Proof = &proof
		case "LOCK":
			out.LockHeld = value == "1"
		case "UNIT":
			out.UnitRunning = value == "1"
		default:
			return execution.Observation{}, errors.New("unknown execution observation field")
		}
	}
	if err := scanner.Err(); err != nil {
		return execution.Observation{}, err
	}
	if !seen["PROOF"] || !seen["LOCK"] || !seen["UNIT"] {
		return execution.Observation{}, errors.New("incomplete execution observation output")
	}
	return out, nil
}
