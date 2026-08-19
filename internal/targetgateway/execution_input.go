package targetgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	args, cleanup, err := t.prepareSSHInvocation(sess, remoteCommand)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()
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
