package targetgateway

import (
	"context"
	"errors"
	"io"
	"os/exec"
)

type inputStreamProcessRunner interface {
	RunInputStream(context.Context, io.Reader, string, ...string) ([]byte, []byte, error)
}

func (execRunner) RunInputStream(ctx context.Context, input io.Reader, name string, args ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = input
	stdout, err := command.Output()
	if err == nil {
		return stdout, nil, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout, append([]byte(nil), exitErr.Stderr...), err
	}
	return stdout, nil, err
}

func (t *sshTransport) runRemoteInputStream(ctx context.Context, sess session, remoteCommand string, input io.Reader) ([]byte, []byte, error) {
	if input == nil {
		return nil, nil, errors.New("ssh input reader is required")
	}
	args, cleanup, err := t.prepareSSHInvocation(sess, remoteCommand)
	if err != nil {
		return nil, nil, err
	}
	defer cleanup()
	runner, ok := t.runner.(inputStreamProcessRunner)
	if !ok {
		return nil, nil, errors.New("ssh process runner does not support streamed stdin")
	}
	stdout, stderr, err := runner.RunInputStream(ctx, input, "ssh", args...)
	if err != nil {
		return stdout, stderr, errors.New("strict ssh streamed input operation failed")
	}
	return stdout, stderr, nil
}
