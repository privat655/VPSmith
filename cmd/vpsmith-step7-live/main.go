package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/privat655/VPSmith/internal/bootstrap"
	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

type rejectingRegistry struct{}

func (rejectingRegistry) Resolve(context.Context, string) (string, error) {
	return "", errors.New("registry access is not available in the step 7 live test")
}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: vpsmith-step7-live prepare|enroll"))
	}
	var err error
	switch os.Args[1] {
	case "prepare":
		err = prepare(os.Args[2:])
	case "enroll":
		err = enroll(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func prepare(args []string) error {
	fs := flag.NewFlagSet("prepare", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "", "management-state directory")
	runtimeDir := fs.String("runtime-dir", "", "SSH runtime directory")
	output := fs.String("output", "", "Cloud-init output path")
	targetIDOutput := fs.String("target-id-output", "", "target id output path")
	hostname := fs.String("hostname", "vpsmith-step7", "target hostname")
	timezone := fs.String("timezone", "Etc/UTC", "target timezone")
	administrator := fs.String("administrator", "vpsmith", "administrator user")
	version := fs.String("version", "step7-live-v1", "Cloud-init definition version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *stateDir == "" || *runtimeDir == "" || *output == "" || *targetIDOutput == "" {
		return errors.New("state-dir, runtime-dir, output, and target-id-output are required")
	}

	ctx := context.Background()
	state, gateway, compiler, closeFn, err := stack(*stateDir, *runtimeDir)
	if err != nil {
		return err
	}
	defer closeFn()
	coordinator, err := bootstrap.New(state, gateway, compiler)
	if err != nil {
		return err
	}
	prepared, err := coordinator.PrepareNewTarget(ctx, bootstrap.NewTargetRequest{
		Hostname: *hostname, Timezone: *timezone, Administrator: *administrator, DefinitionVersion: *version,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*output, prepared.CloudInit.Bytes, 0o600); err != nil {
		return fmt.Errorf("write Cloud-init: %w", err)
	}
	if err := os.WriteFile(*targetIDOutput, []byte(prepared.TargetID+"\n"), 0o600); err != nil {
		return fmt.Errorf("write target id: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"target_id":              prepared.TargetID,
		"cloud_init_sha256":      prepared.CloudInit.SHA256,
		"cloud_init_bytes":       len(prepared.CloudInit.Bytes),
		"ssh_public_fingerprint": prepared.SSHIdentity.Fingerprint,
	})
}

func enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "", "management-state directory")
	runtimeDir := fs.String("runtime-dir", "", "SSH runtime directory")
	targetID := fs.String("target-id", "", "target id")
	address := fs.String("address", "", "host:port address")
	timeout := fs.Duration("timeout", 20*time.Minute, "enrollment timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *stateDir == "" || *runtimeDir == "" || *targetID == "" || *address == "" {
		return errors.New("state-dir, runtime-dir, target-id, and address are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, gateway, _, closeFn, err := stack(*stateDir, *runtimeDir)
	if err != nil {
		return err
	}
	defer closeFn()
	id := managementstate.TargetID(*targetID)
	if err := state.Change(ctx, func(ch *managementstate.Change) error { return ch.SetTargetAddress(id, *address) }); err != nil {
		return err
	}

	var observation targetgateway.HostKeyObservation
	for {
		observation, err = gateway.ObserveHostKey(ctx, id)
		if err == nil {
			break
		}
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("observe fresh target host key: %w", err)
		}
	}
	if err := gateway.ConfirmHostKey(ctx, id, observation); err != nil {
		return fmt.Errorf("confirm observed host key: %w", err)
	}

	var result targetgateway.EnrollmentResult
	var lastErr error
	for {
		result, lastErr = gateway.Enroll(ctx, id)
		if lastErr == nil {
			break
		}
		if err := sleepContext(ctx, 3*time.Second); err != nil {
			return fmt.Errorf("enrollment did not become valid: %v: %w", lastErr, err)
		}
	}
	if result.Observed.Host.Swap.TotalBytes != 0 {
		return fmt.Errorf("fresh target unexpectedly has %d swap bytes", result.Observed.Host.Swap.TotalBytes)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		HostKey targetgateway.HostKeyObservation `json:"host_key"`
		Result  targetgateway.EnrollmentResult   `json:"enrollment"`
	}{HostKey: observation, Result: result})
}

func stack(stateDir, runtimeDir string) (*managementstate.Store, *targetgateway.Gateway, *deployment.Compiler, func(), error) {
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return nil, nil, nil, nil, err
	}
	state, err := managementstate.Open(stateDir)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	gateway, err := targetgateway.New(state, runtimeDir)
	if err != nil {
		_ = state.Close()
		return nil, nil, nil, nil, err
	}
	bundles, err := executionbundle.NewAssembler(filepath.Join(stateDir, "live-test-bundles"))
	if err != nil {
		_ = state.Close()
		return nil, nil, nil, nil, err
	}
	compiler, err := deployment.New(rejectingRegistry{}, bundles)
	if err != nil {
		_ = state.Close()
		return nil, nil, nil, nil, err
	}
	return state, gateway, compiler, func() { _ = state.Close() }, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
