package main

import (
	"bytes"
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
	"github.com/privat655/VPSmith/internal/sourcelibrary"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

type rejectingRegistry struct{}

func (rejectingRegistry) Resolve(context.Context, string) (string, error) {
	return "", errors.New("registry access is not available in the step 7 live test")
}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: vpsmith-step7-live prepare|enroll|diagnose"))
	}
	var err error
	switch os.Args[1] {
	case "prepare":
		err = prepare(os.Args[2:])
	case "enroll":
		err = enroll(os.Args[2:])
	case "diagnose":
		err = diagnose(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func prepare(args []string) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	stateDir := flags.String("state-dir", "", "management-state directory")
	sourcesDir := flags.String("sources-dir", "", "source-library directory")
	embeddedRoot := flags.String("embedded-root", "embedded", "embedded release source root")
	runtimeDir := flags.String("runtime-dir", "", "SSH runtime directory")
	output := flags.String("output", "", "Cloud-init output path")
	targetIDOutput := flags.String("target-id-output", "", "target id output path")
	hostname := flags.String("hostname", "vpsmith-step7", "target hostname")
	timezone := flags.String("timezone", "Etc/UTC", "target timezone")
	administrator := flags.String("administrator", "vpsmith", "administrator user")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *stateDir == "" || *sourcesDir == "" || *runtimeDir == "" || *output == "" || *targetIDOutput == "" {
		return errors.New("state-dir, sources-dir, runtime-dir, output, and target-id-output are required")
	}

	ctx := context.Background()
	state, gateway, closeFn, err := targetStack(*stateDir, *runtimeDir)
	if err != nil {
		return err
	}
	defer closeFn()
	sources, err := sourcelibrary.New(*sourcesDir, *embeddedRoot, state, sourcelibrary.NewGithubRemote())
	if err != nil {
		return err
	}
	if _, err := sources.ImportEmbedded(ctx); err != nil {
		return fmt.Errorf("import embedded source snapshots: %w", err)
	}
	bundles, err := executionbundle.NewAssembler(filepath.Join(*stateDir, "live-test-bundles"))
	if err != nil {
		return err
	}
	compiler, err := deployment.New(rejectingRegistry{}, bundles)
	if err != nil {
		return err
	}
	coordinator, err := bootstrap.New(state, gateway, compiler, sources)
	if err != nil {
		return err
	}
	prepared, err := coordinator.PrepareNewTarget(ctx, bootstrap.NewTargetRequest{
		Hostname: *hostname, Timezone: *timezone, Administrator: *administrator,
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
		"target_id":                 prepared.TargetID,
		"cloud_init_source_version": prepared.CloudInitSource.Version,
		"cloud_init_source_sha256":  prepared.CloudInitSource.SHA256,
		"cloud_init_output_sha256":  prepared.CloudInit.SHA256,
		"cloud_init_bytes":          len(prepared.CloudInit.Bytes),
		"ssh_public_fingerprint":    prepared.SSHIdentity.Fingerprint,
	})
}

func enroll(args []string) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	stateDir := flags.String("state-dir", "", "management-state directory")
	runtimeDir := flags.String("runtime-dir", "", "SSH runtime directory")
	targetID := flags.String("target-id", "", "target id")
	address := flags.String("address", "", "host:port address")
	timeout := flags.Duration("timeout", 20*time.Minute, "enrollment timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *stateDir == "" || *runtimeDir == "" || *targetID == "" || *address == "" {
		return errors.New("state-dir, runtime-dir, target-id, and address are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	state, gateway, closeFn, err := targetStack(*stateDir, *runtimeDir)
	if err != nil {
		return err
	}
	defer closeFn()
	id := managementstate.TargetID(*targetID)
	if err := state.Change(ctx, func(ch *managementstate.Change) error { return ch.SetTargetAddress(id, *address) }); err != nil {
		return err
	}

	var observation targetgateway.HostKeyObservation
	for attempt := 1; ; attempt++ {
		observation, err = gateway.ObserveHostKey(ctx, id)
		if err == nil {
			break
		}
		reportRetry("SSH host-key observation", attempt, err)
		if err := sleepContext(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("observe fresh target host key: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "SSH host key observed: %s\n", observation.Fingerprint)
	if err := gateway.ConfirmHostKey(ctx, id, observation); err != nil {
		return fmt.Errorf("confirm observed host key: %w", err)
	}
	fmt.Fprintln(os.Stderr, "SSH host key confirmed; waiting for Cloud-init and Primary Host Hardening")

	var result targetgateway.EnrollmentResult
	var lastErr error
	for attempt := 1; ; attempt++ {
		result, lastErr = gateway.Enroll(ctx, id)
		if lastErr == nil {
			break
		}
		reportRetry("enrollment", attempt, lastErr)
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

type liveDiagnostics struct {
	Observed     *managementstate.ObservedState `json:"observed,omitempty"`
	InspectError string                         `json:"inspect_error,omitempty"`
	Logs         map[string]string              `json:"logs,omitempty"`
	LogErrors    map[string]string              `json:"log_errors,omitempty"`
}

func diagnose(args []string) error {
	flags := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	stateDir := flags.String("state-dir", "", "management-state directory")
	runtimeDir := flags.String("runtime-dir", "", "SSH runtime directory")
	targetID := flags.String("target-id", "", "target id")
	address := flags.String("address", "", "host:port address")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *stateDir == "" || *runtimeDir == "" || *targetID == "" || *address == "" {
		return errors.New("state-dir, runtime-dir, target-id, and address are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	state, gateway, closeFn, err := targetStack(*stateDir, *runtimeDir)
	if err != nil {
		return err
	}
	defer closeFn()
	id := managementstate.TargetID(*targetID)
	if err := state.Change(ctx, func(ch *managementstate.Change) error { return ch.SetTargetAddress(id, *address) }); err != nil {
		return err
	}

	diagnostics := liveDiagnostics{Logs: map[string]string{}, LogErrors: map[string]string{}}
	observed, inspectErr := gateway.Inspect(ctx, id)
	if inspectErr != nil {
		diagnostics.InspectError = inspectErr.Error()
	} else {
		diagnostics.Observed = &observed
	}
	for _, unit := range []string{"cloud-final.service", "fail2ban.service"} {
		var buffer bytes.Buffer
		err := gateway.Logs(ctx, id, targetgateway.LogRequest{Kind: targetgateway.LogJournalUnit, Name: unit, Scope: "system", Lines: 200}, func(chunk targetgateway.LogChunk) error {
			_, writeErr := buffer.Write(chunk.Data)
			return writeErr
		})
		if err != nil {
			diagnostics.LogErrors[unit] = err.Error()
			continue
		}
		diagnostics.Logs[unit] = buffer.String()
	}
	if len(diagnostics.Logs) == 0 {
		diagnostics.Logs = nil
	}
	if len(diagnostics.LogErrors) == 0 {
		diagnostics.LogErrors = nil
	}
	return json.NewEncoder(os.Stdout).Encode(diagnostics)
}

func reportRetry(stage string, attempt int, err error) {
	if attempt == 1 || attempt%10 == 0 {
		fmt.Fprintf(os.Stderr, "%s not ready (attempt %d): %v\n", stage, attempt, err)
	}
}

func targetStack(stateDir, runtimeDir string) (*managementstate.Store, *targetgateway.Gateway, func(), error) {
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return nil, nil, nil, err
	}
	state, err := managementstate.Open(stateDir)
	if err != nil {
		return nil, nil, nil, err
	}
	gateway, err := targetgateway.New(state, runtimeDir)
	if err != nil {
		_ = state.Close()
		return nil, nil, nil, err
	}
	return state, gateway, func() { _ = state.Close() }, nil
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
