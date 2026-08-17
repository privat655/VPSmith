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
	"strings"
	"time"

	"github.com/privat655/VPSmith/internal/application"
	"github.com/privat655/VPSmith/internal/bootstrap"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/targetgateway"
)

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: vpsmith-step7-live prepare|observe|confirm|enroll|diagnose"))
	}
	var err error
	switch os.Args[1] {
	case "prepare":
		err = prepare(os.Args[2:])
	case "observe":
		err = observe(os.Args[2:])
	case "confirm":
		err = confirm(os.Args[2:])
	case "enroll":
		err = enroll(os.Args[2:])
	case "diagnose":
		err = diagnose(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil { fatal(err) }
}

type appFlags struct {
	stateDir *string
	sourcesDir *string
	embeddedRoot *string
	runtimeDir *string
}

func addAppFlags(flags *flag.FlagSet) appFlags {
	return appFlags{
		stateDir: flags.String("state-dir", "", "management-state directory"),
		sourcesDir: flags.String("sources-dir", "", "source-library directory"),
		embeddedRoot: flags.String("embedded-root", "embedded", "embedded release source root"),
		runtimeDir: flags.String("runtime-dir", "", "SSH runtime directory"),
	}
}

func (f appFlags) open(ctx context.Context) (*application.Application, error) {
	if *f.stateDir == "" || *f.sourcesDir == "" || *f.runtimeDir == "" { return nil, errors.New("state-dir, sources-dir, and runtime-dir are required") }
	stateAbs, err := filepath.Abs(*f.stateDir); if err != nil { return nil, err }
	sourcesAbs, err := filepath.Abs(*f.sourcesDir); if err != nil { return nil, err }
	embeddedAbs, err := filepath.Abs(*f.embeddedRoot); if err != nil { return nil, err }
	runtimeAbs, err := filepath.Abs(*f.runtimeDir); if err != nil { return nil, err }
	return application.Open(ctx, application.Paths{
		StateDir: stateAbs,
		SourcesDir: sourcesAbs,
		BackupsDir: filepath.Join(stateAbs, "live-backups"),
		EmbeddedRoot: embeddedAbs,
		SSHRuntimeDir: runtimeAbs,
		BundlesDir: filepath.Join(stateAbs, "live-test-bundles"),
	})
}

func prepare(args []string) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	common := addAppFlags(flags)
	output := flags.String("output", "", "Cloud-init output path")
	targetIDOutput := flags.String("target-id-output", "", "target id output path")
	hostname := flags.String("hostname", "vpsmith-step7", "target hostname")
	timezone := flags.String("timezone", "Etc/UTC", "target timezone")
	administrator := flags.String("administrator", "vpsmith", "administrator user")
	if err := flags.Parse(args); err != nil { return err }
	if *output == "" || *targetIDOutput == "" { return errors.New("output and target-id-output are required") }
	ctx := context.Background()
	app, err := common.open(ctx); if err != nil { return err }
	defer app.Close()
	prepared, err := app.PrepareNewTarget(ctx, bootstrap.NewTargetRequest{Hostname: *hostname, Timezone: *timezone, Administrator: *administrator})
	if err != nil { return err }
	if err := os.WriteFile(*output, prepared.CloudInit.Bytes, 0o600); err != nil { return fmt.Errorf("write Cloud-init: %w", err) }
	if err := os.WriteFile(*targetIDOutput, []byte(prepared.TargetID+"\n"), 0o600); err != nil { return fmt.Errorf("write target id: %w", err) }
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"target_id": prepared.TargetID,
		"cloud_init_source_id": prepared.CloudInitSource.ID,
		"cloud_init_source_version": prepared.CloudInitSource.Version,
		"cloud_init_source_sha256": prepared.CloudInitSource.SHA256,
		"cloud_init_output_sha256": prepared.CloudInit.SHA256,
		"cloud_init_bytes": len(prepared.CloudInit.Bytes),
		"ssh_public_fingerprint": prepared.SSHIdentity.Fingerprint,
	})
}

func observe(args []string) error {
	flags := flag.NewFlagSet("observe", flag.ContinueOnError)
	common := addAppFlags(flags)
	targetID := flags.String("target-id", "", "target id")
	address := flags.String("address", "", "host:port address")
	output := flags.String("output", "", "host-key observation output path")
	timeout := flags.Duration("timeout", 20*time.Minute, "observation timeout")
	if err := flags.Parse(args); err != nil { return err }
	if *targetID == "" || *address == "" || *output == "" { return errors.New("target-id, address, and output are required") }
	ctx, cancel := context.WithTimeout(context.Background(), *timeout); defer cancel()
	app, err := common.open(ctx); if err != nil { return err }; defer app.Close()
	id := managementstate.TargetID(*targetID)
	if err := app.SetTargetAddress(ctx, id, *address); err != nil { return err }
	var observation targetgateway.HostKeyObservation
	for attempt := 1; ; attempt++ {
		observation, err = app.ObserveHostKey(ctx, id)
		if err == nil { break }
		reportRetry("SSH host-key observation", attempt, err)
		if err := sleepContext(ctx, 2*time.Second); err != nil { return fmt.Errorf("observe fresh target host key: %w", err) }
	}
	data, err := json.MarshalIndent(observation, "", "  "); if err != nil { return err }
	data = append(data, '\n')
	if err := os.WriteFile(*output, data, 0o600); err != nil { return fmt.Errorf("write host-key observation: %w", err) }
	fmt.Fprintf(os.Stderr, "SSH host key observed, not trusted: %s\n", observation.Fingerprint)
	return json.NewEncoder(os.Stdout).Encode(observation)
}

func confirm(args []string) error {
	flags := flag.NewFlagSet("confirm", flag.ContinueOnError)
	common := addAppFlags(flags)
	targetID := flags.String("target-id", "", "target id")
	observationPath := flags.String("observation", "", "previous host-key observation JSON")
	if err := flags.Parse(args); err != nil { return err }
	if *targetID == "" || *observationPath == "" { return errors.New("target-id and observation are required") }
	ctx := context.Background()
	app, err := common.open(ctx); if err != nil { return err }; defer app.Close()
	data, err := os.ReadFile(*observationPath); if err != nil { return fmt.Errorf("read host-key observation: %w", err) }
	var observation targetgateway.HostKeyObservation
	if err := json.Unmarshal(data, &observation); err != nil { return fmt.Errorf("decode host-key observation: %w", err) }
	if err := app.ConfirmHostKey(ctx, managementstate.TargetID(*targetID), observation); err != nil { return fmt.Errorf("confirm explicitly approved host key: %w", err) }
	fmt.Fprintf(os.Stderr, "SSH host key explicitly confirmed: %s\n", observation.Fingerprint)
	return nil
}

func enroll(args []string) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	common := addAppFlags(flags)
	targetID := flags.String("target-id", "", "target id")
	timeout := flags.Duration("timeout", 20*time.Minute, "enrollment timeout")
	if err := flags.Parse(args); err != nil { return err }
	if *targetID == "" { return errors.New("target-id is required") }
	ctx, cancel := context.WithTimeout(context.Background(), *timeout); defer cancel()
	app, err := common.open(ctx); if err != nil { return err }; defer app.Close()
	id := managementstate.TargetID(*targetID)
	var result targetgateway.EnrollmentResult
	var lastErr error
	for attempt := 1; ; attempt++ {
		result, lastErr = app.Enroll(ctx, id)
		if lastErr == nil { break }
		if errors.Is(lastErr, targetgateway.ErrTrustRequired) { return lastErr }
		reportRetry("enrollment", attempt, lastErr)
		if attempt == 1 || attempt%3 == 0 {
			marker, markerErr := cloudFinalFailure(ctx, app.Gateway(), id)
			if markerErr == nil && marker != "" { return fmt.Errorf("cloud-init Primary Host Hardening failed: %s", marker) }
		}
		if err := sleepContext(ctx, 3*time.Second); err != nil { return fmt.Errorf("enrollment did not become valid: %v: %w", lastErr, err) }
	}
	if result.Observed.Host.Swap.TotalBytes != 0 { return fmt.Errorf("fresh target unexpectedly has %d swap bytes", result.Observed.Host.Swap.TotalBytes) }
	return json.NewEncoder(os.Stdout).Encode(result)
}

func cloudFinalFailure(ctx context.Context, gateway *targetgateway.Gateway, id managementstate.TargetID) (string, error) {
	var buffer bytes.Buffer
	err := gateway.Logs(ctx, id, targetgateway.LogRequest{Kind: targetgateway.LogJournalUnit, Name: "cloud-final.service", Scope: "system", Lines: 80}, func(chunk targetgateway.LogChunk) error { _, writeErr := buffer.Write(chunk.Data); return writeErr })
	if err != nil { return "", err }
	return primaryFailureMarker(buffer.String()), nil
}

func primaryFailureMarker(logText string) string {
	const prefix = "vpsmith-primary-failed stage="
	for _, line := range strings.Split(logText, "\n") { if index := strings.Index(line, prefix); index >= 0 { return strings.TrimSpace(line[index:]) } }
	return ""
}

type liveDiagnostics struct {
	Observed *managementstate.ObservedState `json:"observed,omitempty"`
	InspectError string `json:"inspect_error,omitempty"`
	Logs map[string]string `json:"logs,omitempty"`
	LogErrors map[string]string `json:"log_errors,omitempty"`
}

func diagnose(args []string) error {
	flags := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	common := addAppFlags(flags)
	targetID := flags.String("target-id", "", "target id")
	if err := flags.Parse(args); err != nil { return err }
	if *targetID == "" { return errors.New("target-id is required") }
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second); defer cancel()
	app, err := common.open(ctx); if err != nil { return err }; defer app.Close()
	id := managementstate.TargetID(*targetID)
	gateway := app.Gateway()
	diagnostics := liveDiagnostics{Logs: map[string]string{}, LogErrors: map[string]string{}}
	observed, inspectErr := gateway.Inspect(ctx, id)
	if inspectErr != nil { diagnostics.InspectError = inspectErr.Error() } else { diagnostics.Observed = &observed }
	for _, unit := range []string{"cloud-final.service", "fail2ban.service"} {
		var buffer bytes.Buffer
		err := gateway.Logs(ctx, id, targetgateway.LogRequest{Kind: targetgateway.LogJournalUnit, Name: unit, Scope: "system", Lines: 200}, func(chunk targetgateway.LogChunk) error { _, writeErr := buffer.Write(chunk.Data); return writeErr })
		if err != nil { diagnostics.LogErrors[unit] = err.Error(); continue }
		diagnostics.Logs[unit] = buffer.String()
	}
	if len(diagnostics.Logs) == 0 { diagnostics.Logs = nil }
	if len(diagnostics.LogErrors) == 0 { diagnostics.LogErrors = nil }
	return json.NewEncoder(os.Stdout).Encode(diagnostics)
}

func reportRetry(stage string, attempt int, err error) { if attempt == 1 || attempt%10 == 0 { fmt.Fprintf(os.Stderr, "%s not ready (attempt %d): %v\n", stage, attempt, err) } }
func sleepContext(ctx context.Context, d time.Duration) error { timer := time.NewTimer(d); defer timer.Stop(); select { case <-ctx.Done(): return ctx.Err(); case <-timer.C: return nil } }
func fatal(err error) { _, _ = fmt.Fprintln(os.Stderr, err); os.Exit(1) }
