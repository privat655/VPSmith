package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/privat655/VPSmith/internal/application"
	"github.com/privat655/VPSmith/internal/corelifecycle"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcehash"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

const (
	ciOperatorUser  = "ci-operator"
	ciOperatorGroup = "ci-admins"
)

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: vpsmith-step9-live run|assert-primary-block"))
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runAcceptance(os.Args[2:])
	case "assert-primary-block":
		err = assertPrimaryBlock(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

type appPathFlags struct {
	stateDir     *string
	sourcesDir   *string
	backupsDir   *string
	embeddedRoot *string
	runtimeDir   *string
	bundlesDir   *string
}

func addAppPathFlags(flags *flag.FlagSet) appPathFlags {
	return appPathFlags{
		stateDir:     flags.String("state-dir", "", "management-state directory"),
		sourcesDir:   flags.String("sources-dir", "", "source-library directory"),
		backupsDir:   flags.String("backups-dir", "", "backup catalog directory"),
		embeddedRoot: flags.String("embedded-root", "embedded", "embedded release source root"),
		runtimeDir:   flags.String("runtime-dir", "", "SSH runtime directory"),
		bundlesDir:   flags.String("bundles-dir", "", "execution bundle directory"),
	}
}

func (f appPathFlags) paths(embeddedOverride string) (application.Paths, error) {
	if *f.stateDir == "" || *f.sourcesDir == "" || *f.backupsDir == "" || *f.runtimeDir == "" || *f.bundlesDir == "" {
		return application.Paths{}, errors.New("state-dir, sources-dir, backups-dir, runtime-dir, and bundles-dir are required")
	}
	embedded := *f.embeddedRoot
	if embeddedOverride != "" {
		embedded = embeddedOverride
	}
	stateDir, err := filepath.Abs(*f.stateDir)
	if err != nil {
		return application.Paths{}, err
	}
	sourcesDir, err := filepath.Abs(*f.sourcesDir)
	if err != nil {
		return application.Paths{}, err
	}
	backupsDir, err := filepath.Abs(*f.backupsDir)
	if err != nil {
		return application.Paths{}, err
	}
	embeddedRoot, err := filepath.Abs(embedded)
	if err != nil {
		return application.Paths{}, err
	}
	runtimeDir, err := filepath.Abs(*f.runtimeDir)
	if err != nil {
		return application.Paths{}, err
	}
	bundlesDir, err := filepath.Abs(*f.bundlesDir)
	if err != nil {
		return application.Paths{}, err
	}
	return application.Paths{
		StateDir:      stateDir,
		SourcesDir:    sourcesDir,
		BackupsDir:    backupsDir,
		EmbeddedRoot:  embeddedRoot,
		SSHRuntimeDir: runtimeDir,
		BundlesDir:    bundlesDir,
	}, nil
}

type acceptanceResult struct {
	Initial                coreFingerprint `json:"initial_core"`
	AfterSwap              coreFingerprint `json:"after_swap"`
	AfterUpdate            coreFingerprint `json:"after_update"`
	AfterPreviousRestore   coreFingerprint `json:"after_previous_restore"`
	ExplicitBackupVerified bool            `json:"explicit_backup_verified"`
	ReconnectVerified      bool            `json:"reconnect_verified"`
	StudioSourceChanged    bool            `json:"studio_source_changed"`
	StudioNoTargetMutation bool            `json:"studio_no_target_mutation"`
}

type coreFingerprint struct {
	SourceID       managementstate.SourceSnapshotID `json:"source_id"`
	Version        string                           `json:"version"`
	PackageSHA256  string                           `json:"package_sha256"`
	CaddyDigest    string                           `json:"caddy_digest"`
	AutheliaDigest string                           `json:"authelia_digest"`
	HTTPS          bool                             `json:"https"`
}

func runAcceptance(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	common := addAppPathFlags(flags)
	targetIDRaw := flags.String("target-id", "", "target id")
	domain := flags.String("domain", "ci.example.com", "Core base domain")
	acmeEmail := flags.String("acme-email", "ci@example.invalid", "ACME contact email")
	nextEmbeddedRoot := flags.String("next-embedded-root", "", "scratch embedded root for the newer Studio image proof")
	output := flags.String("output", "", "acceptance result JSON")
	timeout := flags.Duration("timeout", 75*time.Minute, "acceptance timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *targetIDRaw == "" || *nextEmbeddedRoot == "" || *output == "" {
		return errors.New("target-id, next-embedded-root, and output are required")
	}
	paths, err := common.paths("")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	targetID := managementstate.TargetID(*targetIDRaw)

	passphrase, err := randomASCIISecret(32)
	if err != nil {
		return err
	}
	defer zero(passphrase)

	var refs managementstate.CoreSecretReferences
	if err := withApp(ctx, paths, func(app *application.Application) error {
		var createErr error
		refs, createErr = createCoreSecrets(ctx, app.State())
		if createErr != nil {
			return createErr
		}
		observed, err := app.Core().Diagnose(ctx, targetID)
		if err != nil {
			return fmt.Errorf("diagnose fresh Step-7 target: %w", err)
		}
		if observed.Core.Present {
			return errors.New("fresh Step-7 target unexpectedly already has Core")
		}
		prepared, err := app.Core().PrepareInstall(ctx, corelifecycle.PrepareRequest{
			TargetID: targetID,
			Configuration: corelifecycle.CoreConfiguration{
				Domain:    *domain,
				ACMEEmail: *acmeEmail,
				Authelia: managementstate.CoreAutheliaDesiredState{
					Users:      []string{ciOperatorUser},
					Groups:     []string{ciOperatorGroup},
					Enrollment: "self-service-totp",
				},
				Secrets: refs,
			},
			Swap: managementstate.SwapDesiredState{Mode: "none"},
		})
		if err != nil {
			return fmt.Errorf("prepare Core install: %w", err)
		}
		if _, err := app.Core().Execute(ctx, prepared); err != nil {
			return fmt.Errorf("execute Core install: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	result := acceptanceResult{}
	if err := withApp(ctx, paths, func(app *application.Application) error {
		observed, err := app.Core().Diagnose(ctx, targetID)
		if err != nil {
			return fmt.Errorf("diagnose Core after reconnect: %w", err)
		}
		result.Initial, err = healthyFingerprint(observed)
		if err != nil {
			return fmt.Errorf("validate installed Core after reconnect: %w", err)
		}
		result.ReconnectVerified = true
		return nil
	}); err != nil {
		return err
	}

	if err := withApp(ctx, paths, func(app *application.Application) error {
		prepared, err := app.Core().PrepareSwapChange(ctx, corelifecycle.PrepareRequest{
			TargetID: targetID,
			Swap:     managementstate.SwapDesiredState{Mode: "swapfile", SizeGiB: 1},
		})
		if err != nil {
			return fmt.Errorf("prepare Core swap change: %w", err)
		}
		if _, err := app.Core().Execute(ctx, prepared); err != nil {
			return fmt.Errorf("execute Core swap change: %w", err)
		}
		observed, err := app.Core().Diagnose(ctx, targetID)
		if err != nil {
			return err
		}
		result.AfterSwap, err = healthyFingerprint(observed)
		if err != nil {
			return err
		}
		if result.AfterSwap.SourceID != result.Initial.SourceID || result.AfterSwap.PackageSHA256 != result.Initial.PackageSHA256 {
			return errors.New("Core reconfigure changed exact Core package identity")
		}
		if len(observed.Host.SwapDevices) != 1 || !observed.Host.SwapDevices[0].CoreManaged || observed.Host.SwapDevices[0].SizeBytes != 1<<30 {
			return fmt.Errorf("Core swap post-state is not the approved 1 GiB Core swapfile: %#v", observed.Host.SwapDevices)
		}
		return nil
	}); err != nil {
		return err
	}

	var preUpdate coreFingerprint
	var updateBackupID managementstate.BackupArtifactID
	if err := withApp(ctx, paths, func(app *application.Application) error {
		artifact, err := app.Core().Backup(ctx, corelifecycle.BackupRequest{TargetID: targetID, Passphrase: passphrase})
		if err != nil {
			return fmt.Errorf("create explicit Core backup: %w", err)
		}
		inspection, err := app.Backups().InspectArtifact(ctx, artifact.Metadata.ID, managementstate.BackupCore, passphrase)
		if err != nil {
			return fmt.Errorf("verify explicit Core backup: %w", err)
		}
		_ = inspection.Close()
		result.ExplicitBackupVerified = true

		observed, err := app.Core().Diagnose(ctx, targetID)
		if err != nil {
			return err
		}
		preUpdate, err = healthyFingerprint(observed)
		if err != nil {
			return err
		}

		workspace, err := app.Sources().CreateWorkspace(ctx, preUpdate.SourceID)
		if err != nil {
			return fmt.Errorf("create Core update workspace: %w", err)
		}
		if _, err := app.Sources().Apply(ctx, workspace.ID, []sourcelibrary.Edit{{
			Path:    "step9-live-update-marker.txt",
			Content: []byte("VPSmith Step 9 live update candidate\n"),
			Mode:    0o644,
		}}); err != nil {
			return fmt.Errorf("edit Core update workspace: %w", err)
		}
		adopted, err := app.Sources().AdoptCoreWorkspace(ctx, workspace.ID)
		if err != nil {
			return fmt.Errorf("adopt Core update workspace: %w", err)
		}
		if adopted.ID == preUpdate.SourceID || adopted.SHA256 == preUpdate.PackageSHA256 {
			return errors.New("adopted Core update candidate did not acquire a new immutable identity")
		}
		prepared, err := app.Core().PrepareUpdateWithBackup(ctx, corelifecycle.PrepareRequest{
			TargetID:         targetID,
			Candidate:        sourcelibrary.CoreCandidateRef{SnapshotID: adopted.ID},
			BackupPassphrase: passphrase,
		})
		if err != nil {
			return fmt.Errorf("prepare controlled Core update: %w", err)
		}
		updateBackupID = prepared.Previous.BackupID
		if prepared.Previous.SourceID != preUpdate.SourceID || prepared.Previous.PackageSHA256 != preUpdate.PackageSHA256 {
			return errors.New("Core update immediate backup does not identify the exact previous Core")
		}
		if _, err := app.Core().Execute(ctx, prepared.Prepared); err != nil {
			return fmt.Errorf("execute controlled Core update: %w", err)
		}
		observed, err = app.Core().Diagnose(ctx, targetID)
		if err != nil {
			return err
		}
		result.AfterUpdate, err = healthyFingerprint(observed)
		if err != nil {
			return err
		}
		if result.AfterUpdate.SourceID != adopted.ID || result.AfterUpdate.PackageSHA256 != adopted.SHA256 {
			return errors.New("observed Core update identity does not match the adopted immutable candidate")
		}
		return nil
	}); err != nil {
		return err
	}

	if updateBackupID == "" {
		return errors.New("controlled Core update did not retain its immediate backup identity")
	}
	if err := withApp(ctx, paths, func(app *application.Application) error {
		prepared, err := app.Core().PreparePreviousCoreRestore(ctx, corelifecycle.PreviousCoreRestoreRequest{
			TargetID:         targetID,
			BackupPassphrase: passphrase,
		})
		if err != nil {
			return fmt.Errorf("prepare Previous Core Restore: %w", err)
		}
		if _, err := app.Core().ExecuteRestore(ctx, prepared, corelifecycle.RestoreExecutionRequest{
			BackupID:   updateBackupID,
			Passphrase: passphrase,
		}); err != nil {
			return fmt.Errorf("execute Previous Core Restore: %w", err)
		}
		observed, err := app.Core().Diagnose(ctx, targetID)
		if err != nil {
			return err
		}
		result.AfterPreviousRestore, err = healthyFingerprint(observed)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(result.AfterPreviousRestore, preUpdate) {
			return fmt.Errorf("Previous Core Restore did not recover exact previous Core: got=%#v want=%#v", result.AfterPreviousRestore, preUpdate)
		}
		return nil
	}); err != nil {
		return err
	}

	beforeCounts, beforeDesired, err := stateExecutionAndDesired(ctx, paths, targetID)
	if err != nil {
		return err
	}
	if err := prepareNextStudioEmbedded(paths.EmbeddedRoot, *nextEmbeddedRoot); err != nil {
		return fmt.Errorf("prepare newer Studio image fixture: %w", err)
	}
	nextPaths, err := common.paths(*nextEmbeddedRoot)
	if err != nil {
		return err
	}
	if err := withApp(ctx, nextPaths, func(app *application.Application) error {
		nextCore, err := app.Sources().CurrentEmbedded(ctx, managementstate.SourceCore)
		if err != nil {
			return fmt.Errorf("load newer Studio embedded Core source: %w", err)
		}
		if nextCore.SHA256 == result.AfterPreviousRestore.PackageSHA256 {
			return errors.New("newer Studio image did not expose a different embedded Core source")
		}
		result.StudioSourceChanged = true
		observed, err := app.Core().Diagnose(ctx, targetID)
		if err != nil {
			return fmt.Errorf("diagnose target after Studio source change: %w", err)
		}
		got, err := healthyFingerprint(observed)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, result.AfterPreviousRestore) {
			return errors.New("changing the VPSmith Studio image mutated the target Core")
		}
		return nil
	}); err != nil {
		return err
	}
	afterCounts, afterDesired, err := stateExecutionAndDesired(ctx, nextPaths, targetID)
	if err != nil {
		return err
	}
	if beforeCounts != afterCounts || !reflect.DeepEqual(beforeDesired, afterDesired) {
		return errors.New("changing the VPSmith Studio image changed target execution history or desired Core")
	}
	result.StudioNoTargetMutation = true

	return writeJSON(*output, result)
}

type executionCounts struct {
	Bundles int
	Records int
}

func stateExecutionAndDesired(ctx context.Context, paths application.Paths, targetID managementstate.TargetID) (executionCounts, managementstate.CoreDesiredState, error) {
	app, err := application.Open(ctx, paths)
	if err != nil {
		return executionCounts{}, managementstate.CoreDesiredState{}, err
	}
	defer app.Close()
	snapshot, err := app.State().Snapshot(ctx)
	if err != nil {
		return executionCounts{}, managementstate.CoreDesiredState{}, err
	}
	for _, target := range snapshot.Targets {
		if target.ID == targetID {
			return executionCounts{Bundles: len(snapshot.ExecutionBundles), Records: len(snapshot.ExecutionRecords)}, target.Desired.Core, nil
		}
	}
	return executionCounts{}, managementstate.CoreDesiredState{}, errors.New("target disappeared from Management State")
}

func assertPrimaryBlock(args []string) error {
	flags := flag.NewFlagSet("assert-primary-block", flag.ContinueOnError)
	common := addAppPathFlags(flags)
	targetIDRaw := flags.String("target-id", "", "target id")
	output := flags.String("output", "", "assertion result JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *targetIDRaw == "" || *output == "" {
		return errors.New("target-id and output are required")
	}
	paths, err := common.paths("")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	targetID := managementstate.TargetID(*targetIDRaw)

	app, err := application.Open(ctx, paths)
	if err != nil {
		return err
	}
	defer app.Close()
	observed, err := app.Core().Diagnose(ctx, targetID)
	if err != nil {
		return fmt.Errorf("diagnose drifted target: %w", err)
	}
	if observed.Host.PrimaryHardening.SSHValues["maxsessions"] != "4" {
		return fmt.Errorf("out-of-band Cloud-init-owned SSH tamper was not observed: maxsessions=%q", observed.Host.PrimaryHardening.SSHValues["maxsessions"])
	}
	before, err := app.State().Snapshot(ctx)
	if err != nil {
		return err
	}
	beforeFingerprint, err := healthyFingerprintIgnoringPrimary(observed)
	if err != nil {
		return err
	}
	_, prepareErr := app.Core().PrepareSwapChange(ctx, corelifecycle.PrepareRequest{
		TargetID: targetID,
		Swap:     managementstate.SwapDesiredState{Mode: "none"},
	})
	if prepareErr == nil {
		return errors.New("Core mutation was not blocked by Primary Host Hardening drift")
	}
	after, err := app.State().Snapshot(ctx)
	if err != nil {
		return err
	}
	if len(before.ExecutionBundles) != len(after.ExecutionBundles) || len(before.ExecutionRecords) != len(after.ExecutionRecords) {
		return errors.New("blocked Core mutation still created execution history")
	}
	afterObserved, err := app.Core().Diagnose(ctx, targetID)
	if err != nil {
		return err
	}
	afterFingerprint, err := healthyFingerprintIgnoringPrimary(afterObserved)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(beforeFingerprint, afterFingerprint) || afterObserved.Host.PrimaryHardening.SSHValues["maxsessions"] != "4" {
		return errors.New("blocked Core mutation repaired or otherwise changed the drifted target")
	}
	return writeJSON(*output, map[string]any{
		"primary_drift_observed":      true,
		"core_mutation_blocked":       true,
		"execution_history_unchanged": true,
		"core_identity_unchanged":     true,
		"primary_drift_not_repaired":  true,
	})
}

func createCoreSecrets(ctx context.Context, state *managementstate.Store) (managementstate.CoreSecretReferences, error) {
	if state == nil {
		return managementstate.CoreSecretReferences{}, errors.New("management state is required")
	}
	var refs managementstate.CoreSecretReferences
	err := state.Change(ctx, func(change *managementstate.Change) error {
		create := func(name string, value []byte) (managementstate.SecretID, error) {
			id, err := change.CreateSecret(name, managementstate.SecretGenerated)
			if err != nil {
				return "", err
			}
			if err := change.SetSecret(id, value); err != nil {
				return "", err
			}
			return id, nil
		}

		session, err := randomASCIISecret(64)
		if err != nil {
			return err
		}
		defer zero(session)
		storage, err := randomASCIISecret(64)
		if err != nil {
			return err
		}
		defer zero(storage)
		reset, err := randomASCIISecret(64)
		if err != nil {
			return err
		}
		defer zero(reset)
		users, err := generatedUsersDatabase()
		if err != nil {
			return err
		}
		defer zero(users)

		if refs.AutheliaSession, err = create("step9-live-authelia-session", session); err != nil {
			return err
		}
		if refs.AutheliaStorage, err = create("step9-live-authelia-storage", storage); err != nil {
			return err
		}
		if refs.AutheliaResetPassword, err = create("step9-live-authelia-reset", reset); err != nil {
			return err
		}
		if refs.AutheliaUsersDatabase, err = create("step9-live-authelia-users", users); err != nil {
			return err
		}
		return nil
	})
	return refs, err
}

func generatedUsersDatabase() ([]byte, error) {
	password, err := randomASCIISecret(24)
	if err != nil {
		return nil, err
	}
	defer zero(password)
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("users:\n  %s:\n    disabled: false\n    displayname: 'CI Operator'\n    password: '%s'\n    email: 'ci-operator@example.invalid'\n    groups:\n      - '%s'\n", ciOperatorUser, hash, ciOperatorGroup)), nil
}

func randomASCIISecret(bytesCount int) ([]byte, error) {
	raw := make([]byte, bytesCount)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	defer zero(raw)
	encoded := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(encoded, raw)
	return encoded, nil
}

func healthyFingerprint(observed managementstate.ObservedState) (coreFingerprint, error) {
	if err := requireHealthyCore(observed); err != nil {
		return coreFingerprint{}, err
	}
	return fingerprint(observed), nil
}

func healthyFingerprintIgnoringPrimary(observed managementstate.ObservedState) (coreFingerprint, error) {
	if !observed.Core.Present || !observed.Core.Running || !observed.Core.HTTPS || !observed.Core.Caddy.Running || !observed.Core.Authelia.Running {
		return coreFingerprint{}, errors.New("Core runtime is not healthy while checking Primary drift blocking")
	}
	return fingerprint(observed), nil
}

func requireHealthyCore(observed managementstate.ObservedState) error {
	if !observed.Host.Reachable || !observed.Host.SSH || !observed.CloudInit.Present || observed.CloudInit.Status != "ok" {
		return errors.New("target is not reachable with successful Cloud-init")
	}
	if !observed.Core.Present || !observed.Core.Running || !observed.Core.HTTPS {
		return errors.New("Core is not installed, running, and HTTPS-valid")
	}
	if !observed.Core.Caddy.Present || !observed.Core.Caddy.Running || !observed.Core.Caddy.ConfigChecked || !observed.Core.Caddy.ConfigValid {
		return errors.New("Caddy is not running with a validated configuration")
	}
	if !observed.Core.Authelia.Present || !observed.Core.Authelia.Running {
		return errors.New("Authelia is not running")
	}
	fp := fingerprint(observed)
	if fp.SourceID == "" || fp.Version == "" || fp.PackageSHA256 == "" || fp.CaddyDigest == "" || fp.AutheliaDigest == "" {
		return errors.New("Core exact runtime identity is incomplete")
	}
	return nil
}

func fingerprint(observed managementstate.ObservedState) coreFingerprint {
	return coreFingerprint{
		SourceID:       observed.Core.SourceID,
		Version:        observed.Core.Version,
		PackageSHA256:  observed.Core.PackageSHA256,
		CaddyDigest:    imageDigest(observed.Core.Containers, "caddy"),
		AutheliaDigest: imageDigest(observed.Core.Containers, "authelia"),
		HTTPS:          observed.Core.HTTPS,
	}
}

func imageDigest(containers []managementstate.ContainerObservedState, name string) string {
	for _, container := range containers {
		if container.Name == name && container.Present && container.Running {
			return container.ImageDigest
		}
	}
	return ""
}

func prepareNextStudioEmbedded(currentRoot, nextRoot string) error {
	currentRoot, err := filepath.Abs(currentRoot)
	if err != nil {
		return err
	}
	nextRoot, err = filepath.Abs(nextRoot)
	if err != nil {
		return err
	}
	if currentRoot == nextRoot {
		return errors.New("next Studio embedded root must be separate from the current release")
	}
	if err := os.RemoveAll(nextRoot); err != nil {
		return err
	}
	if err := copyTree(currentRoot, nextRoot); err != nil {
		return err
	}
	marker := filepath.Join(nextRoot, "core", "step9-live-next-studio-marker.txt")
	if err := os.WriteFile(marker, []byte("new embedded Core basis supplied by newer VPSmith Studio image\n"), 0o644); err != nil {
		return err
	}
	coreSHA, err := sourcehash.TreeSHA256(filepath.Join(nextRoot, "core"))
	if err != nil {
		return err
	}
	manifestPath := filepath.Join(nextRoot, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return err
	}
	studio, ok := manifest["studio"].(map[string]any)
	if !ok {
		return errors.New("embedded manifest has no Studio object")
	}
	studio["version"] = "0.1.0-dev.2"
	embedded, ok := manifest["embedded"].(map[string]any)
	if !ok {
		return errors.New("embedded manifest has no embedded object")
	}
	core, ok := embedded["core"].(map[string]any)
	if !ok {
		return errors.New("embedded manifest has no Core object")
	}
	core["sha256"] = coreSHA
	updated, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	updated = append(updated, '\n')
	return os.WriteFile(manifestPath, updated, 0o644)
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("embedded fixture contains unsupported symlink %s", rel)
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("embedded fixture contains unsupported file type %s", rel)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		return errors.Join(copyErr, closeErr)
	})
}

func withApp(ctx context.Context, paths application.Paths, fn func(*application.Application) error) error {
	app, err := application.Open(ctx, paths)
	if err != nil {
		return err
	}
	defer app.Close()
	return fn(app)
}

func writeJSON(path string, value any) error {
	if path == "" {
		return errors.New("output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(value)
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
