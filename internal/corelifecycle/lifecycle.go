package corelifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/privat655/VPSmith/internal/backuprestore"
	"github.com/privat655/VPSmith/internal/deployment"
	"github.com/privat655/VPSmith/internal/execution"
	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/sourcelibrary"
)

const maxAutoSwapBytes int64 = 4 << 30

type Sources interface {
	FreezeCoreCandidate(context.Context, sourcelibrary.CoreCandidateRef) (sourcelibrary.FrozenSnapshot, error)
}

type Inspector interface {
	Inspect(context.Context, managementstate.TargetID) (managementstate.ObservedState, error)
}

type Compiler interface {
	PrepareCore(context.Context, deployment.CoreRequest) (deployment.PreparedCoreOperation, error)
}

type CoreBackupStorage interface {
	backuprestore.TargetStorage
	QuiesceCoreRuntime(context.Context, string) error
	ResumeAndValidateCoreRuntime(context.Context, string) error
}

type Lifecycle struct {
	state     *managementstate.Store
	sources   Sources
	inspector Inspector
	compiler  Compiler
	executor  *execution.Executor
	backups   *backuprestore.Manager
	storage   CoreBackupStorage
	dns       dnsResolver
}

type CoreConfiguration struct {
	Domain    string
	ACMEEmail string
	Authelia  managementstate.CoreAutheliaDesiredState
	Secrets   managementstate.CoreSecretReferences
}

type PrepareRequest struct {
	TargetID         managementstate.TargetID
	Candidate        sourcelibrary.CoreCandidateRef
	Configuration    CoreConfiguration
	Swap             managementstate.SwapDesiredState
	BackupID         managementstate.BackupArtifactID
	BackupPassphrase []byte
}

type BackupRequest struct {
	TargetID   managementstate.TargetID
	Passphrase []byte
}

type Prepared struct {
	Operation     deployment.PreparedCoreOperation
	TargetID      managementstate.TargetID
	DesiredCore   managementstate.CoreDesiredState
	PrimaryBefore managementstate.PrimaryHardeningObservedState
	SwapBefore    []managementstate.SwapDeviceObservedState
}

type ReconcileRequest struct {
	TargetID     managementstate.TargetID
	RunID        string
	BundleID     string
	BundleSHA256 string
}

type verifiedBackup struct {
	Manifest   backuprestore.Manifest
	Desired    managementstate.CoreDesiredState
	ImageLocks coreBackupImageLocks
}

func New(state *managementstate.Store, sources Sources, inspector Inspector, compiler Compiler, executor *execution.Executor, backups *backuprestore.Manager, storage CoreBackupStorage) (*Lifecycle, error) {
	if state == nil || sources == nil || inspector == nil || compiler == nil || executor == nil || backups == nil || storage == nil {
		return nil, errors.New("complete Core lifecycle dependencies are required")
	}
	return &Lifecycle{state: state, sources: sources, inspector: inspector, compiler: compiler, executor: executor, backups: backups, storage: storage, dns: net.DefaultResolver}, nil
}

func (l *Lifecycle) PrepareInstall(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.prepare(ctx, deployment.Install, req)
}
func (l *Lifecycle) PrepareUpdate(context.Context, PrepareRequest) (Prepared, error) {
	return Prepared{}, errors.New("Core update must use PrepareUpdateWithBackup so the immediate verified backup cannot be bypassed")
}
func (l *Lifecycle) PrepareReconfigure(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.prepare(ctx, deployment.Reconfigure, req)
}
func (l *Lifecycle) PrepareSwapChange(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.PrepareReconfigure(ctx, req)
}
func (l *Lifecycle) PrepareRestore(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.prepare(ctx, deployment.Restore, req)
}
func (l *Lifecycle) PrepareValidation(ctx context.Context, req PrepareRequest) (Prepared, error) {
	return l.prepare(ctx, deployment.Validate, req)
}

func (l *Lifecycle) Execute(ctx context.Context, prepared Prepared) (execution.Run, error) {
	if prepared.TargetID == "" || prepared.Operation.Bundle.ID == "" {
		return execution.Run{}, errors.New("prepared Core operation is required")
	}
	run, err := l.executor.Execute(ctx, string(prepared.TargetID), prepared.Operation.Bundle)
	if err != nil {
		return run, err
	}
	observed, err := l.inspector.Inspect(ctx, prepared.TargetID)
	if err != nil {
		return run, fmt.Errorf("inspect Core after execution: %w", err)
	}
	if err := validatePostState(prepared, observed); err != nil {
		return run, fmt.Errorf("Core post-validation failed: %w", err)
	}
	snapshot, err := l.state.Snapshot(ctx)
	if err != nil {
		return run, fmt.Errorf("read Management State after Core validation: %w", err)
	}
	target, err := targetFromSnapshot(snapshot, prepared.TargetID)
	if err != nil {
		return run, err
	}
	desired := target.Desired
	if err := l.state.Change(ctx, func(change *managementstate.Change) error {
		if prepared.Operation.Operation != deployment.Validate {
			desired.Core = prepared.DesiredCore
			if err := change.SetDesiredState(prepared.TargetID, desired); err != nil {
				return err
			}
		}
		return change.RecordObservedState(prepared.TargetID, observed)
	}); err != nil {
		return run, fmt.Errorf("commit Core lifecycle state: %w", err)
	}
	return run, nil
}

func (l *Lifecycle) Reconcile(ctx context.Context, req ReconcileRequest) (execution.Run, error) {
	return l.executor.Reconcile(ctx, string(req.TargetID), req.RunID, req.BundleID, req.BundleSHA256)
}

func (l *Lifecycle) Diagnose(ctx context.Context, targetID managementstate.TargetID) (managementstate.ObservedState, error) {
	if targetID == "" {
		return managementstate.ObservedState{}, errors.New("target id is required")
	}
	return l.inspector.Inspect(ctx, targetID)
}

func (l *Lifecycle) Backup(ctx context.Context, req BackupRequest) (backuprestore.Artifact, error) {
	if req.TargetID == "" {
		return backuprestore.Artifact{}, errors.New("target id is required")
	}
	observed, err := l.inspector.Inspect(ctx, req.TargetID)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	if !observed.Core.Present {
		return backuprestore.Artifact{}, errors.New("Core backup requires an installed Core")
	}
	snapshot, err := l.state.Snapshot(ctx)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	target, err := targetFromSnapshot(snapshot, req.TargetID)
	if err != nil {
		return backuprestore.Artifact{}, err
	}
	if err := requireCoreBackupReady(snapshot, target, observed); err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("Core backup preflight failed: %w", err)
	}
	if err := requireCoreBackupDiskSpace(observed); err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("Core backup preflight failed: %w", err)
	}

	targetID := string(req.TargetID)
	if err := l.storage.QuiesceCoreRuntime(ctx, targetID); err != nil {
		return backuprestore.Artifact{}, err
	}
	recoveryCtx := context.WithoutCancel(ctx)
	copy, copyErr := l.backups.CopyOfflineStorage(ctx, l.storage, targetID, coreBackupStoragePaths())
	resumeErr := l.storage.ResumeAndValidateCoreRuntime(recoveryCtx, targetID)
	if copyErr != nil {
		var cleanupErr error
		if copy.Token != "" {
			cleanupErr = l.backups.CleanupTargetStorageCopy(recoveryCtx, l.storage, targetID, copy.Token)
		}
		return backuprestore.Artifact{}, errors.Join(copyErr, resumeErr, cleanupErr)
	}
	defer copy.Close()
	if resumeErr != nil {
		cleanupErr := l.backups.CleanupTargetStorageCopy(recoveryCtx, l.storage, targetID, copy.Token)
		return backuprestore.Artifact{}, errors.Join(resumeErr, cleanupErr)
	}

	producer := corePayloadProducer{copy: copy, observed: observed, desired: target.Desired.Core, bundleRef: latestSuccessfulCoreBundle(snapshot, observed, req.TargetID)}
	artifact, err := l.backups.Create(ctx, backuprestore.CreateRequest{Type: managementstate.BackupCore, TargetID: req.TargetID, Passphrase: req.Passphrase, Producer: producer})
	if err != nil {
		cleanupErr := l.backups.CleanupTargetStorageCopy(recoveryCtx, l.storage, targetID, copy.Token)
		return backuprestore.Artifact{}, errors.Join(err, cleanupErr)
	}
	if err := l.backups.FinalizeStorageCopy(recoveryCtx, l.storage, &copy); err != nil {
		return backuprestore.Artifact{}, fmt.Errorf("Core backup persisted but target temporary copy cleanup failed: %w", err)
	}
	return artifact, nil
}

func (l *Lifecycle) prepare(ctx context.Context, kind deployment.OperationKind, req PrepareRequest) (Prepared, error) {
	if req.TargetID == "" {
		return Prepared{}, errors.New("target id is required")
	}
	observed, err := l.inspector.Inspect(ctx, req.TargetID)
	if err != nil {
		return Prepared{}, err
	}
	if err := requirePrimary(observed); err != nil {
		return Prepared{}, err
	}
	if err := requireSupportedHost(observed); err != nil {
		return Prepared{}, err
	}
	snapshot, err := l.state.Snapshot(ctx)
	if err != nil {
		return Prepared{}, err
	}
	target, err := targetFromSnapshot(snapshot, req.TargetID)
	if err != nil {
		return Prepared{}, err
	}
	if kind == deployment.Install && observed.Core.Present {
		return Prepared{}, errors.New("Core is already installed")
	}
	if kind != deployment.Install && !observed.Core.Present {
		return Prepared{}, errors.New("Core is not installed")
	}
	if err := requireSteadyCoreBeforeMutation(snapshot, target, observed, kind); err != nil {
		return Prepared{}, err
	}

	var backup *verifiedBackup
	if kind == deployment.Update || kind == deployment.Restore {
		verified, err := l.verifiedCoreBackup(ctx, req, observed, kind)
		if err != nil {
			return Prepared{}, err
		}
		backup = &verified
	}

	candidateRef, err := candidateForOperation(kind, req, observed, backup)
	if err != nil {
		return Prepared{}, err
	}
	source, err := l.sources.FreezeCoreCandidate(ctx, candidateRef)
	if err != nil {
		return Prepared{}, err
	}
	if backup != nil && kind == deployment.Restore {
		if err := backupMatchesSource(backup.Manifest, source); err != nil {
			return Prepared{}, err
		}
	}

	desiredCore, err := desiredCoreForOperation(kind, req, target.Desired.Core, backup)
	if err != nil {
		return Prepared{}, err
	}
	desiredCore.Authelia = normalizeDesiredAuthelia(desiredCore.Authelia)
	if err := requireCoreSecretReferences(snapshot, desiredCore.Secrets); err != nil {
		return Prepared{}, err
	}
	effectiveSwapBytes, err := resolveSwapV1(observed, desiredCore.Swap)
	if err != nil {
		return Prepared{}, err
	}
	installedModules, err := freezeLifecycleModuleSources(ctx, snapshot, target, observed, l.sources)
	if err != nil {
		return Prepared{}, err
	}

	coreReq := deployment.CoreRequest{
		Operation:          kind,
		TargetID:           string(req.TargetID),
		AdminUser:          target.SSHUser,
		Domain:             desiredCore.Domain,
		ACMEEmail:          desiredCore.ACMEEmail,
		Authelia:           deploymentAuthelia(desiredCore.Authelia),
		Secrets:            deploymentCoreSecrets(desiredCore.Secrets),
		Source:             deployment.FrozenCoreSource{SourceID: string(source.ID), Version: source.Version, GitCommit: source.Commit, PackageSHA256: source.SHA256, PackageFS: source.FS},
		InstalledModules:   installedModules,
		SwapMode:           desiredCore.Swap.Mode,
		SwapSizeGiB:        desiredCore.Swap.SizeGiB,
		EffectiveSwapBytes: effectiveSwapBytes,
		ObservedArtifacts:  observedArtifactHashes(observed.Core.ManagedArtifacts),
		BackupRequired:     kind == deployment.Update,
	}
	if kind == deployment.Update {
		coreReq.BackupRef = string(req.BackupID)
	}
	if kind == deployment.Reconfigure || kind == deployment.Validate {
		locks, err := frozenCoreImages(desiredCore.Images)
		if err != nil {
			return Prepared{}, err
		}
		coreReq.LockedImages = locks
	}
	if observed.Core.Present {
		if observed.Core.SourceID == "" || observed.Core.PackageSHA256 == "" {
			return Prepared{}, errors.New("installed Core identity is incomplete")
		}
		coreReq.ObservedCoreID = string(observed.Core.SourceID)
		coreReq.ObservedCoreSHA256 = observed.Core.PackageSHA256
	}
	operation, err := prepareCoreOperation(ctx, l.compiler, kind, coreReq, backup)
	if err != nil {
		return Prepared{}, err
	}
	resolver := l.dns
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	for _, hostname := range coreDNSHostnames(desiredCore.Domain, operation.PublicRoutes) {
		if err := requireDNSARecord(ctx, resolver, hostname, target.Address); err != nil {
			return Prepared{}, err
		}
	}
	desiredCore.SourceID = source.ID
	desiredCore.Version = source.Version
	desiredCore.CoreContract = operation.CoreContract
	desiredCore.Authelia = desiredAuthelia(operation.Authelia)
	desiredCore.Images, err = desiredCoreImages(operation.Bundle.Manifest.Images)
	if err != nil {
		return Prepared{}, err
	}
	if kind == deployment.Restore && backup != nil && backup.Desired.CoreContract != "" && backup.Desired.CoreContract != operation.CoreContract {
		return Prepared{}, errors.New("restored Core source core_contract does not match backed-up desired state")
	}
	return Prepared{Operation: operation, TargetID: req.TargetID, DesiredCore: desiredCore, PrimaryBefore: observed.Host.PrimaryHardening, SwapBefore: append([]managementstate.SwapDeviceObservedState(nil), observed.Host.SwapDevices...)}, nil
}

func desiredCoreForOperation(kind deployment.OperationKind, req PrepareRequest, current managementstate.CoreDesiredState, backup *verifiedBackup) (managementstate.CoreDesiredState, error) {
	switch kind {
	case deployment.Install:
		desired := managementstate.CoreDesiredState{Domain: req.Configuration.Domain, ACMEEmail: req.Configuration.ACMEEmail, Authelia: normalizeDesiredAuthelia(req.Configuration.Authelia), Secrets: req.Configuration.Secrets, Swap: req.Swap}
		if desired.Swap.Mode == "" { desired.Swap.Mode = "none" }
		return desired, nil
	case deployment.Update, deployment.Validate:
		if current.SourceID == "" { return managementstate.CoreDesiredState{}, errors.New("installed Core has no canonical desired state") }
		if err := completeCoreDesiredRuntime(current); err != nil { return managementstate.CoreDesiredState{}, err }
		return current, nil
	case deployment.Reconfigure:
		if current.SourceID == "" { return managementstate.CoreDesiredState{}, errors.New("installed Core has no canonical desired state") }
		if err := completeCoreDesiredRuntime(current); err != nil { return managementstate.CoreDesiredState{}, err }
		if req.Configuration.Domain != "" { current.Domain = req.Configuration.Domain }
		if req.Configuration.ACMEEmail != "" { current.ACMEEmail = req.Configuration.ACMEEmail }
		if coreSecretRefsAny(req.Configuration.Secrets) { current.Secrets = req.Configuration.Secrets }
		if req.Configuration.Authelia.Enrollment != "" || len(req.Configuration.Authelia.Users) > 0 || len(req.Configuration.Authelia.Groups) > 0 { current.Authelia = normalizeDesiredAuthelia(req.Configuration.Authelia) }
		if req.Swap.Mode != "" { current.Swap = req.Swap }
		return current, nil
	case deployment.Restore:
		if backup == nil || backup.Desired.SourceID == "" { return managementstate.CoreDesiredState{}, errors.New("Core restore backup has no previous desired state") }
		return backup.Desired, nil
	default:
		return managementstate.CoreDesiredState{}, errors.New("unsupported Core operation")
	}
}

func (l *Lifecycle) verifiedCoreBackup(ctx context.Context, req PrepareRequest, observed managementstate.ObservedState, kind deployment.OperationKind) (verifiedBackup, error) {
	if req.BackupID == "" { return verifiedBackup{}, errors.New("Core update/restore requires a concrete verified Core backup") }
	inspection, err := l.backups.InspectArtifact(ctx, req.BackupID, managementstate.BackupCore, req.BackupPassphrase)
	if err != nil { return verifiedBackup{}, fmt.Errorf("verify Core backup: %w", err) }
	defer inspection.Close()
	manifest := inspection.Manifest
	if manifest.TargetID != req.TargetID || manifest.Identity == nil || manifest.Identity.SubjectKind != "core" { return verifiedBackup{}, errors.New("Core backup belongs to another target or subject") }
	if kind == deployment.Update { identity := manifest.Identity; if identity.SubjectID != string(observed.Core.SourceID) || identity.Version != observed.Core.Version || identity.PackageSHA256 != observed.Core.PackageSHA256 { return verifiedBackup{}, errors.New("Core update backup does not match the installed exact Core identity") } }
	desired, locks, err := coreStateFromBackup(inspection)
	if err != nil { return verifiedBackup{}, err }
	if desired.SourceID != managementstate.SourceSnapshotID(manifest.Identity.SubjectID) || desired.Version != manifest.Identity.Version || locks.SourceID != desired.SourceID || locks.Version != desired.Version || locks.PackageSHA256 != manifest.Identity.PackageSHA256 { return verifiedBackup{}, errors.New("Core backup desired state or image locks do not match manifest identity") }
	return verifiedBackup{Manifest: manifest, Desired: desired, ImageLocks: locks}, nil
}

func coreStateFromBackup(inspection *backuprestore.Inspection) (managementstate.CoreDesiredState, coreBackupImageLocks, error) {
	if inspection == nil || inspection.PayloadPath == "" { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, errors.New("validated Core backup payload is required") }
	root, err := os.MkdirTemp("", "vpsmith-core-backup-"); if err != nil { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, err }; defer os.RemoveAll(root)
	if err := backuprestore.ExtractTarZst(inspection.PayloadPath, root, backuprestore.ArchiveOptions{}); err != nil { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, fmt.Errorf("extract Core backup desired state: %w", err) }
	data, err := os.ReadFile(filepath.Join(root, "management", "core-desired.json")); if err != nil { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, fmt.Errorf("read Core backup desired state: %w", err) }
	var desired managementstate.CoreDesiredState; if err := json.Unmarshal(data, &desired); err != nil { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, fmt.Errorf("decode Core backup desired state: %w", err) }
	lockData, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(coreBackupImageLocksRef))); if err != nil { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, fmt.Errorf("read Core backup image locks: %w", err) }
	var locks coreBackupImageLocks; if err := json.Unmarshal(lockData, &locks); err != nil { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, fmt.Errorf("decode Core backup image locks: %w", err) }
	if len(locks.Images) != 2 { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, errors.New("Core backup image lock set is incomplete") }
	if desired.Images == nil { desired.Images = map[string]managementstate.CoreImageIdentity{} }
	for _, name := range []string{"caddy", "authelia"} { image, ok := locks.Images[name]; if !ok || strings.TrimSpace(image.Ref) == "" || !validCoreImageDigest(image.Digest) { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, fmt.Errorf("Core backup image lock for %s is invalid", name) }; canonical, exists := desired.Images[name]; if exists && (canonical.Ref != image.Ref || canonical.Digest != image.Digest) { return managementstate.CoreDesiredState{}, coreBackupImageLocks{}, fmt.Errorf("Core backup canonical %s image identity disagrees with image locks", name) }; desired.Images[name] = managementstate.CoreImageIdentity{Ref: image.Ref, Digest: image.Digest} }
	desired.Authelia = normalizeDesiredAuthelia(desired.Authelia)
	return desired, locks, nil
}

func desiredCoreFromBackup(inspection *backuprestore.Inspection) (managementstate.CoreDesiredState, error) { desired, _, err := coreStateFromBackup(inspection); return desired, err }

func candidateForOperation(kind deployment.OperationKind, req PrepareRequest, observed managementstate.ObservedState, backup *verifiedBackup) (sourcelibrary.CoreCandidateRef, error) {
	switch kind {
	case deployment.Install, deployment.Update:
		if req.Candidate.WorkspaceID != "" { return sourcelibrary.CoreCandidateRef{}, errors.New("mutable Core workspace must be explicitly adopted before target planning") }
		return req.Candidate, nil
	case deployment.Reconfigure, deployment.Validate:
		if req.Candidate.SnapshotID != "" || req.Candidate.WorkspaceID != "" { return sourcelibrary.CoreCandidateRef{}, errors.New("Core reconfigure/validation must use the installed Core source") }
		return sourcelibrary.CoreCandidateRef{SnapshotID: observed.Core.SourceID}, nil
	case deployment.Restore:
		if backup == nil || backup.Manifest.Identity == nil || backup.Manifest.Identity.SubjectID == "" { return sourcelibrary.CoreCandidateRef{}, errors.New("Core restore backup has no previous source identity") }
		if req.Candidate.SnapshotID != "" || req.Candidate.WorkspaceID != "" { return sourcelibrary.CoreCandidateRef{}, errors.New("Core restore source is selected by the verified backup") }
		return sourcelibrary.CoreCandidateRef{SnapshotID: managementstate.SourceSnapshotID(backup.Manifest.Identity.SubjectID)}, nil
	default:
		return sourcelibrary.CoreCandidateRef{}, errors.New("unsupported Core operation")
	}
}

func backupMatchesSource(manifest backuprestore.Manifest, source sourcelibrary.FrozenSnapshot) error { identity := manifest.Identity; if identity == nil || identity.SubjectID != string(source.ID) || identity.Version != source.Version || identity.PackageSHA256 != source.SHA256 { return errors.New("Core restore source does not match the verified backup identity") }; return nil }
func requireCoreSecretReferences(snapshot managementstate.Snapshot, refs managementstate.CoreSecretReferences) error { available := make(map[managementstate.SecretID]bool, len(snapshot.Secrets)); for _, secret := range snapshot.Secrets { available[secret.ID] = secret.IsSet }; for _, id := range refs.IDs() { if id == "" || !available[id] { return errors.New("Core requires all referenced Authelia secrets to exist and be set") } }; return nil }
func deploymentCoreSecrets(refs managementstate.CoreSecretReferences) deployment.CoreSecretIDs { return deployment.CoreSecretIDs{AutheliaSession: string(refs.AutheliaSession), AutheliaStorage: string(refs.AutheliaStorage), AutheliaResetPassword: string(refs.AutheliaResetPassword), AutheliaUsersDatabase: string(refs.AutheliaUsersDatabase)} }
func observedArtifactHashes(artifacts []managementstate.ManagedArtifactObservedState) map[string]string { out := make(map[string]string, len(artifacts)); for _, artifact := range artifacts { if artifact.Present && artifact.Path != "" && artifact.SHA256 != "" { out[artifact.Path] = artifact.SHA256 } }; return out }
func requirePrimary(observed managementstate.ObservedState) error { facts := observed.Host.PrimaryHardening; if !observed.Host.Reachable || !observed.Host.SSH || !observed.CloudInit.Present || observed.CloudInit.Status != "ok" { return errors.New("successful Cloud-init and SSH are required") }; if !facts.RootPasswordLocked || !facts.SSHConfigValid || !facts.UFWActive || facts.UFWUnexpectedPublicAllow || !facts.Fail2banSSHActive || !facts.Fail2banRecidiveActive { return errors.New("Primary Host Hardening is not effective") }; return nil }
func requireSupportedHost(observed managementstate.ObservedState) error { if strings.ToLower(observed.Host.OSID) != "ubuntu" || observed.Host.OSVersion != "24.04" { return fmt.Errorf("unsupported target OS %s %s; VPSmith Step 9 requires Ubuntu 24.04", observed.Host.OSID, observed.Host.OSVersion) }; if observed.Host.Kernel == "" || observed.Host.Memory.TotalBytes <= 0 || observed.Host.RootFilesystem.AvailableBytes <= 0 { return errors.New("target host facts are incomplete") }; return nil }

func validatePostState(prepared Prepared, observed managementstate.ObservedState) error {
	if err := requirePrimary(observed); err != nil { return err }
	if !reflect.DeepEqual(prepared.PrimaryBefore, observed.Host.PrimaryHardening) { return errors.New("Core operation changed Cloud-init-owned Primary Host Hardening") }
	if err := requireCoreOwnedPostState(prepared, observed); err != nil { return err }
	if !observed.Core.Present || observed.Core.SourceID != prepared.DesiredCore.SourceID || observed.Core.Version != prepared.DesiredCore.Version || observed.Core.PackageSHA256 != prepared.Operation.Bundle.Manifest.PackageSHA256 { return errors.New("effective Core identity does not match the approved bundle") }
	if !observed.Core.Podman.Present || !observed.Core.Podman.Rootless || observed.Core.Podman.CgroupVersion != "v2" || observed.Core.Podman.RootlessNetworkCmd != "pasta" { return errors.New("rootless Podman foundation is not effective") }
	if !observed.Core.Running { return errors.New("expected Core runtime is not running") }
	if !observed.Core.Caddy.Present || !observed.Core.Caddy.Running || !observed.Core.Caddy.ConfigChecked || !observed.Core.Caddy.ConfigValid { return errors.New("Caddy is not running with a valid checked configuration") }
	if !observed.Core.Authelia.Present || !observed.Core.Authelia.Running { return errors.New("Authelia is not running") }
	if !observed.Core.HTTPS { return errors.New("Core HTTPS endpoint is not valid") }
	if err := requireExactRunningCoreImages(prepared.DesiredCore.Images, observed.Core.Containers); err != nil { return err }
	if err := requirePublicRoutes(prepared.Operation.PublicRoutes, observed.Core.PublicRoutes); err != nil { return err }
	return nil
}
func requireExactRunningCoreImages(desired map[string]managementstate.CoreImageIdentity, containers []managementstate.ContainerObservedState) error { if len(desired) != 2 { return errors.New("canonical Core desired image locks are incomplete") }; byName := make(map[string]managementstate.ContainerObservedState, len(containers)); for _, container := range containers { byName[container.Name] = container }; for _, name := range []string{"caddy", "authelia"} { want, ok := desired[name]; got, present := byName[name]; if !ok || !present || !got.Present || !got.Running || got.ImageDigest != want.Digest { return fmt.Errorf("running %s image does not match approved digest", name) }; if got.ImageRef != "" && got.ImageRef != want.Ref && got.ImageRef != want.Ref+"@"+want.Digest { return fmt.Errorf("running %s image reference does not match approved identity", name) } }; return nil }
func requirePublicRoutes(expected []deployment.CorePublicRoute, observed []managementstate.PublicRouteObservedState) error { if len(expected) != len(observed) { return errors.New("observed public Core routes do not match the approved platform routes") }; byKey := make(map[string]managementstate.PublicRouteObservedState, len(observed)); for _, route := range observed { key := route.Hostname+"\x00"+route.PathPrefix; if _, duplicate := byKey[key]; duplicate { return fmt.Errorf("public route %s%s was observed more than once", route.Hostname, route.PathPrefix) }; byKey[key] = route }; for _, want := range expected { got, ok := byKey[want.Hostname+"\x00"+want.PathPrefix]; if !ok || got.AuthMode != want.AuthMode || !got.HTTPS { return fmt.Errorf("public route %s%s is not healthy over HTTPS", want.Hostname, want.PathPrefix) }; if want.AuthMode == "protected" && !got.AuthEnforced { return fmt.Errorf("public route %s%s does not enforce Authelia", want.Hostname, want.PathPrefix) } }; return nil }
func coreDNSHostnames(domain string, routes []deployment.CorePublicRoute) []string { seen := map[string]struct{}{"auth."+domain:{}}; out:=[]string{"auth."+domain}; for _,route:=range routes{if _,ok:=seen[route.Hostname];ok{continue};seen[route.Hostname]=struct{}{};out=append(out,route.Hostname)};return out }
func targetFromSnapshot(snapshot managementstate.Snapshot, id managementstate.TargetID) (managementstate.Target, error) { for _,target:=range snapshot.Targets{if target.ID==id{return target,nil}};return managementstate.Target{},fmt.Errorf("target %s does not exist in Management State",id) }

type corePayloadProducer struct { copy backuprestore.StorageCopy; observed managementstate.ObservedState; desired managementstate.CoreDesiredState; bundleRef string }
func (p corePayloadProducer) Produce(ctx context.Context, root string) (backuprestore.PayloadDescriptor, error) { if err:=ctx.Err();err!=nil{return backuprestore.PayloadDescriptor{},err}; if err:=backuprestore.ExtractTarZst(p.copy.ArchivePath,root,backuprestore.ArchiveOptions{});err!=nil{return backuprestore.PayloadDescriptor{},err}; locks,err:=captureCoreImageLocks(root,p.observed);if err!=nil{return backuprestore.PayloadDescriptor{},err};if err:=writeCoreImageLocks(root,locks);err!=nil{return backuprestore.PayloadDescriptor{},err};managementDir:=filepath.Join(root,"management");if err:=os.MkdirAll(managementDir,0o700);err!=nil{return backuprestore.PayloadDescriptor{},err};desiredBytes,err:=json.MarshalIndent(p.desired,"","  ");if err!=nil{return backuprestore.PayloadDescriptor{},err};desiredBytes=append(desiredBytes,'\n');if err:=os.WriteFile(filepath.Join(managementDir,"core-desired.json"),desiredBytes,0o600);err!=nil{return backuprestore.PayloadDescriptor{},err};identity:=&backuprestore.ArtifactIdentity{SubjectKind:"core",SubjectID:string(p.observed.Core.SourceID),Version:p.observed.Core.Version,PackageSHA256:p.observed.Core.PackageSHA256,StoragePaths:append([]string(nil),p.copy.DeclaredPath...),PreviousDesiredStateRef:"management/core-desired.json",ExecutionBundleRef:p.bundleRef};descriptor:=backuprestore.PayloadDescriptor{Identity:identity,SourceRefs:[]string{string(p.observed.Core.SourceID)}};if p.bundleRef!=""{descriptor.BundleRefs=[]string{p.bundleRef}};return descriptor,nil }
func latestSuccessfulCoreBundle(snapshot managementstate.Snapshot, observed managementstate.ObservedState, targetID managementstate.TargetID) string { proved:=make(map[string]struct{},len(observed.Core.ExecutionProofs));for _,proof:=range observed.Core.ExecutionProofs{if proof.BundleID!=""&&proof.Outcome=="success"{proved[proof.BundleID]=struct{}{}}};latestFinished:="";latestBundle:="";for _,record:=range snapshot.ExecutionRecords{if record.TargetID!=targetID||record.Outcome!="success"||record.BundleID==""{continue};if _,ok:=proved[string(record.BundleID)];!ok{continue};when:=record.FinishedAt;if when==""{when=record.StartedAt};if when>latestFinished{latestFinished=when;latestBundle=string(record.BundleID)}};return latestBundle }
