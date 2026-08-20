package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/mail"
	"regexp"
	"strings"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

const coreDesiredTarget = "/var/lib/vpsmith/core/desired.json"

var coreDomainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var coreAdminUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// FrozenCoreSource is the exact immutable Core package selected by the Source Library.
type FrozenCoreSource struct {
	SourceID      string
	Version       string
	GitCommit     string
	PackageSHA256 string
	PackageFS     fs.FS
}

// CoreSecretIDs are stable Management State references. Secret material never
// crosses the Deployment Compiler seam.
type CoreSecretIDs struct {
	AutheliaSession       string
	AutheliaStorage       string
	AutheliaResetPassword string
	AutheliaUsersDatabase string
}

func (s CoreSecretIDs) complete() bool {
	return s.AutheliaSession != "" && s.AutheliaStorage != "" && s.AutheliaResetPassword != "" && s.AutheliaUsersDatabase != ""
}

// CoreRequest contains only frozen facts. Detection belongs to CoreLifecycle
// and TargetInspector; generation belongs here.
type CoreRequest struct {
	Operation          OperationKind
	TargetID           string
	AdminUser          string
	Domain             string
	ACMEEmail          string
	Secrets            CoreSecretIDs
	Source             FrozenCoreSource
	ObservedCoreID     string
	ObservedCoreSHA256 string
	ObservedArtifacts  map[string]string
	SwapMode           string
	SwapSizeGiB        int
	EffectiveSwapBytes int64
	BackupRequired     bool
	BackupRef          string
}

// PreparedCoreOperation keeps the Core-specific contract result behind the
// Core compiler seam while embedding the generic immutable operation.
type PreparedCoreOperation struct {
	PreparedOperation
	CoreContract string
}

type generatedCoreImage struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

type generatedCoreSecrets struct {
	AutheliaSession       string `json:"authelia_session"`
	AutheliaStorage       string `json:"authelia_storage"`
	AutheliaResetPassword string `json:"authelia_reset_password"`
	AutheliaUsersDatabase string `json:"authelia_users_database"`
}

type generatedCoreDesired struct {
	SourceID           string                        `json:"source_id"`
	Version            string                        `json:"version"`
	PackageSHA256      string                        `json:"package_sha256"`
	CoreContract       string                        `json:"core_contract"`
	AdminUser          string                        `json:"admin_user"`
	Domain             string                        `json:"domain"`
	ACMEEmail          string                        `json:"acme_email"`
	Images             map[string]generatedCoreImage `json:"images"`
	Secrets            generatedCoreSecrets          `json:"secrets"`
	SwapMode           string                        `json:"swap_mode"`
	SwapSizeGiB        int                           `json:"swap_size_gib"`
	EffectiveSwapBytes int64                         `json:"effective_swap_bytes"`
}

// PrepareCore freezes one Core candidate into the same immutable execution
// bundle used by all structural VPSmith operations. The target runner stays
// generic; it never contains a second Core installer.
func (c *Compiler) PrepareCore(ctx context.Context, req CoreRequest) (PreparedCoreOperation, error) {
	if err := ctx.Err(); err != nil {
		return PreparedCoreOperation{}, err
	}
	if c == nil || c.bundles == nil || c.registry == nil {
		return PreparedCoreOperation{}, errors.New("deployment compiler is required")
	}
	if req.Operation != Install && req.Operation != Update && req.Operation != Reconfigure && req.Operation != Restore && req.Operation != Validate {
		return PreparedCoreOperation{}, errors.New("unsupported Core operation")
	}
	if strings.TrimSpace(req.TargetID) == "" || strings.TrimSpace(req.Source.SourceID) == "" || strings.TrimSpace(req.Source.Version) == "" || !validSHA256(req.Source.PackageSHA256) || req.Source.PackageFS == nil {
		return PreparedCoreOperation{}, errors.New("complete frozen Core source identity is required")
	}
	if err := validateCoreConfiguration(req); err != nil {
		return PreparedCoreOperation{}, err
	}
	if req.Operation == Install && (req.ObservedCoreID != "" || req.ObservedCoreSHA256 != "") {
		return PreparedCoreOperation{}, errors.New("Core install requires Core to be absent")
	}
	if req.Operation != Install && (req.ObservedCoreID == "" || !validSHA256(req.ObservedCoreSHA256)) {
		return PreparedCoreOperation{}, errors.New("Core mutation requires the installed exact Core identity")
	}
	if req.Operation == Update {
		if !req.BackupRequired || strings.TrimSpace(req.BackupRef) == "" {
			return PreparedCoreOperation{}, errors.New("Core update requires a concrete verified backup precondition")
		}
	} else if req.BackupRef != "" {
		return PreparedCoreOperation{}, errors.New("Core backup reference is valid only for update")
	}
	if err := validateCoreSwap(req.SwapMode, req.SwapSizeGiB, req.EffectiveSwapBytes); err != nil {
		return PreparedCoreOperation{}, err
	}

	definition, err := compileCoreDefinition(req.Source.PackageFS, req.Source.Version)
	if err != nil {
		return PreparedCoreOperation{}, err
	}
	imageIDs, imageDigests, err := c.resolveCoreImages(ctx, definition)
	if err != nil {
		return PreparedCoreOperation{}, err
	}
	actions, actionIDs, err := coreActions(req.Source.PackageFS, req.Operation)
	if err != nil {
		return PreparedCoreOperation{}, err
	}
	artifacts := []GeneratedArtifact{}
	files := []executionbundle.File{}
	if req.Operation != Validate {
		artifacts, err = generateCoreArtifacts(req, definition, imageIDs)
		if err != nil {
			return PreparedCoreOperation{}, err
		}
		for _, generated := range artifacts {
			files = append(files, executionbundle.File{Path: generated.Path, TargetPath: generated.TargetPath, Mode: generated.Mode, Data: generated.Data})
		}
	}

	preconditions := []executionbundle.Precondition{{Kind: "target", Subject: req.TargetID, Expected: "same-target"}}
	if req.Operation != Install {
		preconditions = append(preconditions,
			executionbundle.Precondition{Kind: "core-source-id", Subject: "installed", Expected: req.ObservedCoreID},
			executionbundle.Precondition{Kind: "core-package-sha256", Subject: "installed", Expected: req.ObservedCoreSHA256},
		)
	}
	for _, generated := range artifacts {
		if current := req.ObservedArtifacts[generated.TargetPath]; current != "" {
			if !validSHA256(current) {
				return PreparedCoreOperation{}, fmt.Errorf("invalid observed artifact sha256 for %s", generated.TargetPath)
			}
			preconditions = append(preconditions, executionbundle.Precondition{Kind: "artifact-sha256", Subject: generated.TargetPath, Expected: current})
		}
	}

	plan := corePlan(req.Operation)
	steps := make([]executionbundle.Step, 0, len(artifacts)+len(actions))
	for i, generated := range artifacts {
		steps = append(steps, executionbundle.Step{ID: fmt.Sprintf("apply-core-artifact-%03d", i+1), Kind: "apply-artifact", Artifact: generated.Path, Mutating: true})
	}
	for _, id := range actionIDs {
		steps = append(steps, executionbundle.Step{ID: id, Kind: "action", Action: id, Mutating: req.Operation != Validate})
	}
	validations := []executionbundle.ValidationSpec{{ID: "core-complete", ReadOnly: true}}
	post := map[string]any{
		"target_id":           req.TargetID,
		"core_source_id":      req.Source.SourceID,
		"core_version":        req.Source.Version,
		"core_package_sha256": req.Source.PackageSHA256,
		"core_contract":       definition.CoreContract,
		"image_digests":       imageDigests,
		"artifacts":           artifactPostState(artifacts),
	}
	bundleKind := executionbundle.Migration
	switch req.Operation {
	case Install:
		bundleKind = executionbundle.Installation
	case Validate:
		bundleKind = executionbundle.Validation
	}
	bundleSecrets := coreBundleSecrets(req.Secrets)
	if req.Operation == Restore {
		// Restore gets the backed-up values from the verified restore payload.
		// Stable secret IDs remain in generated desired state, but current
		// Management State values must not overwrite historical restore data.
		bundleSecrets = nil
	}
	sourceIdentity := executionbundle.SourceIdentity{Kind: "core", ID: req.Source.SourceID, Version: req.Source.Version, GitCommit: req.Source.GitCommit, PackageSHA256: req.Source.PackageSHA256}
	bundle, err := c.bundles.Assemble(executionbundle.Input{
		Kind:            bundleKind,
		TargetID:        req.TargetID,
		SubjectKind:     "core",
		SubjectID:       "core",
		SubjectIdentity: req.Source.SourceID,
		PackageSHA256:   req.Source.PackageSHA256,
		Version:         req.Source.Version,
		Sources:         []executionbundle.SourceIdentity{sourceIdentity},
		Images:          imageIDs,
		Files:           files,
		Actions:         actions,
		ActionIDs:       actionIDs,
		Secrets:         bundleSecrets,
		Preconditions:   preconditions,
		ExpectedPost:    post,
		Validations:     validations,
		Steps:           steps,
		BackupRequired:  req.BackupRequired,
		BackupRef:       req.BackupRef,
	})
	if err != nil {
		return PreparedCoreOperation{}, err
	}
	operation := PreparedOperation{
		Operation:    req.Operation,
		PlanRequired: req.Operation != Validate,
		Plan:         plan,
		FrozenSources: []FrozenIdentity{{
			InstanceID:    "core",
			ModuleID:      "core",
			Version:       req.Source.Version,
			SourceID:      req.Source.SourceID,
			GitCommit:     req.Source.GitCommit,
			PackageSHA256: req.Source.PackageSHA256,
		}},
		ImageDigests:  imageDigests,
		Artifacts:     artifacts,
		Preconditions: preconditions,
		ExpectedPost:  post,
		Validations:   validations,
		Bundle:        bundle,
	}
	return PreparedCoreOperation{PreparedOperation: operation, CoreContract: definition.CoreContract}, nil
}

func validateCoreConfiguration(req CoreRequest) error {
	if !coreAdminUser.MatchString(req.AdminUser) {
		return errors.New("Core requires a valid administrator user")
	}
	if err := validateCoreDomain(req.Domain); err != nil {
		return err
	}
	address, err := mail.ParseAddress(req.ACMEEmail)
	if err != nil || address.Address != req.ACMEEmail || strings.TrimSpace(req.ACMEEmail) == "" {
		return errors.New("Core requires a valid ACME email address")
	}
	if !req.Secrets.complete() {
		return errors.New("Core requires all Authelia secret references")
	}
	return nil
}

func validateCoreDomain(domain string) error {
	if domain == "" || domain != strings.ToLower(domain) || len(domain) > 253 || strings.HasSuffix(domain, ".") {
		return errors.New("Core requires a lowercase ASCII FQDN without trailing dot")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return errors.New("Core requires a public FQDN")
	}
	for _, label := range labels {
		if !coreDomainLabel.MatchString(label) {
			return errors.New("Core domain contains an invalid DNS label")
		}
	}
	return nil
}

func coreBundleSecrets(ids CoreSecretIDs) []executionbundle.SecretReference {
	return []executionbundle.SecretReference{
		{SecretID: ids.AutheliaSession, Container: "core/authelia", Delivery: "file", Target: "/run/secrets/session"},
		{SecretID: ids.AutheliaStorage, Container: "core/authelia", Delivery: "file", Target: "/run/secrets/storage"},
		{SecretID: ids.AutheliaResetPassword, Container: "core/authelia", Delivery: "file", Target: "/run/secrets/reset-password"},
		{SecretID: ids.AutheliaUsersDatabase, Container: "core/authelia", Delivery: "file", Target: "/config/users_database.yml"},
	}
}

func generateCoreDesired(req CoreRequest, definition coreDefinition, images []executionbundle.ImageIdentity) (GeneratedArtifact, error) {
	resolved := make(map[string]generatedCoreImage, len(images))
	for _, image := range images {
		resolved[image.Name] = generatedCoreImage{Ref: image.Ref, Digest: image.Digest}
	}
	data, err := json.Marshal(generatedCoreDesired{
		SourceID:      req.Source.SourceID,
		Version:       req.Source.Version,
		PackageSHA256: req.Source.PackageSHA256,
		CoreContract:  definition.CoreContract,
		AdminUser:     req.AdminUser,
		Domain:        req.Domain,
		ACMEEmail:     req.ACMEEmail,
		Images:        resolved,
		Secrets: generatedCoreSecrets{
			AutheliaSession:       req.Secrets.AutheliaSession,
			AutheliaStorage:       req.Secrets.AutheliaStorage,
			AutheliaResetPassword: req.Secrets.AutheliaResetPassword,
			AutheliaUsersDatabase: req.Secrets.AutheliaUsersDatabase,
		},
		SwapMode:           req.SwapMode,
		SwapSizeGiB:        req.SwapSizeGiB,
		EffectiveSwapBytes: req.EffectiveSwapBytes,
	})
	if err != nil {
		return GeneratedArtifact{}, err
	}
	data = append(data, '\n')
	return artifact("generated/core-desired.json", coreDesiredTarget, 0o400, data), nil
}

func validateCoreSwap(mode string, sizeGiB int, effectiveBytes int64) error {
	switch mode {
	case "none", "preserve-existing":
		if sizeGiB != 0 || effectiveBytes != 0 {
			return errors.New("Core swap size is only valid for swapfile")
		}
	case "swapfile":
		if sizeGiB < 0 || effectiveBytes <= 0 {
			return errors.New("Core swapfile requires a resolved positive size")
		}
	default:
		return errors.New("Core swap mode must be none, swapfile, or preserve-existing")
	}
	return nil
}

func corePlan(operation OperationKind) []PlanStep {
	if operation == Validate {
		return []PlanStep{{ID: "validate", Description: "Core vollständig read-only validieren", Mutating: false}}
	}
	return []PlanStep{
		{ID: "preflight", Description: "Cloud-init und Core-Preconditions prüfen"},
		{ID: "secondary-hardening", Description: "Secondary Host Hardening anwenden", Mutating: true},
		{ID: "swap", Description: "gewählte Swap-Konfiguration anwenden; Swapdateien sind unverschlüsselt", Mutating: true},
		{ID: "podman", Description: "Rootless Podman, pasta, cgroup v2 und UserNS vorbereiten", Mutating: true},
		{ID: "paths", Description: "passive Core-Plattformpfade erzeugen", Mutating: true},
		{ID: "edge", Description: "root-eigene Socket-Proxies für 80 und 443 erzeugen", Mutating: true},
		{ID: "caddy", Description: "Caddy erzeugen und starten", Mutating: true},
		{ID: "authelia", Description: "Authelia erzeugen und starten", Mutating: true},
		{ID: "inventory", Description: "exakte Core-Identität inventarisieren", Mutating: true},
		{ID: "validate", Description: "Core vollständig read-only validieren"},
	}
}

func coreActions(source fs.FS, operation OperationKind) ([]executionbundle.File, []string, error) {
	runtimeName := "actions/runtime.sh"
	runtime, err := fs.ReadFile(source, runtimeName)
	if err != nil {
		return nil, nil, fmt.Errorf("Core package missing %s: %w", runtimeName, err)
	}
	if len(runtime) == 0 {
		return nil, nil, errors.New("Core shared runtime action is empty")
	}
	name := "actions/" + string(operation) + ".sh"
	entrypoint, err := fs.ReadFile(source, name)
	if err != nil {
		return nil, nil, fmt.Errorf("Core package missing %s: %w", name, err)
	}
	if len(entrypoint) == 0 {
		return nil, nil, fmt.Errorf("Core action %s is empty", name)
	}
	data := make([]byte, 0, len(runtime)+len(entrypoint)+1)
	data = append(data, runtime...)
	if runtime[len(runtime)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, entrypoint...)
	return []executionbundle.File{{Path: name, Mode: 0o500, Data: data}}, []string{"core-" + string(operation)}, nil
}

func artifactPostState(values []GeneratedArtifact) map[string]string {
	out := make(map[string]string, len(values))
	for _, value := range values {
		out[value.TargetPath] = value.SHA256
	}
	return out
}
