package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

const coreDesiredTarget = "/var/lib/vpsmith/core/desired.json"

// FrozenCoreSource is the exact immutable Core package selected by the Source Library.
type FrozenCoreSource struct {
	SourceID      string
	Version       string
	GitCommit     string
	PackageSHA256 string
	PackageFS     fs.FS
}

// CoreRequest contains only frozen facts. Detection belongs to CoreLifecycle
// and TargetInspector; generation belongs here.
type CoreRequest struct {
	Operation          OperationKind
	TargetID           string
	Source             FrozenCoreSource
	ObservedCoreID     string
	ObservedCoreSHA256 string
	ObservedArtifacts  map[string]string
	SwapMode           string
	SwapSizeGiB        int
	EffectiveSwapBytes int64
	BackupRequired     bool
}

type generatedCoreDesired struct {
	SourceID           string `json:"source_id"`
	Version            string `json:"version"`
	PackageSHA256      string `json:"package_sha256"`
	SwapMode           string `json:"swap_mode"`
	SwapSizeGiB        int    `json:"swap_size_gib,omitempty"`
	EffectiveSwapBytes int64  `json:"effective_swap_bytes,omitempty"`
}

// PrepareCore freezes one Core candidate into the same immutable execution
// bundle used by all structural VPSmith operations. The target runner stays
// generic; it never contains a second Core installer.
func (c *Compiler) PrepareCore(ctx context.Context, req CoreRequest) (PreparedOperation, error) {
	if err := ctx.Err(); err != nil {
		return PreparedOperation{}, err
	}
	if c == nil || c.bundles == nil {
		return PreparedOperation{}, errors.New("deployment compiler is required")
	}
	if req.Operation != Install && req.Operation != Update && req.Operation != Reconfigure && req.Operation != Restore && req.Operation != Validate {
		return PreparedOperation{}, errors.New("unsupported Core operation")
	}
	if strings.TrimSpace(req.TargetID) == "" || strings.TrimSpace(req.Source.SourceID) == "" || strings.TrimSpace(req.Source.Version) == "" || !validSHA256(req.Source.PackageSHA256) || req.Source.PackageFS == nil {
		return PreparedOperation{}, errors.New("complete frozen Core source identity is required")
	}
	if req.Operation == Install && (req.ObservedCoreID != "" || req.ObservedCoreSHA256 != "") {
		return PreparedOperation{}, errors.New("Core install requires Core to be absent")
	}
	if req.Operation != Install && (req.ObservedCoreID == "" || !validSHA256(req.ObservedCoreSHA256)) {
		return PreparedOperation{}, errors.New("Core mutation requires the installed exact Core identity")
	}
	if req.Operation == Update && !req.BackupRequired {
		return PreparedOperation{}, errors.New("Core update requires a verified backup precondition")
	}
	if err := validateCoreSwap(req.SwapMode, req.SwapSizeGiB, req.EffectiveSwapBytes); err != nil {
		return PreparedOperation{}, err
	}

	actions, actionIDs, err := coreActions(req.Source.PackageFS, req.Operation)
	if err != nil {
		return PreparedOperation{}, err
	}
	artifacts := []GeneratedArtifact{}
	files := []executionbundle.File{}
	if req.Operation != Validate {
		desired, err := generateCoreDesired(req)
		if err != nil {
			return PreparedOperation{}, err
		}
		artifacts = append(artifacts, desired)
		files = append(files, executionbundle.File{Path: desired.Path, TargetPath: desired.TargetPath, Mode: desired.Mode, Data: desired.Data})
	}

	preconditions := []executionbundle.Precondition{{Kind: "target", Subject: req.TargetID, Expected: "same-target"}}
	if req.Operation != Install {
		preconditions = append(preconditions,
			executionbundle.Precondition{Kind: "core-source-id", Subject: "installed", Expected: req.ObservedCoreID},
			executionbundle.Precondition{Kind: "core-package-sha256", Subject: "installed", Expected: req.ObservedCoreSHA256},
		)
	}
	for _, artifact := range artifacts {
		if current := req.ObservedArtifacts[artifact.TargetPath]; current != "" {
			if !validSHA256(current) {
				return PreparedOperation{}, fmt.Errorf("invalid observed artifact sha256 for %s", artifact.TargetPath)
			}
			preconditions = append(preconditions, executionbundle.Precondition{Kind: "artifact-sha256", Subject: artifact.TargetPath, Expected: current})
		}
	}

	plan := corePlan(req.Operation)
	steps := make([]executionbundle.Step, 0, len(artifacts)+len(actions))
	for _, artifact := range artifacts {
		steps = append(steps, executionbundle.Step{ID: "apply-core-desired", Kind: "apply-artifact", Artifact: artifact.Path, Mutating: true})
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
		"artifacts":           artifactPostState(artifacts),
	}
	bundleKind := executionbundle.Migration
	switch req.Operation {
	case Install:
		bundleKind = executionbundle.Installation
	case Validate:
		bundleKind = executionbundle.Validation
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
		Files:           files,
		Actions:         actions,
		ActionIDs:       actionIDs,
		Preconditions:   preconditions,
		ExpectedPost:    post,
		Validations:     validations,
		Steps:           steps,
		BackupRequired:  req.BackupRequired,
	})
	if err != nil {
		return PreparedOperation{}, err
	}
	return PreparedOperation{
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
		ImageDigests:  map[string]string{},
		Artifacts:     artifacts,
		Preconditions: preconditions,
		ExpectedPost:  post,
		Validations:   validations,
		Bundle:        bundle,
	}, nil
}

func generateCoreDesired(req CoreRequest) (GeneratedArtifact, error) {
	data, err := json.Marshal(generatedCoreDesired{
		SourceID:           req.Source.SourceID,
		Version:            req.Source.Version,
		PackageSHA256:      req.Source.PackageSHA256,
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
		{ID: "swap", Description: "gewählte Swap-Konfiguration anwenden", Mutating: true},
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
	name := "actions/" + string(operation) + ".sh"
	data, err := fs.ReadFile(source, name)
	if err != nil {
		return nil, nil, fmt.Errorf("Core package missing %s: %w", name, err)
	}
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("Core action %s is empty", name)
	}
	return []executionbundle.File{{Path: name, Mode: 0o500, Data: data}}, []string{"core-" + string(operation)}, nil
}

func artifactPostState(values []GeneratedArtifact) map[string]string {
	out := make(map[string]string, len(values))
	for _, value := range values {
		out[value.TargetPath] = value.SHA256
	}
	return out
}
