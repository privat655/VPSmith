package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

// FrozenCoreSource is the exact immutable Core package selected by the Source Library.
type FrozenCoreSource struct {
	SourceID      string
	Version       string
	GitCommit     string
	PackageSHA256 string
	PackageFS     fs.FS
}

// CoreRequest is deliberately smaller than the module compiler request. Core
// owns host/platform infrastructure, not application topology.
type CoreRequest struct {
	Operation      OperationKind
	TargetID       string
	Source         FrozenCoreSource
	ObservedCoreID string
	SwapMode       string
	SwapSizeGiB    int
	BackupRequired bool
}

// PrepareCore freezes one Core package into the same immutable execution-bundle
// format used by every structural VPSmith operation. The package owns its
// scripts and generated files; the target runner remains generic.
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
	if req.Operation == Install && req.ObservedCoreID != "" {
		return PreparedOperation{}, errors.New("Core install requires Core to be absent")
	}
	if req.Operation != Install && req.ObservedCoreID == "" {
		return PreparedOperation{}, errors.New("Core mutation requires an installed Core identity")
	}
	if req.Operation == Update && !req.BackupRequired {
		return PreparedOperation{}, errors.New("Core update requires a verified backup precondition")
	}
	if err := validateCoreSwap(req.SwapMode, req.SwapSizeGiB); err != nil {
		return PreparedOperation{}, err
	}

	actions, actionIDs, err := coreActions(req.Source.PackageFS, req.Operation)
	if err != nil {
		return PreparedOperation{}, err
	}
	artifacts, files, err := coreArtifacts(req.Source.PackageFS)
	if err != nil {
		return PreparedOperation{}, err
	}
	pre := []executionbundle.Precondition{{Kind: "target", Subject: req.TargetID, Expected: "same-target"}}
	if req.Operation != Install {
		pre = append(pre, executionbundle.Precondition{Kind: "core", Subject: "installed", Expected: req.ObservedCoreID})
	}
	plan := corePlan(req.Operation)
	steps := make([]executionbundle.Step, 0, len(actions)+len(files))
	for _, a := range artifacts {
		steps = append(steps, executionbundle.Step{ID: "apply-" + safeStepID(a.Path), Kind: "apply-artifact", Artifact: a.Path, Mutating: req.Operation != Validate})
	}
	for _, id := range actionIDs {
		steps = append(steps, executionbundle.Step{ID: id, Kind: "action", Action: id, Args: []string{req.SwapMode, fmt.Sprintf("%d", req.SwapSizeGiB)}, Mutating: req.Operation != Validate})
	}
	validations := []executionbundle.ValidationSpec{{ID: "core-complete", ReadOnly: true}}
	post := map[string]any{"target_id": req.TargetID, "core_source_id": req.Source.SourceID, "core_version": req.Source.Version, "core_package_sha256": req.Source.PackageSHA256, "artifacts": artifactPostState(artifacts)}
	kind := executionbundle.Migration
	if req.Operation == Install { kind = executionbundle.Installation }
	if req.Operation == Validate { kind = executionbundle.Validation }
	bundle, err := c.bundles.Assemble(executionbundle.Input{
		Kind: kind, TargetID: req.TargetID, SubjectKind: "core", SubjectID: "core",
		SubjectIdentity: req.Source.SourceID, PackageSHA256: req.Source.PackageSHA256, Version: req.Source.Version,
		Sources: []executionbundle.SourceIdentity{{Kind: "core", ID: req.Source.SourceID, Version: req.Source.Version, GitCommit: req.Source.GitCommit, PackageSHA256: req.Source.PackageSHA256}},
		Files: files, Actions: actions, ActionIDs: actionIDs, Preconditions: pre, ExpectedPost: post,
		Validations: validations, Steps: steps, BackupRequired: req.BackupRequired,
	})
	if err != nil { return PreparedOperation{}, err }
	return PreparedOperation{Operation: req.Operation, PlanRequired: req.Operation != Validate, Plan: plan, Preconditions: pre, ExpectedPost: post, Validations: validations, Artifacts: artifacts, Bundle: bundle}, nil
}

func validateCoreSwap(mode string, size int) error {
	switch mode {
	case "none", "preserve-existing":
		if size != 0 { return errors.New("Core swap size is only valid for swapfile") }
	case "swapfile":
		if size < 0 { return errors.New("Core swap size must be auto or a positive GiB value") }
	default:
		return errors.New("Core swap mode must be none, swapfile, or preserve-existing")
	}
	return nil
}

func corePlan(op OperationKind) []PlanStep {
	if op == Validate { return []PlanStep{{ID: "validate", Description: "Core vollständig read-only validieren", Mutating: false}} }
	return []PlanStep{
		{ID:"preflight", Description:"Cloud-init und Core-Preconditions prüfen"},
		{ID:"secondary-hardening", Description:"Secondary Host Hardening anwenden", Mutating:true},
		{ID:"swap", Description:"gewählte Swap-Konfiguration anwenden", Mutating:true},
		{ID:"podman", Description:"Rootless Podman, pasta, cgroup v2 und UserNS vorbereiten", Mutating:true},
		{ID:"paths", Description:"passive Core-Plattformpfade erzeugen", Mutating:true},
		{ID:"edge", Description:"root-eigene Socket-Proxies für 80 und 443 erzeugen", Mutating:true},
		{ID:"caddy", Description:"Caddy erzeugen und starten", Mutating:true},
		{ID:"authelia", Description:"Authelia erzeugen und starten", Mutating:true},
		{ID:"inventory", Description:"exakte Core-Identität inventarisieren", Mutating:true},
		{ID:"validate", Description:"Core vollständig read-only validieren"},
	}
}

func coreActions(fsys fs.FS, op OperationKind) ([]executionbundle.File, []string, error) {
	name := "actions/" + string(op) + ".sh"
	data, err := fs.ReadFile(fsys, name)
	if err != nil { return nil, nil, fmt.Errorf("Core package missing %s: %w", name, err) }
	if len(data) == 0 { return nil, nil, fmt.Errorf("Core action %s is empty", name) }
	return []executionbundle.File{{Path:name, Mode:0o500, Data:data}}, []string{"core-" + string(op)}, nil
}

func coreArtifacts(fsys fs.FS) ([]GeneratedArtifact, []executionbundle.File, error) {
	var generated []GeneratedArtifact
	var files []executionbundle.File
	err := fs.WalkDir(fsys, "generated", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil { return walkErr }
		if d.IsDir() { return nil }
		if !d.Type().IsRegular() { return fmt.Errorf("unsupported Core generated entry %s", name) }
		data, err := fs.ReadFile(fsys, name); if err != nil { return err }
		rel := strings.TrimPrefix(name, "generated/")
		target := "/" + rel
		sum := sha256.Sum256(data)
		generated = append(generated, GeneratedArtifact{Path:name, TargetPath:target, Mode:0o444, Data:data, SHA256:hex.EncodeToString(sum[:])})
		files = append(files, executionbundle.File{Path:name, TargetPath:target, Mode:0o444, Data:data})
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) { return nil, nil, err }
	sort.Slice(generated, func(i,j int) bool { return generated[i].Path < generated[j].Path })
	sort.Slice(files, func(i,j int) bool { return files[i].Path < files[j].Path })
	return generated, files, nil
}

func artifactPostState(values []GeneratedArtifact) map[string]string {
	out := make(map[string]string, len(values)); for _, v := range values { out[v.TargetPath] = v.SHA256 }; return out
}

func safeStepID(value string) string {
	value = path.Clean(value); value = strings.ReplaceAll(value, "/", "-"); value = strings.ReplaceAll(value, ".", "-"); return value
}
