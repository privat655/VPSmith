package deployment

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/privat655/VPSmith/internal/executionbundle"
	"github.com/privat655/VPSmith/internal/modulecontract"
)

func New(registry Registry, bundles *executionbundle.Assembler) (*Compiler, error) {
	if registry == nil {
		return nil, errors.New("registry adapter is required")
	}
	if bundles == nil {
		return nil, errors.New("bundle assembler is required")
	}
	return &Compiler{registry: registry, bundles: bundles}, nil
}

func (c *Compiler) Prepare(ctx context.Context, req Request) (PreparedOperation, error) {
	if err := validateRequest(req); err != nil {
		return PreparedOperation{}, err
	}
	mods, err := c.compileModules(ctx, req)
	if err != nil {
		return PreparedOperation{}, err
	}
	if err := validateSubject(req, mods); err != nil {
		return PreparedOperation{}, err
	}
	detachedSubject, err := c.compileDetachedSubject(ctx, req, mods)
	if err != nil {
		return PreparedOperation{}, err
	}
	links, err := deriveLinks(mods, req.Observed.Networks)
	if err != nil {
		return PreparedOperation{}, err
	}
	if err := validateClaims(mods, links, req.Observed.Claims); err != nil {
		return PreparedOperation{}, err
	}
	if req.Operation == Uninstall {
		if err := validateProviderRemoval(req, mods); err != nil {
			return PreparedOperation{}, err
		}
	}
	updateActions, err := validateUpdate(req, mods)
	if err != nil {
		return PreparedOperation{}, err
	}
	artifacts, err := generateArtifacts(mods, links)
	if err != nil {
		return PreparedOperation{}, err
	}
	pre := preconditions(req)
	validations := validationSpecs(req, mods)
	plan, steps, actionFiles, actionIDs, err := buildPlan(req, mods, artifacts, updateActions)
	if err != nil {
		return PreparedOperation{}, err
	}
	frozen, sources, imageIDs, imageMap := freezePlanIdentities(req, mods, detachedSubject)
	post := expectedPost(req, mods, artifacts)
	subjectIdentity, packageID, packageSHA := subjectBundleIdentity(req, mods, detachedSubject)
	bundleFiles := make([]executionbundle.File, 0, len(artifacts))
	for _, a := range artifacts {
		bundleFiles = append(bundleFiles, executionbundle.File{Path: a.Path, TargetPath: a.TargetPath, Mode: a.Mode, Data: a.Data})
	}
	bundle, err := c.bundles.Assemble(executionbundle.Input{
		Kind: bundleKind(req.Operation), TargetID: req.TargetID, SubjectKind: "module", SubjectID: req.SubjectInstance,
		SubjectIdentity: subjectIdentity, PackageID: packageID, PackageSHA256: packageSHA,
		Version: subjectVersion(req, mods, detachedSubject), Sources: sources, Images: imageIDs, Files: bundleFiles,
		Actions: actionFiles, ActionIDs: actionIDs, ActionWritablePaths: actionWritablePaths(req, mods, detachedSubject),
		Secrets: bundleSecrets(mods), Preconditions: pre,
		ExpectedPost: post, Validations: validations, Steps: steps, BackupRequired: req.BackupRequired,
	})
	if err != nil {
		return PreparedOperation{}, err
	}
	return PreparedOperation{
		Operation: req.Operation, PlanRequired: req.Operation != Validate, Plan: plan,
		FrozenSources: frozen, ImageDigests: imageMap, ExpectedChanges: diffState(req, mods, artifacts, links),
		Artifacts: artifacts, Preconditions: pre, ExpectedPost: post, Validations: validations,
		LinkNetworks: links, Bundle: bundle,
	}, nil
}

func (c *Compiler) compileModules(ctx context.Context, req Request) ([]compiledModule, error) {
	mods := make([]compiledModule, 0, len(req.DesiredModules))
	for _, d := range req.DesiredModules {
		contract, err := c.modules.Compile(modulecontract.Package{FS: d.Source.PackageFS})
		if err != nil {
			return nil, fmt.Errorf("compile module %s: %w", d.InstanceID, err)
		}
		if contract.Version == "" || d.Source.PackageSHA256 == "" || d.Source.PackageID == "" || d.Source.SourceID == "" {
			return nil, fmt.Errorf("module %s source identity is incomplete", d.InstanceID)
		}
		if req.CoreContract != "" && contract.CoreContract != req.CoreContract {
			return nil, fmt.Errorf("module %s requires core_contract %s, target provides %s", d.InstanceID, contract.CoreContract, req.CoreContract)
		}
		if err := validateSecretBindings(contract, d.SecretIDs); err != nil {
			return nil, fmt.Errorf("module %s: %w", d.InstanceID, err)
		}
		images := map[string]string{}
		for _, id := range sortedImageKeys(contract.Images) {
			digest, err := c.registry.Resolve(ctx, contract.Images[id].Ref)
			if err != nil {
				return nil, fmt.Errorf("resolve image %s/%s: %w", d.InstanceID, id, err)
			}
			if !validDigest(digest) {
				return nil, fmt.Errorf("registry returned invalid digest for %s/%s", d.InstanceID, id)
			}
			images[id] = digest
		}
		mods = append(mods, compiledModule{Desired: d, Contract: contract, Images: images, Effective: mergeResources(contract.Resources, d.Resources)})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Desired.InstanceID < mods[j].Desired.InstanceID })
	return mods, nil
}

func (c *Compiler) compileDetachedSubject(ctx context.Context, req Request, mods []compiledModule) (*compiledModule, error) {
	if req.Operation != Uninstall {
		return nil, nil
	}
	for _, m := range mods {
		if m.Desired.InstanceID == req.SubjectInstance {
			return nil, errors.New("uninstall subject must be absent from target Sollzustand")
		}
	}
	if req.SubjectSource == nil {
		return nil, errors.New("uninstall requires frozen subject source")
	}
	source := *req.SubjectSource
	if source.InstanceID != "" && source.InstanceID != req.SubjectInstance {
		return nil, errors.New("uninstall frozen subject source belongs to different module instance")
	}
	contract, err := c.modules.Compile(modulecontract.Package{FS: source.PackageFS})
	if err != nil {
		return nil, fmt.Errorf("compile uninstall subject %s: %w", req.SubjectInstance, err)
	}
	if source.SourceID == "" || source.PackageID == "" || source.PackageSHA256 == "" {
		return nil, errors.New("uninstall frozen subject identity is incomplete")
	}
	if req.CoreContract != "" && contract.CoreContract != req.CoreContract {
		return nil, fmt.Errorf("uninstall subject requires core_contract %s, target provides %s", contract.CoreContract, req.CoreContract)
	}
	if err := validateSecretBindings(contract, req.SubjectSecretIDs); err != nil {
		return nil, fmt.Errorf("uninstall subject: %w", err)
	}
	var observed *ObservedModule
	for i := range req.Observed.Modules {
		if req.Observed.Modules[i].InstanceID == req.SubjectInstance {
			observed = &req.Observed.Modules[i]
			break
		}
	}
	if observed == nil {
		return nil, errors.New("uninstall subject is not installed in Ist-Zustand")
	}
	if observed.Version != contract.Version || observed.PackageID != source.PackageID || observed.PackageSHA256 != source.PackageSHA256 {
		return nil, errors.New("uninstall frozen source does not match installed exact module identity")
	}
	images := map[string]string{}
	for _, id := range sortedImageKeys(contract.Images) {
		digest, err := c.registry.Resolve(ctx, contract.Images[id].Ref)
		if err != nil {
			return nil, fmt.Errorf("resolve uninstall image %s/%s: %w", req.SubjectInstance, id, err)
		}
		if !validDigest(digest) {
			return nil, fmt.Errorf("registry returned invalid digest for uninstall subject %s/%s", req.SubjectInstance, id)
		}
		images[id] = digest
		if installed := observed.ImageDigests[id]; installed != "" && installed != digest {
			return nil, fmt.Errorf("uninstall image digest drift for %s/%s", req.SubjectInstance, id)
		}
	}
	desired := DesiredModule{InstanceID: req.SubjectInstance, Source: source, SecretIDs: req.SubjectSecretIDs}
	return &compiledModule{Desired: desired, Contract: contract, Images: images, Effective: contract.Resources}, nil
}
