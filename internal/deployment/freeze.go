package deployment

import "github.com/privat655/VPSmith/internal/executionbundle"

func freezePlanIdentities(req Request, mods []compiledModule, detached *compiledModule) ([]FrozenIdentity, []executionbundle.SourceIdentity, []executionbundle.ImageIdentity, map[string]string) {
	frozen := make([]FrozenIdentity, 0, len(mods))
	sources := make([]executionbundle.SourceIdentity, 0, len(mods)+1)
	images := []executionbundle.ImageIdentity{}
	imageMap := map[string]string{}
	if req.CoreSource.ID != "" {
		sources = append(sources, req.CoreSource)
	}
	all := append([]compiledModule(nil), mods...)
	if detached != nil {
		all = append(all, *detached)
	}
	for _, m := range all {
		frozen = append(frozen, FrozenIdentity{
			InstanceID: m.Desired.InstanceID, ModuleID: m.Contract.ID, Version: m.Contract.Version,
			SourceID: m.Desired.Source.SourceID, PackageID: m.Desired.Source.PackageID,
			GitCommit: m.Desired.Source.GitCommit, PackageSHA256: m.Desired.Source.PackageSHA256,
		})
		sources = append(sources, executionbundle.SourceIdentity{
			Kind: "module", ID: m.Desired.Source.SourceID, Version: m.Contract.Version,
			GitCommit: m.Desired.Source.GitCommit, PackageSHA256: m.Desired.Source.PackageSHA256,
		})
		for _, id := range sortedDigestKeys(m.Images) {
			key := m.Desired.InstanceID + "/" + id
			imageMap[key] = m.Images[id]
			images = append(images, executionbundle.ImageIdentity{Name: key, Ref: m.Contract.Images[id].Ref, Digest: m.Images[id]})
		}
	}
	return frozen, sources, images, imageMap
}

func bundleSecrets(mods []compiledModule) []executionbundle.SecretReference {
	var out []executionbundle.SecretReference
	for _, m := range mods {
		for _, s := range m.Contract.Secrets {
			for _, container := range s.Containers {
				target := s.Name
				if s.Delivery == "file" {
					target = s.Path
				}
				out = append(out, executionbundle.SecretReference{
					SecretID: m.Desired.SecretIDs[s.ID], Container: m.Desired.InstanceID + "/" + container,
					Delivery: s.Delivery, Target: target,
				})
			}
		}
	}
	return out
}
