package deployment

import (
	"sort"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

func preconditions(req Request) []executionbundle.Precondition {
	out := []executionbundle.Precondition{{Kind: "target", Subject: req.TargetID, Expected: "same-target"}}
	for _, o := range req.Observed.Modules {
		out = append(out,
			executionbundle.Precondition{Kind: "module-version", Subject: o.InstanceID, Expected: o.Version},
			executionbundle.Precondition{Kind: "module-package-sha256", Subject: o.InstanceID, Expected: o.PackageSHA256})
		for p, h := range o.ArtifactSHA256 {
			out = append(out, executionbundle.Precondition{Kind: "artifact-sha256", Subject: p, Expected: h})
		}
	}
	if req.Observed.CoreID != "" {
		out = append(out, executionbundle.Precondition{Kind: "core", Subject: "core", Expected: req.Observed.CoreID})
	}
	return out
}

func diffState(req Request, mods []compiledModule, artifacts []GeneratedArtifact, links []LinkNetwork) []DiffFact {
	obs := map[string]ObservedModule{}
	for _, o := range req.Observed.Modules {
		obs[o.InstanceID] = o
	}
	var out []DiffFact
	if req.Operation == Uninstall {
		for _, o := range req.Observed.Modules {
			if o.InstanceID == req.SubjectInstance {
				out = append(out, DiffFact{Kind: "module_removed", Subject: o.InstanceID, Observed: o.Version})
				break
			}
		}
	}
	for _, m := range mods {
		o, ok := obs[m.Desired.InstanceID]
		if !ok {
			out = append(out, DiffFact{Kind: "module_missing", Subject: m.Desired.InstanceID, Desired: m.Contract.Version})
			continue
		}
		if o.Version != m.Contract.Version {
			out = append(out, DiffFact{Kind: "version_changed", Subject: m.Desired.InstanceID, Desired: m.Contract.Version, Observed: o.Version})
		}
		if o.PackageSHA256 != m.Desired.Source.PackageSHA256 {
			out = append(out, DiffFact{Kind: "source_changed", Subject: m.Desired.InstanceID, Desired: m.Desired.Source.PackageSHA256, Observed: o.PackageSHA256})
		}
		for id, d := range m.Images {
			if o.ImageDigests[id] != d {
				out = append(out, DiffFact{Kind: "image_digest_changed", Subject: m.Desired.InstanceID + "/" + id, Desired: d, Observed: o.ImageDigests[id]})
			}
		}
		wantRuntime := runtimeObjects(m, links)
		gotRuntime := map[string]struct{}{}
		for _, value := range o.RuntimeObjects {
			gotRuntime[value] = struct{}{}
		}
		for _, value := range wantRuntime {
			if _, ok := gotRuntime[value]; !ok {
				out = append(out, DiffFact{Kind: "runtime_missing", Subject: m.Desired.InstanceID, Desired: value})
			}
			delete(gotRuntime, value)
		}
		for value := range gotRuntime {
			out = append(out, DiffFact{Kind: "runtime_unexpected", Subject: m.Desired.InstanceID, Observed: value})
		}
	}
	artifactObs := map[string]string{}
	for _, o := range req.Observed.Modules {
		for p, h := range o.ArtifactSHA256 {
			artifactObs[p] = h
		}
	}
	for _, a := range artifacts {
		if got := artifactObs[a.TargetPath]; got != "" && got != a.SHA256 {
			out = append(out, DiffFact{Kind: "artifact_hash_changed", Subject: a.TargetPath, Desired: a.SHA256, Observed: got})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func expectedPost(req Request, mods []compiledModule, artifacts []GeneratedArtifact) any {
	type modulePost struct {
		InstanceID    string            `json:"instance_id"`
		ModuleID      string            `json:"module_id"`
		Version       string            `json:"version"`
		PackageSHA256 string            `json:"package_sha256"`
		Images        map[string]string `json:"images"`
	}
	doc := struct {
		TargetID  string            `json:"target_id"`
		Modules   []modulePost      `json:"modules"`
		Artifacts map[string]string `json:"artifacts"`
	}{TargetID: req.TargetID, Artifacts: map[string]string{}}
	for _, m := range mods {
		doc.Modules = append(doc.Modules, modulePost{
			InstanceID: m.Desired.InstanceID, ModuleID: m.Contract.ID, Version: m.Contract.Version,
			PackageSHA256: m.Desired.Source.PackageSHA256, Images: m.Images,
		})
	}
	for _, a := range artifacts {
		doc.Artifacts[a.TargetPath] = a.SHA256
	}
	return doc
}

func runtimeObjects(m compiledModule, links []LinkNetwork) []string {
	prefix := "vpsmith-" + m.Desired.InstanceID
	var out []string
	for _, c := range m.Contract.Containers {
		out = append(out, "container:"+prefix+"-"+c.ID, "unit:"+prefix+"-"+c.ID+".service")
	}
	for _, n := range m.Contract.Networks {
		out = append(out, "network:"+prefix+"-"+n.ID)
	}
	for _, l := range links {
		if participantInstance(l.Provider) == m.Desired.InstanceID || participantInstance(l.Consumer) == m.Desired.InstanceID {
			out = append(out, "network:"+l.Name)
		}
	}
	sort.Strings(out)
	return out
}
