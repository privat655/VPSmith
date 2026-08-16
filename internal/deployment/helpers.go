package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/modulecontract"
)

func artifact(p, target string, mode int64, data []byte) GeneratedArtifact {
	s := sha256.Sum256(data)
	return GeneratedArtifact{Path: p, TargetPath: target, Mode: mode, Data: data, SHA256: hex.EncodeToString(s[:])}
}

func subjectVersion(req Request, mods []compiledModule, detached *compiledModule) string {
	for _, m := range mods {
		if m.Desired.InstanceID == req.SubjectInstance {
			return m.Contract.Version
		}
	}
	if detached != nil {
		return detached.Contract.Version
	}
	for _, o := range req.Observed.Modules {
		if o.InstanceID == req.SubjectInstance {
			return o.Version
		}
	}
	return "unknown"
}

func sortedImageKeys(m map[string]modulecontract.Image) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedDigestKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func validDigest(v string) bool {
	if !strings.HasPrefix(v, "sha256:") || len(v) != 71 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(v, "sha256:"))
	return err == nil
}

func subjectBundleIdentity(req Request, mods []compiledModule, detached *compiledModule) (string, string, string) {
	for _, m := range mods {
		if m.Desired.InstanceID == req.SubjectInstance {
			return m.Contract.ID, m.Desired.Source.PackageID, m.Desired.Source.PackageSHA256
		}
	}
	if detached != nil {
		return detached.Contract.ID, detached.Desired.Source.PackageID, detached.Desired.Source.PackageSHA256
	}
	return "unknown", "", ""
}
