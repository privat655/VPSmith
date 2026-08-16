package executionbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

func validateInput(in Input) error {
	if in.Kind != Installation && in.Kind != Migration && in.Kind != Validation {
		return errors.New("invalid bundle kind")
	}
	if strings.TrimSpace(in.TargetID) == "" || strings.TrimSpace(in.SubjectKind) == "" || strings.TrimSpace(in.SubjectID) == "" || strings.TrimSpace(in.SubjectIdentity) == "" || strings.TrimSpace(in.Version) == "" {
		return errors.New("bundle identity is incomplete")
	}
	if len(in.ActionIDs) != len(in.Actions) {
		return errors.New("action IDs and action files must have equal length")
	}
	if in.PackageSHA256 != "" && !validSHA256(in.PackageSHA256) {
		return errors.New("bundle package sha256 is invalid")
	}
	for _, source := range in.Sources {
		if strings.TrimSpace(source.Kind) == "" || strings.TrimSpace(source.ID) == "" || strings.TrimSpace(source.Version) == "" || !validSHA256(source.PackageSHA256) {
			return errors.New("bundle source identity is incomplete or invalid")
		}
	}
	for _, image := range in.Images {
		if strings.TrimSpace(image.Name) == "" || strings.TrimSpace(image.Ref) == "" || !strings.HasPrefix(image.Digest, "sha256:") || !validSHA256(strings.TrimPrefix(image.Digest, "sha256:")) {
			return errors.New("bundle image identity is incomplete or invalid")
		}
	}
	if in.Kind == Validation {
		for _, s := range in.Steps {
			if s.Mutating {
				return fmt.Errorf("validation bundle contains mutating step %s", s.ID)
			}
		}
	}
	return nil
}

func normalizeFiles(in Input) ([]File, []Artifact, []Action, error) {
	seen := map[string]struct{}{}
	files := make([]File, 0, len(in.Files)+len(in.Actions))
	artifacts := make([]Artifact, 0, len(in.Files))
	actions := make([]Action, 0, len(in.Actions))
	add := func(f File) (string, error) {
		if f.Path == "" || path.Clean(f.Path) != f.Path || strings.HasPrefix(f.Path, "/") || strings.HasPrefix(f.Path, "../") || strings.ContainsAny(f.Path, "\r\n\x00") {
			return "", fmt.Errorf("invalid bundle path %q", f.Path)
		}
		if _, ok := seen[f.Path]; ok {
			return "", fmt.Errorf("duplicate bundle path %s", f.Path)
		}
		seen[f.Path] = struct{}{}
		f.Data = append([]byte(nil), f.Data...)
		if f.Mode == 0 {
			f.Mode = 0o444
		}
		if f.Mode&^0o755 != 0 {
			return "", fmt.Errorf("unsafe mode for %s", f.Path)
		}
		s := sha256.Sum256(f.Data)
		digest := hex.EncodeToString(s[:])
		files = append(files, f)
		return digest, nil
	}
	for _, f := range in.Files {
		if f.TargetPath == "" || !strings.HasPrefix(f.TargetPath, "/") || path.Clean(f.TargetPath) != f.TargetPath || strings.ContainsAny(f.TargetPath, "\r\n\x00") {
			return nil, nil, nil, fmt.Errorf("invalid artifact target path %q", f.TargetPath)
		}
		digest, err := add(f)
		if err != nil {
			return nil, nil, nil, err
		}
		artifacts = append(artifacts, Artifact{Path: f.Path, TargetPath: f.TargetPath, SHA256: digest, Mode: f.Mode})
	}
	for i, f := range in.Actions {
		digest, err := add(f)
		if err != nil {
			return nil, nil, nil, err
		}
		actions = append(actions, Action{ID: in.ActionIDs[i], Path: f.Path, SHA256: digest})
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	// Action order is plan semantics and is deliberately preserved.
	return files, artifacts, actions, nil
}

func normalizeManifest(m *Manifest) {
	if m.Sources == nil {
		m.Sources = []SourceIdentity{}
	}
	if m.Images == nil {
		m.Images = []ImageIdentity{}
	}
	if m.Artifacts == nil {
		m.Artifacts = []Artifact{}
	}
	if m.Actions == nil {
		m.Actions = []Action{}
	}
	if m.Secrets == nil {
		m.Secrets = []SecretReference{}
	}
	if m.Preconditions == nil {
		m.Preconditions = []Precondition{}
	}
	if m.Validations == nil {
		m.Validations = []ValidationSpec{}
	}
	if m.Steps == nil {
		m.Steps = []Step{}
	}

	sort.Slice(m.Sources, func(i, j int) bool {
		if m.Sources[i].Kind == m.Sources[j].Kind {
			return m.Sources[i].ID < m.Sources[j].ID
		}
		return m.Sources[i].Kind < m.Sources[j].Kind
	})
	sort.Slice(m.Images, func(i, j int) bool { return m.Images[i].Name < m.Images[j].Name })
	sort.Slice(m.Artifacts, func(i, j int) bool { return m.Artifacts[i].Path < m.Artifacts[j].Path })
	sort.Slice(m.Secrets, func(i, j int) bool {
		a, b := m.Secrets[i], m.Secrets[j]
		if a.SecretID != b.SecretID {
			return a.SecretID < b.SecretID
		}
		if a.Container != b.Container {
			return a.Container < b.Container
		}
		return a.Target < b.Target
	})
	sort.Slice(m.Preconditions, func(i, j int) bool {
		a, b := m.Preconditions[i], m.Preconditions[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.Expected < b.Expected
	})
	sort.Slice(m.Validations, func(i, j int) bool { return m.Validations[i].ID < m.Validations[j].ID })
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}
