package deployment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

type coreDefinition struct {
	CoreVersion  string                   `json:"core_version"`
	CoreContract string                   `json:"core_contract"`
	Images       map[string]coreImageSpec `json:"images"`
}

type coreImageSpec struct {
	Ref string `json:"ref"`
}

func compileCoreDefinition(source fs.FS, expectedVersion string) (coreDefinition, error) {
	data, err := fs.ReadFile(source, "core.json")
	if err != nil {
		return coreDefinition{}, fmt.Errorf("Core package missing core.json: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var definition coreDefinition
	if err := decoder.Decode(&definition); err != nil {
		return coreDefinition{}, fmt.Errorf("decode Core definition: %w", err)
	}
	if decoder.More() {
		return coreDefinition{}, errors.New("Core definition contains trailing JSON values")
	}
	if strings.TrimSpace(definition.CoreVersion) == "" || definition.CoreVersion != expectedVersion {
		return coreDefinition{}, errors.New("Core definition version does not match frozen source version")
	}
	if strings.TrimSpace(definition.CoreContract) == "" {
		return coreDefinition{}, errors.New("Core definition requires core_contract")
	}
	for _, required := range []string{"caddy", "authelia"} {
		image, ok := definition.Images[required]
		if !ok || strings.TrimSpace(image.Ref) == "" {
			return coreDefinition{}, fmt.Errorf("Core definition requires image %s", required)
		}
	}
	if len(definition.Images) != 2 {
		return coreDefinition{}, errors.New("Core definition contains unsupported images")
	}
	return definition, nil
}

func (c *Compiler) resolveCoreImages(ctx context.Context, definition coreDefinition) ([]executionbundle.ImageIdentity, map[string]string, error) {
	keys := make([]string, 0, len(definition.Images))
	for key := range definition.Images {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	identities := make([]executionbundle.ImageIdentity, 0, len(keys))
	digests := make(map[string]string, len(keys))
	for _, key := range keys {
		ref := definition.Images[key].Ref
		digest, err := c.registry.Resolve(ctx, ref)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve Core image %s: %w", key, err)
		}
		if !validDigest(digest) {
			return nil, nil, fmt.Errorf("registry returned invalid digest for Core image %s", key)
		}
		identities = append(identities, executionbundle.ImageIdentity{Name: key, Ref: ref, Digest: digest})
		digests[key] = digest
	}
	return identities, digests, nil
}
