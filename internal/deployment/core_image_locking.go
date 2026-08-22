package deployment

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

func (c *Compiler) resolveCoreImagesForRequest(ctx context.Context, req CoreRequest, definition coreDefinition) ([]executionbundle.ImageIdentity, map[string]string, error) {
	if len(req.LockedImages) == 0 {
		return c.resolveCoreImages(ctx, definition)
	}
	if req.Operation != Reconfigure && req.Operation != Validate {
		return nil, nil, errors.New("installed Core image locks are valid only for reconfigure and validation")
	}
	if len(req.LockedImages) != len(definition.Images) {
		return nil, nil, errors.New("installed Core image locks must cover every Core image")
	}
	identities := make([]executionbundle.ImageIdentity, 0, len(definition.Images))
	digests := make(map[string]string, len(definition.Images))
	for _, name := range []string{"caddy", "authelia"} {
		want, ok := definition.Images[name]
		if !ok {
			return nil, nil, fmt.Errorf("Core definition is missing image %s", name)
		}
		lock, ok := req.LockedImages[name]
		if !ok || strings.TrimSpace(lock.Ref) == "" || lock.Ref != want.Ref || !validDigest(lock.Digest) {
			return nil, nil, fmt.Errorf("installed Core image lock for %s does not match frozen Core package", name)
		}
		identities = append(identities, executionbundle.ImageIdentity{Name: name, Ref: lock.Ref, Digest: lock.Digest})
		digests[name] = lock.Digest
	}
	return identities, digests, nil
}
