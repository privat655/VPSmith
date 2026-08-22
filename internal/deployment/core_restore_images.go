package deployment

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// FrozenCoreImage is an exact image identity recovered from a verified Core
// backup. It is accepted only by PrepareCoreRestore; normal Core operations
// continue to resolve their selected package references through the registry.
type FrozenCoreImage struct {
	Ref    string
	Digest string
}

func (c *Compiler) PrepareCoreRestore(ctx context.Context, req CoreRequest, frozen map[string]FrozenCoreImage) (PreparedCoreOperation, error) {
	if req.Operation != Restore {
		return PreparedCoreOperation{}, errors.New("backed-up Core image locks are valid only for restore")
	}
	if c == nil || c.bundles == nil || c.registry == nil {
		return PreparedCoreOperation{}, errors.New("deployment compiler is required")
	}
	definition, err := compileCoreDefinition(req.Source.PackageFS, req.Source.Version)
	if err != nil {
		return PreparedCoreOperation{}, err
	}
	if len(frozen) != len(definition.Images) {
		return PreparedCoreOperation{}, errors.New("Core restore requires exact image locks for every Core image")
	}
	byRef := make(map[string]string, len(frozen))
	for _, name := range []string{"caddy", "authelia"} {
		want, ok := definition.Images[name]
		if !ok {
			return PreparedCoreOperation{}, fmt.Errorf("Core definition is missing image %s", name)
		}
		lock, ok := frozen[name]
		if !ok || strings.TrimSpace(lock.Ref) == "" || lock.Ref != want.Ref || !validDigest(lock.Digest) {
			return PreparedCoreOperation{}, fmt.Errorf("Core restore image lock for %s does not match frozen Core package", name)
		}
		if _, duplicate := byRef[lock.Ref]; duplicate {
			return PreparedCoreOperation{}, errors.New("Core restore image references must be unique")
		}
		byRef[lock.Ref] = lock.Digest
	}
	locked := *c
	locked.registry = frozenCoreRegistry{byRef: byRef}
	return locked.PrepareCore(ctx, req)
}

type frozenCoreRegistry struct {
	byRef map[string]string
}

func (r frozenCoreRegistry) Resolve(_ context.Context, ref string) (string, error) {
	digest, ok := r.byRef[ref]
	if !ok {
		return "", fmt.Errorf("Core restore attempted to resolve unbacked image reference %s", ref)
	}
	return digest, nil
}
