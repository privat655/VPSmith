package deployment

import (
	"context"
	"errors"
	"strings"
)

// CoreCandidateInspection is the read-only contract information needed before
// a Core update may create its mandatory backup. It validates the exact frozen
// Core package through the same core.json parser used by compilation, without
// resolving images or assembling an execution bundle.
type CoreCandidateInspection struct {
	Version      string
	CoreContract string
}

func (c *Compiler) InspectCoreCandidate(ctx context.Context, source FrozenCoreSource) (CoreCandidateInspection, error) {
	if err := ctx.Err(); err != nil {
		return CoreCandidateInspection{}, err
	}
	if c == nil {
		return CoreCandidateInspection{}, errors.New("deployment compiler is required")
	}
	if strings.TrimSpace(source.SourceID) == "" || strings.TrimSpace(source.Version) == "" || !validSHA256(source.PackageSHA256) || source.PackageFS == nil {
		return CoreCandidateInspection{}, errors.New("complete frozen Core source identity is required")
	}
	definition, err := compileCoreDefinition(source.PackageFS, source.Version)
	if err != nil {
		return CoreCandidateInspection{}, err
	}
	return CoreCandidateInspection{Version: definition.CoreVersion, CoreContract: definition.CoreContract}, nil
}
