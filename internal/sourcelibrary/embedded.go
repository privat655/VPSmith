package sourcelibrary

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/privat655/VPSmith/internal/managementstate"
	"github.com/privat655/VPSmith/internal/releaseinfo"
)

// FrozenSnapshot is verified immutable source material. Consumers can read the
// snapshot through FS but cannot mutate the source library through this API.
type FrozenSnapshot struct {
	Snapshot
	FS fs.FS
}

// CurrentEmbedded returns the released embedded source identified by the
// current platform manifest. ImportEmbedded must have published that exact
// source into the local immutable source library first.
func (l *Library) CurrentEmbedded(ctx context.Context, kind managementstate.SourceKind) (FrozenSnapshot, error) {
	if l == nil {
		return FrozenSnapshot{}, errors.New("source library is required")
	}
	info, err := releaseinfo.Load(l.embeddedRoot)
	if err != nil {
		return FrozenSnapshot{}, err
	}
	var released releaseinfo.Source
	switch kind {
	case managementstate.SourceCloudInit:
		released = info.Embedded.CloudInit
	case managementstate.SourceCore:
		released = info.Embedded.Core
	case managementstate.SourceEmbeddedN8N:
		released = info.Embedded.N8N
	default:
		return FrozenSnapshot{}, fmt.Errorf("source kind %s has no embedded release", kind)
	}
	state, err := l.state.Sources(ctx)
	if err != nil {
		return FrozenSnapshot{}, err
	}
	for _, artifact := range state.Artifacts {
		if artifact.Kind != kind || artifact.Version != released.Version || artifact.SHA256 != released.SHA256 || artifact.Commit != "" {
			continue
		}
		if err := l.verifySnapshot(artifact); err != nil {
			return FrozenSnapshot{}, err
		}
		return FrozenSnapshot{
			Snapshot: snapshotFromState(artifact),
			FS:       os.DirFS(l.snapshotPath(artifact.SHA256)),
		}, nil
	}
	return FrozenSnapshot{}, fmt.Errorf("current embedded %s source is not imported", kind)
}
