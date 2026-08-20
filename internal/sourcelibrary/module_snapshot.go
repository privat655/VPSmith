package sourcelibrary

import (
	"context"
	"errors"
	"os"

	"github.com/privat655/VPSmith/internal/managementstate"
)

// FreezeModuleSnapshot returns one already immutable module package by exact
// Source Library identity. It never promotes a workspace and never performs a
// remote fetch; callers must select the exact installed snapshot first.
func (l *Library) FreezeModuleSnapshot(ctx context.Context, id managementstate.SourceSnapshotID) (FrozenSnapshot, error) {
	if l == nil {
		return FrozenSnapshot{}, errors.New("source library is required")
	}
	if err := ctx.Err(); err != nil {
		return FrozenSnapshot{}, err
	}
	if id == "" {
		return FrozenSnapshot{}, errors.New("module source snapshot id is required")
	}
	artifact, err := l.artifact(ctx, id)
	if err != nil {
		return FrozenSnapshot{}, err
	}
	if artifact.Kind != managementstate.SourceEmbeddedN8N && artifact.Kind != managementstate.SourceCustomModule {
		return FrozenSnapshot{}, errors.New("selected source snapshot is not a module")
	}
	return FrozenSnapshot{
		Snapshot: snapshotFromState(artifact),
		FS:       os.DirFS(l.snapshotPath(artifact.SHA256)),
	}, nil
}
