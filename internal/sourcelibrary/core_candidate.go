package sourcelibrary

import (
	"context"
	"errors"
	"os"

	"github.com/privat655/VPSmith/internal/managementstate"
)

// CoreCandidateRef identifies exactly one local Core candidate. An empty
// reference selects the current embedded Core release. A workspace is frozen
// to a new immutable Source Library snapshot before it can be compiled.
type CoreCandidateRef struct {
	SnapshotID  managementstate.SourceSnapshotID
	WorkspaceID managementstate.SourceWorkspaceID
}

// FreezeCoreCandidate returns immutable, hash-verified Core source bytes. A
// mutable workspace never crosses the Source Library -> Deployment Compiler
// seam directly.
func (l *Library) FreezeCoreCandidate(ctx context.Context, ref CoreCandidateRef) (FrozenSnapshot, error) {
	if l == nil {
		return FrozenSnapshot{}, errors.New("source library is required")
	}
	if ref.SnapshotID != "" && ref.WorkspaceID != "" {
		return FrozenSnapshot{}, errors.New("Core candidate must select either snapshot or workspace")
	}
	if ref.SnapshotID == "" && ref.WorkspaceID == "" {
		return l.CurrentEmbedded(ctx, managementstate.SourceCore)
	}
	if ref.SnapshotID != "" {
		artifact, err := l.artifact(ctx, ref.SnapshotID)
		if err != nil {
			return FrozenSnapshot{}, err
		}
		if artifact.Kind != managementstate.SourceCore {
			return FrozenSnapshot{}, errors.New("selected source snapshot is not Core")
		}
		return FrozenSnapshot{
			Snapshot: snapshotFromState(artifact),
			FS:       os.DirFS(l.snapshotPath(artifact.SHA256)),
		}, nil
	}

	workspace, err := l.workspace(ctx, ref.WorkspaceID)
	if err != nil {
		return FrozenSnapshot{}, err
	}
	if workspace.Kind != managementstate.SourceCore {
		return FrozenSnapshot{}, errors.New("selected source workspace is not Core")
	}
	refreshed, err := l.RefreshWorkspace(ctx, ref.WorkspaceID)
	if err != nil {
		return FrozenSnapshot{}, err
	}
	workspace, err = l.workspace(ctx, refreshed.ID)
	if err != nil {
		return FrozenSnapshot{}, err
	}
	base, err := l.artifact(ctx, workspace.BaseSourceID)
	if err != nil {
		return FrozenSnapshot{}, err
	}
	snapshot, err := l.importSnapshot(
		ctx,
		managementstate.SourceCore,
		"",
		"",
		base.Version,
		"",
		l.workspacePath(workspace),
		refreshed.SHA256,
	)
	if err != nil {
		return FrozenSnapshot{}, err
	}
	return FrozenSnapshot{
		Snapshot: snapshot,
		FS:       os.DirFS(l.snapshotPath(snapshot.SHA256)),
	}, nil
}
