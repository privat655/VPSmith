package sourcelibrary

import (
	"context"
	"errors"
	"os"

	"github.com/privat655/VPSmith/internal/managementstate"
)

// CoreCandidateRef identifies exactly one immutable Core candidate. An empty
// reference selects the current embedded Core release. Mutable workspaces must
// first cross the explicit AdoptCoreWorkspace seam.
type CoreCandidateRef struct {
	SnapshotID  managementstate.SourceSnapshotID
	WorkspaceID managementstate.SourceWorkspaceID
}

// FreezeCoreCandidate returns immutable, hash-verified Core source bytes. A
// mutable workspace never crosses the Source Library -> Deployment Compiler
// seam directly and is never adopted merely because a target plan was opened.
func (l *Library) FreezeCoreCandidate(ctx context.Context, ref CoreCandidateRef) (FrozenSnapshot, error) {
	if l == nil {
		return FrozenSnapshot{}, errors.New("source library is required")
	}
	if ref.SnapshotID != "" && ref.WorkspaceID != "" {
		return FrozenSnapshot{}, errors.New("Core candidate must select one immutable snapshot")
	}
	if ref.WorkspaceID != "" {
		return FrozenSnapshot{}, errors.New("mutable Core workspace must be explicitly adopted before it can be planned")
	}
	if ref.SnapshotID == "" {
		return l.CurrentEmbedded(ctx, managementstate.SourceCore)
	}
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

// AdoptCoreWorkspace is the visible local promotion step between a mutable
// merge/customization candidate and target planning. It refreshes the workspace
// hash, snapshots those exact bytes immutably, and returns the snapshot the user
// can deliberately select for a later Core plan. It never deploys anything.
func (l *Library) AdoptCoreWorkspace(ctx context.Context, id managementstate.SourceWorkspaceID) (FrozenSnapshot, error) {
	if l == nil {
		return FrozenSnapshot{}, errors.New("source library is required")
	}
	if id == "" {
		return FrozenSnapshot{}, errors.New("Core workspace id is required")
	}
	workspace, err := l.workspace(ctx, id)
	if err != nil {
		return FrozenSnapshot{}, err
	}
	if workspace.Kind != managementstate.SourceCore {
		return FrozenSnapshot{}, errors.New("selected source workspace is not Core")
	}
	refreshed, err := l.RefreshWorkspace(ctx, id)
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
