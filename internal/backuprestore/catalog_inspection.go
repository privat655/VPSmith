package backuprestore

import (
	"context"
	"errors"
	"fmt"

	"github.com/privat655/VPSmith/internal/managementstate"
)

// InspectArtifact resolves a catalogue identity to its canonical bytes and then
// performs the same fail-closed envelope validation as Inspect. Callers never
// reconstruct backup paths from catalogue metadata themselves.
func (m *Manager) InspectArtifact(ctx context.Context, id managementstate.BackupArtifactID, expected managementstate.BackupArtifactType, passphrase []byte) (*Inspection, error) {
	if m == nil {
		return nil, errors.New("backup/restore manager is required")
	}
	if id == "" {
		return nil, errors.New("backup artifact id is required")
	}
	metadata, err := m.catalogEntry(ctx, id)
	if err != nil {
		return nil, err
	}
	if metadata.Type != expected {
		return nil, fmt.Errorf("backup artifact %s has type %s, expected %s", id, metadata.Type, expected)
	}
	filename, err := m.locationPath(metadata.LocationRef)
	if err != nil {
		return nil, err
	}
	actualSHA, err := fileSHA256(filename)
	if err != nil {
		return nil, fmt.Errorf("verify catalogued backup bytes: %w", err)
	}
	if metadata.SHA256 == "" || actualSHA != metadata.SHA256 {
		return nil, errors.New("catalogued backup sha256 mismatch")
	}
	inspection, err := m.Inspect(ctx, filename, expected, passphrase)
	if err != nil {
		return nil, err
	}
	if inspection.Manifest.ArtifactID != id || inspection.Manifest.TargetID != metadata.TargetID {
		_ = inspection.Close()
		return nil, errors.New("catalogued backup manifest identity mismatch")
	}
	return inspection, nil
}
