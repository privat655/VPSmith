package backuprestore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/privat655/VPSmith/internal/managementstate"
)

// CataloguedRestore is a verified long-term backup opened for one explicit
// restore operation. All decrypted bytes remain below the Manager scratch
// directory and disappear when Close is called.
type CataloguedRestore struct {
	Manifest      Manifest
	CandidateRoot string
	PayloadPath   string
	PayloadSHA256 string
	PayloadSize   int64
	workDir       string
}

func (p *CataloguedRestore) Close() error {
	if p == nil || p.workDir == "" {
		return nil
	}
	err := os.RemoveAll(p.workDir)
	p.workDir = ""
	p.CandidateRoot = ""
	p.PayloadPath = ""
	p.PayloadSHA256 = ""
	p.PayloadSize = 0
	return err
}

// PrepareRestoreArtifact resolves a catalogue identity, verifies the encrypted
// envelope through InspectArtifact, and extracts a replace-not-merge candidate
// in volatile scratch. The verified payload archive is retained in the same
// scratch tree so a lifecycle can stream those exact bytes to a target without
// re-opening or reconstructing the backup path.
func (m *Manager) PrepareRestoreArtifact(ctx context.Context, id managementstate.BackupArtifactID, expected managementstate.BackupArtifactType, passphrase []byte) (*CataloguedRestore, error) {
	if m == nil {
		return nil, errors.New("backup/restore manager is required")
	}
	inspection, err := m.InspectArtifact(ctx, id, expected, passphrase)
	if err != nil {
		return nil, err
	}
	work := inspection.workDir
	fail := func(err error) (*CataloguedRestore, error) {
		_ = inspection.Close()
		return nil, err
	}
	candidate := filepath.Join(work, "restore-candidate")
	if err := ExtractTarZst(inspection.PayloadPath, candidate, ArchiveOptions{}); err != nil {
		return fail(fmt.Errorf("prepare replace-not-merge candidate: %w", err))
	}
	sha, err := fileSHA256(inspection.PayloadPath)
	if err != nil {
		return fail(fmt.Errorf("hash verified restore payload: %w", err))
	}
	info, err := os.Stat(inspection.PayloadPath)
	if err != nil {
		return fail(fmt.Errorf("inspect verified restore payload: %w", err))
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return fail(errors.New("verified restore payload is not a non-empty regular file"))
	}
	manifest := inspection.Manifest
	payload := inspection.PayloadPath
	inspection.workDir = ""
	inspection.PayloadPath = ""
	return &CataloguedRestore{
		Manifest:      manifest,
		CandidateRoot: candidate,
		PayloadPath:   payload,
		PayloadSHA256: sha,
		PayloadSize:   info.Size(),
		workDir:       work,
	}, nil
}
