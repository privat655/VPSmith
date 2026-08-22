package execution

import (
	"context"
	"time"

	"github.com/privat655/VPSmith/internal/executionbundle"
)

type Status string

const (
	StatusNotStarted  Status = "not-started"
	StatusRunning     Status = "running"
	StatusInterrupted Status = "interrupted"
	StatusFailed      Status = "failed"
	StatusSuccess     Status = "success"
	StatusUnknown     Status = "unknown"
)

type Run struct {
	ID           string `json:"run_id"`
	TargetID     string `json:"target_vps_id"`
	BundleID     string `json:"bundle_id"`
	BundleSHA256 string `json:"bundle_sha256"`
	Kind         string `json:"kind,omitempty"`
	Version      string `json:"version,omitempty"`
	BackupRef    string `json:"backup_ref,omitempty"`
	Status       Status `json:"status"`
	Phase        string `json:"phase,omitempty"`
}

type StepResult struct {
	ID         string `json:"id"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout,omitempty"`
	Stderr     string `json:"stderr,omitempty"`
}

type Proof struct {
	FormatVersion int            `json:"format_version"`
	RunID         string         `json:"run_id"`
	BundleID      string         `json:"bundle_id"`
	BundleSHA256  string         `json:"bundle_sha256"`
	TargetID      string         `json:"target_vps_id"`
	Kind          string         `json:"kind"`
	Status        Status         `json:"status"`
	Phase         string         `json:"phase"`
	StartedAt     string         `json:"started_at,omitempty"`
	FinishedAt    string         `json:"finished_at,omitempty"`
	Steps         []StepResult   `json:"steps,omitempty"`
	PostState     map[string]any `json:"post_state,omitempty"`
	Error         string         `json:"error,omitempty"`
}

type Observation struct {
	Proof       *Proof
	LockHeld    bool
	UnitRunning bool
}

type SecretValue struct {
	ID    string
	Value []byte
}

type StartRequest struct {
	RunID        string
	BundleID     string
	BundleSHA256 string
	TargetID     string
	Runner       executionbundle.RunnerIdentity
}

type Target interface {
	Upload(context.Context, string, executionbundle.Bundle) error
	Start(context.Context, string, StartRequest) error
	Observe(context.Context, string, string) (Observation, error)
	SendSecrets(context.Context, string, string, []SecretValue) error
}

type Secrets interface {
	Resolve(context.Context, string, func([]byte) error) error
}

type History interface {
	RegisterBundle(context.Context, Run) error
	Finished(context.Context, Run, Proof) error
}

type Options struct {
	PollInterval time.Duration
	NewRunID     func() (string, error)
}
