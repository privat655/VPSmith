package targetgateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/privat655/VPSmith/internal/managementstate"
)

const maxLogLines = 2000

var ErrTrustRequired = errors.New("ssh host key is not confirmed")

type SSHIdentity struct {
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

type HostKeyObservation struct {
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

type HostKeyMismatchError struct {
	ExpectedKey         string
	ExpectedFingerprint string
	ObservedKey         string
	ObservedFingerprint string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("ssh host key changed: expected %s, observed %s", e.ExpectedFingerprint, e.ObservedFingerprint)
}

type HostKeyConfirmationError struct {
	ConfirmedFingerprint string
	ObservedFingerprint  string
}

func (e *HostKeyConfirmationError) Error() string {
	return fmt.Sprintf("ssh host key changed before confirmation: confirmed %s, observed %s", e.ConfirmedFingerprint, e.ObservedFingerprint)
}

type LogKind string

const (
	LogJournalUnit     LogKind = "journal-unit"
	LogPodmanContainer LogKind = "podman-container"
)

type LogRequest struct {
	Kind  LogKind `json:"kind"`
	Name  string  `json:"name"`
	Scope string  `json:"scope,omitempty"`
	Lines int     `json:"lines"`
}

type LogChunk struct {
	Stream string
	Data   []byte
}

type Gateway struct {
	state     *managementstate.Store
	transport transport
	now       func() time.Time
}

type endpoint struct {
	Address string
	SSHUser string
}

type session struct {
	endpoint
	HostKey      string
	IdentitySeed []byte
}

type transport interface {
	ObserveHostKey(context.Context, endpoint) (HostKeyObservation, error)
	Inspect(context.Context, session) (managementstate.ObservedState, error)
	Logs(context.Context, session, LogRequest, func(LogChunk) error) error
}

func New(state *managementstate.Store, runtimeDir string) (*Gateway, error) {
	if state == nil {
		return nil, errors.New("management state is required")
	}
	runtimeDir = strings.TrimSpace(runtimeDir)
	if runtimeDir == "" || !filepath.IsAbs(runtimeDir) {
		return nil, errors.New("absolute ssh runtime directory is required")
	}
	return &Gateway{state: state, transport: newSSHTransport(runtimeDir), now: time.Now}, nil
}

func newGateway(state *managementstate.Store, transport transport, now func() time.Time) *Gateway {
	if now == nil {
		now = time.Now
	}
	return &Gateway{state: state, transport: transport, now: now}
}

// EnsureIdentity atomically creates one Ed25519 administrative identity for a
// target when missing. Only the 32-byte private seed is persisted, encrypted by
// management state; the public key is derived and returned to the caller.
func (g *Gateway) EnsureIdentity(ctx context.Context, targetID managementstate.TargetID) (SSHIdentity, error) {
	if targetID == "" {
		return SSHIdentity{}, errors.New("target id is required")
	}
	var selected managementstate.SecretID
	err := g.state.Change(ctx, func(change *managementstate.Change) error {
		existing, err := change.SSHIdentitySecretID(targetID)
		if err != nil {
			return err
		}
		if existing != "" {
			selected = existing
			return nil
		}
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return fmt.Errorf("generate ssh ed25519 seed: %w", err)
		}
		defer zero(seed)
		id, err := change.CreateSecret("ssh-admin:"+string(targetID), managementstate.SecretGenerated)
		if err != nil {
			return err
		}
		if err := change.SetSecret(id, seed); err != nil {
			return err
		}
		if err := change.SetSSHIdentity(targetID, id); err != nil {
			return err
		}
		selected = id
		return nil
	})
	if err != nil {
		return SSHIdentity{}, fmt.Errorf("ensure target ssh identity: %w", err)
	}
	seed, err := g.resolveSeed(ctx, selected)
	if err != nil {
		return SSHIdentity{}, err
	}
	defer zero(seed)
	return publicIdentity(string(targetID), seed)
}

// ObserveHostKey reads the currently offered key without changing trust state.
func (g *Gateway) ObserveHostKey(ctx context.Context, targetID managementstate.TargetID) (HostKeyObservation, error) {
	target, err := g.target(ctx, targetID)
	if err != nil {
		return HostKeyObservation{}, err
	}
	observation, err := g.transport.ObserveHostKey(ctx, endpoint{Address: target.Address, SSHUser: target.SSHUser})
	if err != nil {
		return HostKeyObservation{}, fmt.Errorf("observe ssh host key: %w", err)
	}
	return observation, nil
}

// ConfirmHostKey re-observes the host key before persisting the exact confirmed
// key. A stale UI observation can therefore never silently establish trust.
func (g *Gateway) ConfirmHostKey(ctx context.Context, targetID managementstate.TargetID, confirmed HostKeyObservation) error {
	if err := validateObservation(confirmed); err != nil {
		return err
	}
	target, err := g.target(ctx, targetID)
	if err != nil {
		return err
	}
	observed, err := g.transport.ObserveHostKey(ctx, endpoint{Address: target.Address, SSHUser: target.SSHUser})
	if err != nil {
		return fmt.Errorf("re-observe ssh host key: %w", err)
	}
	if !sameObservation(confirmed, observed) {
		return &HostKeyConfirmationError{ConfirmedFingerprint: confirmed.Fingerprint, ObservedFingerprint: observed.Fingerprint}
	}
	if target.SSHTrust == managementstate.TrustConfirmed {
		if target.SSHHostKey == observed.PublicKey && target.SSHHostFingerprint == observed.Fingerprint {
			return nil
		}
		return &HostKeyMismatchError{
			ExpectedKey: target.SSHHostKey, ExpectedFingerprint: target.SSHHostFingerprint,
			ObservedKey: observed.PublicKey, ObservedFingerprint: observed.Fingerprint,
		}
	}
	return g.state.Change(ctx, func(change *managementstate.Change) error {
		return change.SetSSHTrust(targetID, observed.PublicKey, observed.Fingerprint, managementstate.TrustConfirmed)
	})
}

// ResetTrust only clears local trust. It does not connect to or modify the VPS.
func (g *Gateway) ResetTrust(ctx context.Context, targetID managementstate.TargetID) error {
	return g.state.Change(ctx, func(change *managementstate.Change) error {
		return change.SetSSHTrust(targetID, "", "", managementstate.TrustUnknown)
	})
}

// Inspect performs only read operations through the transport, normalizes the
// result and records that observed state locally after a successful inspection.
func (g *Gateway) Inspect(ctx context.Context, targetID managementstate.TargetID) (managementstate.ObservedState, error) {
	sess, err := g.strictSession(ctx, targetID)
	if err != nil {
		return managementstate.ObservedState{}, err
	}
	defer zero(sess.IdentitySeed)
	observed, err := g.transport.Inspect(ctx, sess)
	if err != nil {
		return managementstate.ObservedState{}, fmt.Errorf("inspect target: %w", err)
	}
	observed.ObservedAt = g.now().UTC().Format(time.RFC3339Nano)
	managementstate.NormalizeObservedState(&observed)
	if err := g.state.Change(ctx, func(change *managementstate.Change) error {
		return change.RecordObservedState(targetID, observed)
	}); err != nil {
		return managementstate.ObservedState{}, fmt.Errorf("record target inspection: %w", err)
	}
	return observed, nil
}

// Logs streams bounded read-only logs directly from the target. Log contents
// are deliberately not persisted in management state.
func (g *Gateway) Logs(ctx context.Context, targetID managementstate.TargetID, request LogRequest, consume func(LogChunk) error) error {
	if consume == nil {
		return errors.New("log consumer is required")
	}
	if request.Kind != LogJournalUnit && request.Kind != LogPodmanContainer {
		return errors.New("unsupported log kind")
	}
	request.Name = strings.TrimSpace(request.Name)
	if !safeObjectName(request.Name) {
		return errors.New("invalid log object name")
	}
	if request.Lines <= 0 || request.Lines > maxLogLines {
		return fmt.Errorf("log lines must be between 1 and %d", maxLogLines)
	}
	sess, err := g.strictSession(ctx, targetID)
	if err != nil {
		return err
	}
	defer zero(sess.IdentitySeed)
	return g.transport.Logs(ctx, sess, request, consume)
}

func (g *Gateway) strictSession(ctx context.Context, targetID managementstate.TargetID) (session, error) {
	target, err := g.target(ctx, targetID)
	if err != nil {
		return session{}, err
	}
	if target.SSHTrust != managementstate.TrustConfirmed || target.SSHHostKey == "" || target.SSHHostFingerprint == "" {
		return session{}, ErrTrustRequired
	}
	observed, err := g.transport.ObserveHostKey(ctx, endpoint{Address: target.Address, SSHUser: target.SSHUser})
	if err != nil {
		return session{}, fmt.Errorf("verify ssh host key: %w", err)
	}
	if target.SSHHostKey != observed.PublicKey || target.SSHHostFingerprint != observed.Fingerprint {
		return session{}, &HostKeyMismatchError{
			ExpectedKey: target.SSHHostKey, ExpectedFingerprint: target.SSHHostFingerprint,
			ObservedKey: observed.PublicKey, ObservedFingerprint: observed.Fingerprint,
		}
	}
	if target.SSHIdentitySecretID == "" {
		return session{}, errors.New("target ssh identity is missing")
	}
	seed, err := g.resolveSeed(ctx, target.SSHIdentitySecretID)
	if err != nil {
		return session{}, err
	}
	return session{
		endpoint: endpoint{Address: target.Address, SSHUser: target.SSHUser},
		HostKey:  target.SSHHostKey, IdentitySeed: seed,
	}, nil
}

func (g *Gateway) resolveSeed(ctx context.Context, id managementstate.SecretID) ([]byte, error) {
	var seed []byte
	if err := g.state.ResolveSecret(ctx, id, func(secret managementstate.SecretMaterial) error {
		seed = secret.Bytes()
		return nil
	}); err != nil {
		return nil, fmt.Errorf("resolve target ssh identity: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		zero(seed)
		return nil, errors.New("target ssh identity has invalid format")
	}
	return seed, nil
}

func (g *Gateway) target(ctx context.Context, id managementstate.TargetID) (managementstate.Target, error) {
	if id == "" {
		return managementstate.Target{}, errors.New("target id is required")
	}
	snapshot, err := g.state.Snapshot(ctx)
	if err != nil {
		return managementstate.Target{}, fmt.Errorf("read management state: %w", err)
	}
	for _, target := range snapshot.Targets {
		if target.ID == id {
			return target, nil
		}
	}
	return managementstate.Target{}, fmt.Errorf("target %s does not exist", id)
}

func validateObservation(value HostKeyObservation) error {
	if strings.TrimSpace(value.Algorithm) == "" || strings.TrimSpace(value.PublicKey) == "" || strings.TrimSpace(value.Fingerprint) == "" {
		return errors.New("complete host key observation is required")
	}
	return nil
}

func sameObservation(a, b HostKeyObservation) bool {
	return a.Algorithm == b.Algorithm && a.PublicKey == b.PublicKey && a.Fingerprint == b.Fingerprint
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
