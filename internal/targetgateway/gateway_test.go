package targetgateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/privat655/VPSmith/internal/managementstate"
)

type fakeTransport struct {
	offered      HostKeyObservation
	facts        managementstate.ObservedState
	log          []byte
	remoteState  string
	inspectCalls int
	logCalls     int
	observeCalls int
}

func (f *fakeTransport) ObserveHostKey(context.Context, endpoint) (HostKeyObservation, error) {
	f.observeCalls++
	return f.offered, nil
}

func (f *fakeTransport) Inspect(_ context.Context, sess session) (managementstate.ObservedState, error) {
	f.inspectCalls++
	if len(sess.IdentitySeed) != ed25519.SeedSize || sess.HostKey == "" {
		return managementstate.ObservedState{}, errors.New("strict session missing identity or host key")
	}
	return cloneObserved(f.facts), nil
}

func (f *fakeTransport) Logs(_ context.Context, sess session, request LogRequest, consume func(LogChunk) error) error {
	f.logCalls++
	if len(sess.IdentitySeed) != ed25519.SeedSize || sess.HostKey == "" {
		return errors.New("strict session missing identity or host key")
	}
	return consume(LogChunk{Data: append([]byte(nil), f.log...)})
}

func TestEnsureIdentityIsStablePerTargetAndUniqueAcrossTargets(t *testing.T) {
	ctx := context.Background()
	store := newTargetStore(t, "target-a", "target-b")
	gateway := newGateway(store, &fakeTransport{}, time.Now)

	first, err := gateway.EnsureIdentity(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	again, err := gateway.EnsureIdentity(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	other, err := gateway.EnsureIdentity(ctx, "target-b")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("same target identity changed: first=%#v again=%#v", first, again)
	}
	if first.PublicKey == other.PublicKey || first.Fingerprint == other.Fingerprint {
		t.Fatal("different targets received the same ssh identity")
	}
	if !strings.HasPrefix(first.PublicKey, "ssh-ed25519 ") || !strings.HasSuffix(first.PublicKey, " vpsmith:target-a") {
		t.Fatalf("unexpected public key format: %q", first.PublicKey)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Secrets) != 2 || len(snapshot.Targets) != 2 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	for _, target := range snapshot.Targets {
		if target.SSHIdentitySecretID == "" {
			t.Fatalf("target %s has no identity secret reference", target.ID)
		}
	}
	encoded := mustJSON(t, snapshot)
	if strings.Contains(encoded, strings.Fields(first.PublicKey)[1]) || strings.Contains(encoded, strings.Fields(other.PublicKey)[1]) {
		t.Fatal("derived public key leaked into normal management state")
	}
}

func TestTOFURequiresExplicitConfirmationAndBlocksChangedHostKeyUntilReset(t *testing.T) {
	ctx := context.Background()
	store := newTargetStore(t, "target-a")
	firstKey := testHostObservation(1)
	secondKey := testHostObservation(2)
	remote := &fakeTransport{offered: firstKey, facts: richObservedFacts(), remoteState: "immutable-target"}
	gateway := newGateway(store, remote, time.Now)
	if _, err := gateway.EnsureIdentity(ctx, "target-a"); err != nil {
		t.Fatal(err)
	}

	observed, err := gateway.ObserveHostKey(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	if observed != firstKey {
		t.Fatalf("observation = %#v", observed)
	}
	target := onlyTarget(t, store)
	if target.SSHTrust != managementstate.TrustUnknown || target.SSHHostKey != "" {
		t.Fatalf("observation persisted trust: %#v", target)
	}
	if _, err := gateway.Inspect(ctx, "target-a"); !errors.Is(err, ErrTrustRequired) {
		t.Fatalf("inspect before confirmation error = %v", err)
	}

	if err := gateway.ConfirmHostKey(ctx, "target-a", observed); err != nil {
		t.Fatal(err)
	}
	target = onlyTarget(t, store)
	if target.SSHTrust != managementstate.TrustConfirmed || target.SSHHostKey != firstKey.PublicKey || target.SSHHostFingerprint != firstKey.Fingerprint {
		t.Fatalf("confirmed target = %#v", target)
	}
	if _, err := gateway.Inspect(ctx, "target-a"); err != nil {
		t.Fatal(err)
	}

	remote.offered = secondKey
	_, err = gateway.Inspect(ctx, "target-a")
	var mismatch *HostKeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("changed host key error = %v", err)
	}
	if mismatch.ExpectedFingerprint != firstKey.Fingerprint || mismatch.ObservedFingerprint != secondKey.Fingerprint {
		t.Fatalf("mismatch = %#v", mismatch)
	}
	target = onlyTarget(t, store)
	if target.SSHTrust != managementstate.TrustConfirmed || target.SSHHostKey != firstKey.PublicKey {
		t.Fatalf("mismatch mutated trust: %#v", target)
	}

	if err := gateway.ResetTrust(ctx, "target-a"); err != nil {
		t.Fatal(err)
	}
	target = onlyTarget(t, store)
	if target.SSHTrust != managementstate.TrustUnknown || target.SSHHostKey != "" || target.SSHHostFingerprint != "" {
		t.Fatalf("reset target = %#v", target)
	}
	newObservation, err := gateway.ObserveHostKey(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, "target-a", newObservation); err != nil {
		t.Fatal(err)
	}
	if onlyTarget(t, store).SSHHostKey != secondKey.PublicKey {
		t.Fatal("new key was not confirmed after explicit reset")
	}
	if remote.remoteState != "immutable-target" {
		t.Fatal("TOFU operations mutated the target")
	}
}

func TestConfirmationReobservesAndRejectsStaleFingerprint(t *testing.T) {
	ctx := context.Background()
	store := newTargetStore(t, "target-a")
	firstKey := testHostObservation(1)
	secondKey := testHostObservation(2)
	remote := &fakeTransport{offered: firstKey}
	gateway := newGateway(store, remote, time.Now)

	observation, err := gateway.ObserveHostKey(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	remote.offered = secondKey
	err = gateway.ConfirmHostKey(ctx, "target-a", observation)
	var stale *HostKeyConfirmationError
	if !errors.As(err, &stale) {
		t.Fatalf("confirmation error = %v", err)
	}
	if onlyTarget(t, store).SSHTrust != managementstate.TrustUnknown {
		t.Fatal("stale confirmation persisted trust")
	}
}

func TestInspectPersistsStructuredDeterministicFactsWithoutTargetMutation(t *testing.T) {
	ctx := context.Background()
	store := newTargetStore(t, "target-a")
	key := testHostObservation(7)
	facts := richObservedFacts()
	remote := &fakeTransport{offered: key, facts: facts, remoteState: "files=v1;runtime=v1"}
	times := []time.Time{
		time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 16, 10, 0, 1, 0, time.UTC),
	}
	clock := func() time.Time {
		value := times[0]
		if len(times) > 1 {
			times = times[1:]
		}
		return value
	}
	gateway := newGateway(store, remote, clock)
	if _, err := gateway.EnsureIdentity(ctx, "target-a"); err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, "target-a", key); err != nil {
		t.Fatal(err)
	}
	before := remote.remoteState
	first, err := gateway.Inspect(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := gateway.Inspect(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	if remote.remoteState != before {
		t.Fatal("inspection mutated target files or runtime")
	}
	if remote.inspectCalls != 2 {
		t.Fatalf("inspect calls = %d", remote.inspectCalls)
	}
	if !first.Host.Reachable || !first.Host.SSH || !first.CloudInit.Present || !first.Core.Present || len(first.Modules) != 2 || len(first.LinkNetworks) != 1 {
		t.Fatalf("structured inspection incomplete: %#v", first)
	}
	first.ObservedAt = ""
	second.ObservedAt = ""
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("unchanged target inspection is not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if !sort.SliceIsSorted(second.Modules, func(i, j int) bool { return second.Modules[i].InstanceID < second.Modules[j].InstanceID }) {
		t.Fatal("module observations are not normalized")
	}
	persisted := onlyTarget(t, store).Observed
	if persisted.ObservedAt == "" || !persisted.Core.Present || len(persisted.Modules) != 2 {
		t.Fatalf("persisted observed state = %#v", persisted)
	}
}

func TestMissingCoreAndModulesAreNormalObservedState(t *testing.T) {
	ctx := context.Background()
	store := newTargetStore(t, "target-a")
	key := testHostObservation(8)
	remote := &fakeTransport{
		offered: key,
		facts: managementstate.ObservedState{
			Host: managementstate.HostObservedState{Reachable: true, SSH: true},
			Core: managementstate.CoreObservedState{Present: false},
		},
	}
	gateway := newGateway(store, remote, time.Now)
	if _, err := gateway.EnsureIdentity(ctx, "target-a"); err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, "target-a", key); err != nil {
		t.Fatal(err)
	}
	observed, err := gateway.Inspect(ctx, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	if observed.Core.Present || len(observed.Modules) != 0 {
		t.Fatalf("missing core/modules = %#v", observed)
	}
}

func TestLogsAreBoundedDirectAndDoNotChangePersistedOrRemoteState(t *testing.T) {
	ctx := context.Background()
	store := newTargetStore(t, "target-a")
	key := testHostObservation(9)
	remote := &fakeTransport{offered: key, log: []byte("line one\nline two\n"), remoteState: "unchanged"}
	gateway := newGateway(store, remote, time.Now)
	if _, err := gateway.EnsureIdentity(ctx, "target-a"); err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfirmHostKey(ctx, "target-a", key); err != nil {
		t.Fatal(err)
	}
	before := onlyTarget(t, store)
	var received bytes.Buffer
	if err := gateway.Logs(ctx, "target-a", LogRequest{Kind: LogJournalUnit, Name: "vpsmith-core.service", Scope: "user", Lines: 200}, func(chunk LogChunk) error {
		_, _ = received.Write(chunk.Data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if received.String() != string(remote.log) || remote.logCalls != 1 {
		t.Fatalf("logs = %q calls=%d", received.String(), remote.logCalls)
	}
	after := onlyTarget(t, store)
	if !reflect.DeepEqual(before, after) || remote.remoteState != "unchanged" {
		t.Fatal("log retrieval mutated local target state or remote state")
	}
	if err := gateway.Logs(ctx, "target-a", LogRequest{Kind: LogJournalUnit, Name: "vpsmith-core.service", Lines: maxLogLines + 1}, func(LogChunk) error { return nil }); err == nil {
		t.Fatal("unbounded log request was accepted")
	}
}

func TestGatewayHasNoArbitraryCommandInterface(t *testing.T) {
	allowed := map[string]bool{
		"EnsureIdentity": true,
		"ObserveHostKey": true,
		"ConfirmHostKey": true,
		"ResetTrust":     true,
		"Inspect":        true,
		"Logs":           true,
	}
	typeOfGateway := reflect.TypeOf(&Gateway{})
	for i := 0; i < typeOfGateway.NumMethod(); i++ {
		method := typeOfGateway.Method(i)
		if !allowed[method.Name] {
			t.Fatalf("unexpected public target gateway method %s exposes surface beyond step 4", method.Name)
		}
	}
	if typeOfGateway.NumMethod() != len(allowed) {
		t.Fatalf("gateway methods = %d want %d", typeOfGateway.NumMethod(), len(allowed))
	}
}

func newTargetStore(t *testing.T, ids ...managementstate.TargetID) *managementstate.Store {
	t.Helper()
	store, err := managementstate.NewMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Change(context.Background(), func(change *managementstate.Change) error {
		for i, id := range ids {
			if err := change.CreateTarget(managementstate.TargetRegistration{
				ID: id, Address: "203.0.113." + string(rune('1'+i)), SSHUser: "dev", SSHTrust: managementstate.TrustUnknown,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return store
}

func onlyTarget(t *testing.T, store *managementstate.Store) managementstate.Target {
	t.Helper()
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Targets) != 1 {
		t.Fatalf("targets = %d", len(snapshot.Targets))
	}
	return snapshot.Targets[0]
}

func testHostObservation(marker byte) HostKeyObservation {
	seed := bytes.Repeat([]byte{marker}, ed25519.SeedSize)
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	blob := sshPublicBlob(publicKey)
	return HostKeyObservation{
		Algorithm:   sshEd25519,
		PublicKey:   sshEd25519 + " " + base64.StdEncoding.EncodeToString(blob),
		Fingerprint: sshFingerprint(blob),
	}
}

func richObservedFacts() managementstate.ObservedState {
	return managementstate.ObservedState{
		Host: managementstate.HostObservedState{
			Reachable: true, SSH: true, Hostname: "vps-1", OSID: "debian", OSVersion: "12", Kernel: "Linux 6.1",
			RootFilesystem: managementstate.FilesystemObservedState{TotalBytes: 1000, AvailableBytes: 400},
			Memory:         managementstate.MemoryObservedState{TotalBytes: 2000, AvailableBytes: 1000},
			Swap:           managementstate.MemoryObservedState{TotalBytes: 512, AvailableBytes: 256},
			UFWActive:      true, Fail2banActive: true,
		},
		CloudInit: managementstate.CloudInitObservedState{Present: true, Status: "ok", Version: "1", FinishedAt: "2026-08-16T09:00:00Z"},
		Core: managementstate.CoreObservedState{
			Present: true, SourceID: "core-src-1", Version: "1.0.0", PackageSHA256: strings.Repeat("a", 64), Running: true,
			Podman:           managementstate.PodmanObservedState{Present: true, Rootless: true, CgroupVersion: "v2", RootlessNetworkCmd: "pasta"},
			Units:            []managementstate.UnitObservedState{{Name: "z.service", Present: true, Running: true}, {Name: "a.service", Present: true, Running: true}},
			Containers:       []managementstate.ContainerObservedState{{Name: "caddy", Present: true, Running: true, Networks: []string{"z", "a"}}},
			Networks:         []managementstate.NetworkObservedState{{Name: "core", Present: true, Members: []string{"caddy", "authelia"}}},
			Caddy:            managementstate.ServiceObservedState{Present: true, Running: true, ConfigValid: true},
			Authelia:         managementstate.ServiceObservedState{Present: true, Running: true},
			ExecutionProofs:  []managementstate.ExecutionProofObservedState{{ID: "exec-1", Kind: "installation", Outcome: "success", SHA256: strings.Repeat("b", 64)}},
			ManagedArtifacts: []managementstate.ManagedArtifactObservedState{{Path: "/etc/vpsmith/core.conf", Present: true, SHA256: strings.Repeat("c", 64)}},
		},
		Modules: []managementstate.ModuleObservedState{
			{Present: true, InstanceID: "module-z", PackageID: "pkg-z", Version: "1", Running: true, Health: "healthy"},
			{Present: true, InstanceID: "module-a", PackageID: "pkg-a", Version: "1", Running: true, Health: "healthy"},
		},
		LinkNetworks: []managementstate.LinkNetworkObservedState{{Name: "link-a", Present: true, Members: []string{"module-z", "module-a"}}},
	}
}

func cloneObserved(value managementstate.ObservedState) managementstate.ObservedState {
	// The fake deliberately round-trips through JSON so callers cannot mutate
	// the sandbox's source-of-truth slices by aliasing them.
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var cloned managementstate.ObservedState
	if err := json.Unmarshal(raw, &cloned); err != nil {
		panic(err)
	}
	return cloned
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
