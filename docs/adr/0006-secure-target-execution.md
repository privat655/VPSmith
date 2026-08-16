# ADR 0006 — Step 6 secure target execution and proof

## Status

Accepted for Step 6.

## Context

Step 5 produces immutable, deterministic execution bundles. Step 6 must execute one approved bundle on exactly the SSH target selected by VPSmith, without adding a permanent target agent or a second desired-state source. The same mechanism must work for the first Core installation, when only Cloud-init is present, and later for module/core migrations and read-only validation.

The authoritative VPSmith contracts require SHA-256 verification before execution, target/precondition checks before productive mutation, one structural writer at a time, late secret delivery, exact step order, immediate stop on action failure, an atomic target-side proof, and reconciliation after transport loss instead of blind retry. Validation uses the same history/integrity machinery but must remain read-only.

## Decision

### Deep execution seam

`internal/execution` exposes only two behaviours: execute an already approved bundle and reconcile a known run. It owns ordering of upload, start, observation, late secret resolution, terminal-history import, ambiguous transport handling and retry policy. The target gateway is only an adapter for narrowly typed SSH transport operations.

`targetgateway.NewExecutionTarget` returns the transport interface consumed by `internal/execution`; the general `targetgateway.Gateway` does not gain a generic remote-command or structural-mutation method. Direct module runtime operations are exposed separately through `targetgateway.NewRuntimeController` and are resolved from target inventory rather than caller-supplied unit/container/command names.

### Bundle-local runner

Every format-v2 bundle contains the exact `runtime/runner.py` bytes. The manifest carries runner version, path and SHA-256. The runner is assembled from embedded source fragments in the VPSmith binary, but the resulting file in the bundle is a normal immutable payload covered by `SHA256SUMS` and by the outer bundle SHA-256.

The local executor verifies the TAR bytes and parses the runner identity from those verified bytes; it never trusts the mutable convenience `Bundle.Manifest` field as a start authority. The SSH start adapter rechecks the outer bundle SHA-256 and verifies that the requested runner identity matches `manifest.json` before extracting and starting the runner. The runner then validates the archive shape, manifest version and all `SHA256SUMS` entries again before productive mutation.

The runner uses only Python 3 standard-library facilities plus base host commands already required by the execution protocol. If `python3`, `systemd-run`, `tar` or the required host primitives are absent, start fails before productive mutation.

### Detached transient execution

A run is started as a one-shot transient systemd service using `systemd-run`. The service is detached from the SSH request. Therefore loss of the SSH transport after the start request never implies that the target process stopped or failed to start.

Any ambiguous start/observe/secret-transfer error is returned as `unknown`. The caller must reconcile by reading the target proof, lock and transient-unit state. `internal/execution` never issues a blind second start for that run.

This is not a permanent VPSmith agent: there is no listener, socket API, daemon or background desired-state reconciler on the target.

### Two target storage phases

Before Core exists, execution history uses the root-owned bootstrap area:

```text
/var/tmp/vpsmith-execution/
├── bundles/
├── proofs/
├── locks/
└── claims/
```

After the first successful Core bundle, the runner atomically establishes the passive Core history root:

```text
/var/lib/vpsmith/execution/
├── .active
├── bundles/
├── proofs/
├── locks/
└── claims/
```

The first Core bundle, proof and structural claim are copied into the Core history before `.active` is written. Subsequent transfers and observations select the Core root only after that marker exists.

Bundles are immutable by ID. Re-upload is accepted only when the existing bytes have the same outer SHA-256; a collision is rejected and never overwritten.

### Locks and at-most-once structural claims

All structural runs take a non-blocking exclusive `flock` on the target structural lock. Validation takes a shared lock, so read-only validations may coexist with each other but not with a structural mutation.

After preconditions pass and before secret delivery or productive steps begin, a structural run creates an immutable claim keyed by bundle ID using exclusive creation. That claim prevents a second mutating start of the same bundle after interruption or partial failure. Validation intentionally does not create this claim and may be repeated.

There is no automatic rollback. A failed or interrupted structural run is evidence for a new explicit recovery/restore operation in later lifecycle steps.

### Preconditions and drift

Preconditions are evaluated after integrity and lock checks and before secrets or productive changes. Known module version/package identities, Core identity and expected prior artifact SHA-256 values must match. Existing artifact bytes that differ from both the approved desired hash and the expected old hash are treated as drift and block replacement.

Target selection itself is bound outside the bundle to the already confirmed per-target SSH identity and stored host key. The manifest target ID must match the selected management target before upload and again inside the target runner.

### Late secret channel

Bundle manifests contain only stable secret IDs and delivery metadata. Secret values are resolved from encrypted management state only after the verified target proof reaches `awaiting-secrets`.

Values are length-framed and streamed through a root-owned FIFO under `/run/vpsmith-execution/<run-id>/`. They are never placed in the bundle, SSH command line, systemd unit properties or proof. Environment secrets become `0600` module environment files; file secrets become `0600` module secret files. The module secret directory is `0700` and owned by the configured VPSmith administrative user so the declared rootless runtime can consume it.

Validation receives secret values only for action use/redaction and does not rewrite persistent runtime secret copies. Captured action output is bounded and exact secret byte sequences are redacted before proof persistence.

### Atomic proof and reconciliation

The runner writes a JSON proof before productive work and atomically replaces it after each phase/step using temp-file write, `fsync`, `os.replace` and directory `fsync`. The proof contains run/bundle/target identity, phase, status, timestamps, per-step exit/output evidence and measured post-state artifact hashes. It never contains secret values.

Reconciliation classifies a known run from proof + lock + transient-unit state as not started, running, interrupted, failed or successful. A target proof whose run/bundle/SHA/target identity differs from the local run identity is rejected rather than imported.

The target proof is the canonical fact for what actually ran. `internal/executionstate` imports immutable bundle metadata and terminal target proofs into the local management history without turning them into desired state.

### Direct runtime operations

Start, stop and restart are not structural bundle operations. `RuntimeController.Control` accepts only target ID, module instance ID and the fixed enum `start|stop|restart`. The SSH adapter loads generated `/var/lib/vpsmith/inventory/modules.json`, resolves the exact inventoried units, validates their names/scopes, and applies the action. Stop order is reversed; start order follows inventory order; restart is deterministic stop-then-start. No desired-state write occurs.

The same generated inventory carries the primary declarative module healthcheck. `RuntimeController.Healthcheck` accepts only target ID and module instance ID. HTTP, TCP and command probes are derived from the stored inventory, not supplied by the caller. Command checks execute in the inventoried container; HTTP/TCP probes execute from that container's network namespace. Output is bounded and the operation is read-only.

## Consequences

- Core, module, restore and validation lifecycles share one execution protocol.
- An SSH disconnect can leave an operation in an unknown local state, but it cannot trigger an automatic duplicate apply.
- A partially failed structural bundle is intentionally not replayable under the same bundle identity.
- Historical execution remains byte-comparable between management station and target using SHA-256 only; no signing or PKI layer is introduced.
- The target gains passive history and transient per-run systemd units, not a permanent deployment agent.
- Runtime control remains a small inventory-bound seam and cannot be used as a generic SSH shell escape hatch.
