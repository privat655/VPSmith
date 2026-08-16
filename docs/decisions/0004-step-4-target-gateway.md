# ADR 0004 — Step 4 target gateway, SSH trust, and read-only inspection

## Status

Accepted for Step 4.

## Context

Step 4 must establish one reusable target-VPS seam before any target mutation exists. VPSmith Studio needs one administrative SSH identity per target, explicit TOFU host-key enrollment, strict blocking after a host-key change, structured current-state facts, and direct bounded logs. The target must remain unchanged by inspection and log retrieval.

The VPSmith specs are authoritative. Existing shell implementations are evidence only.

## Primary-source validation

The implementation was checked against these upstream sources before coding:

- OpenBSD `ssh-keyscan(1)`: https://man.openbsd.org/ssh-keyscan — key scanning gathers offered public host keys without login and does not authenticate them. VPSmith therefore treats keyscan output only as an observation for explicit TOFU confirmation; it never creates trust by itself.
- OpenBSD `ssh_config(5)`: https://man.openbsd.org/OpenBSD-current/man5/ssh_config — `StrictHostKeyChecking=yes` refuses unknown/changed keys, `UserKnownHostsFile` selects the exact trust database, `IdentityAgent=none` disables agent use, `IdentitiesOnly=yes` limits authentication identities, and `UpdateHostKeys=no` prevents implicit host-key learning.
- OpenBSD `ssh(1)`: https://man.openbsd.org/ssh — `-F none` disables user and system configuration files. VPSmith also disables forwarding, interactive authentication, DNS host-key verification, and prompts.
- OpenSSH portable private-key format: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key — VPSmith derives an OpenSSH Ed25519 private-key file from the encrypted 32-byte seed only for a connection and deletes that 0600 file immediately afterward.
- Podman `info`, container inspection, and network inspection: https://docs.podman.io/en/stable/markdown/podman-info.1.html, https://docs.podman.io/en/stable/markdown/podman-container-inspect.1.html, https://docs.podman.io/en/v5.7.1/markdown/podman-network-inspect.1.html — these expose the rootless/cgroup, container state/health/network, and network membership facts required by VPSmith without lifecycle mutations.
- Caddy command line: https://caddyserver.com/docs/command-line — `caddy validate` loads/provisions the existing configuration for validation without starting the server. VPSmith only exposes this as the one fixed Caddy validation operation.
- cloud-init status documentation: https://cloudinit.readthedocs.io/en/latest/howto/status.html — cloud-init also has machine-readable status, while VPSmith's authoritative bootstrap completion fact remains its own atomic status document required by the VPSmith spec.

The research did not require changing the approved deep-module seam.

## Decision

### One deep gateway

`internal/targetgateway` owns all target transport policy. Its public domain operations are deliberately limited to:

- ensure the per-target SSH identity;
- observe a host key;
- confirm an exact observed host key;
- reset SSH trust explicitly;
- inspect read-only current state;
- retrieve bounded logs.

There is no public `Execute(command string)` surface. The production adapter may build remote command strings internally, but only from fixed typed operation shapes and conservatively validated identifiers.

### SSH identity

The existing management-state secret store remains the only private-key store. The secret value is a 32-byte Ed25519 seed. The public key is deterministic from that seed and is returned on demand for later Cloud-init generation; it is not redundantly persisted. Identity creation reads and writes the identity reference inside one serialized management-state change, making concurrent ensure calls stable.

For an SSH connection the seed is resolved, converted to an unencrypted OpenSSH private-key file with mode `0600` inside the writable management-state runtime directory, used once, zeroed in memory where practical, and removed. The long-lived persisted copy remains encrypted by management state.

### TOFU

`ObserveHostKey` uses `ssh-keyscan` only to present the currently offered key and SHA-256 fingerprint. It does not write management state.

`ConfirmHostKey` re-observes immediately and persists only if the observation is still exact. After confirmation every operation first compares the offered key with the stored exact key, then invokes OpenSSH with an ephemeral exact known-hosts file and `StrictHostKeyChecking=yes`. A mismatch returns expected and observed fingerprints and does not mutate stored trust. Trust replacement is possible only after `ResetTrust` followed by a new explicit confirmation.

The legacy `blocked` enum remains readable for schema compatibility; Step 4 does not persist it on a mismatch because doing so would itself alter the stored trust record.

### Read-only current state

The persisted `ObservedState` is expanded with direct facts for:

- host reachability/SSH, OS/kernel, root filesystem, RAM, swap, reboot-required, UFW, fail2ban;
- VPSmith Cloud-init completion status;
- Core identity, rootless Podman/cgroup facts, expected units, containers, networks, Caddy, Authelia, execution-proof identities, and managed-artifact hashes;
- module identities, expected units/containers/networks, existing container health facts, and managed-artifact hashes;
- declared link-network existence and actual members.

Missing Core or module inventory is represented as `present=false`/an empty collection, not as a transport error. Existing but malformed inventory fails closed.

Step 4 establishes only passive inventory read paths:

- `/var/lib/vpsmith/cloud-init/status`
- `/var/lib/vpsmith/inventory/core.json`
- `/var/lib/vpsmith/inventory/modules.json`
- `/var/lib/vpsmith/inventory/link-networks.json`

It deliberately does **not** choose the later runner, execution-bundle, execution-record, or lock storage paths reserved for the Step 6 runner contract. Execution-proof identities may be referenced from the passive inventory without deciding where their immutable historical payloads live.

All set-like facts are normalized before persistence, so unchanged targets produce semantically identical inspections apart from `observed_at`.

### Logs

Logs are fetched only through typed `journal-unit` or `podman-container` requests. The caller supplies a validated object name and a bounded line count (maximum 2000). Output is passed directly to the caller in chunks and is never written to the local management database.

## Consequences

- Later lifecycle code gets one SSH trust and transport implementation instead of embedding SSH in Core/module/backup code.
- Host-key changes are fail-closed and require a visible reset/re-enrollment flow.
- The management-state database schema remains version 2 because the richer observed JSON is already stored in the existing JSON column and the public SSH key is derivable.
- The runtime image needs the OpenSSH client. It is extracted from the same frozen Debian snapshot technique used for Git so Docker/Podman image reproducibility remains a hard CI contract.
- Step 4 adds no target mutation, deployment compiler, bundle transfer/execution, start/stop/restart, repair, backup, or final UI.
