# ADR 0007 — Cloud-init bootstrap and target enrollment

## Scope

This ADR records only implementation decisions left open by VPSmith step 7. Product and ownership decisions remain defined by the finished VPSmith specs.

## Released Cloud-init source

The released Cloud-init basis is a normal embedded VPSmith source snapshot under `embedded/cloud-init`. Its version and canonical tree SHA-256 are recorded in `embedded/manifest.json`, verified by the existing release-info pipeline, and imported by the existing source library as an immutable local snapshot.

`cloud-init.yaml.tmpl` is the single released Primary Host Hardening source. The deployment compiler renders target-specific hostname, timezone, administrator, per-target public SSH key, and released definition version into that frozen source. The compiler does not contain a second Cloud-init here-document. Local Cloud-init workspaces can therefore use the same source-snapshot model established for Cloud-init and Core without changing the released basis in place.

The generated provider-facing document remains ordinary readable `#cloud-config`. CI validates the final serialized document with `cloud-init schema --config-file`. No compressed payload, downloader, provider API, or VPSmith Github runtime access is introduced.

## Existing seams reused

- `managementstate.Store` remains the only persistent administrative state and encrypted secret store.
- `sourcelibrary.Library` remains the source-snapshot boundary. Bootstrap consumes the exact released and hash-verified Cloud-init snapshot.
- `targetgateway.Gateway.EnsureIdentity` remains the only per-target SSH identity generator. Only its derived public key enters generated Cloud-init.
- `deployment.Compiler` specializes its existing `BootstrapArtifact` output through `PrepareBootstrap`; Cloud-init is not an execution bundle.
- `targetgateway.Gateway` remains the TOFU and read-only target inspection seam. Enrollment requires prior explicit host-key confirmation and therefore inherits strict host-key checking and changed-key blocking.

## Primary Host Hardening

OpenSSH hardening is emitted in an `sshd_config.d` drop-in and validated with `sshd -t` before reload. Completion and enrollment additionally check effective `sshd -T` values. The released source enforces public-key-only authentication, the target-specific `AllowUsers` administrator, bounded login/session settings, disabled forwarding/tunneling, disabled compression, verbose SSH logging, and fresh host-key generation on first boot.

UFW is reset to a closed inbound/routed baseline, permits only public TCP 22, 80 and 443, and enables low logging. Fail2ban uses the systemd backend and UFW actions with active `sshd` and `recidive` jails. Unattended upgrades are enabled while `Unattended-Upgrade::Automatic-Reboot` is explicitly false.

Secondary Host Hardening, Swap, Podman, Quadlet, Caddy, Authelia, Core and Modules remain excluded from the Cloud-init source.

The success marker is removed before final configuration. It is created in the destination directory with `mktemp`, populated only after all effective assertions pass, and atomically renamed into place. A failed run therefore cannot publish a new successful marker.

## Enrollment contract

`Gateway.Enroll` is read-only. It succeeds only when all of these agree:

1. the atomic Cloud-init status exists and reports `status=ok`, the exact desired released definition version, and completion time;
2. effective SSH, UFW, Fail2ban, and unattended-upgrade facts satisfy Primary Host Hardening;
3. Core is absent;
4. no Modules are present.

The effective Primary Host Hardening facts use the canonical management-state observation type and are persisted with the enrolled target observation. Enrollment never invokes the step-6 execution runner and never starts Core installation.

## Verification boundary

Normal repository CI verifies formatting, vet, tests, embedded-manifest identity, final Cloud-init size, forbidden responsibilities, deterministic rendering, atomic status ordering, and the official Cloud-init schema.

A separate `workflow_dispatch` workflow boots a fresh pinned Ubuntu 24.04 cloud image under QEMU and exercises the real released source, per-target SSH identity, Cloud-init boot, TOFU, strict SSH and enrollment. This workflow is intentionally manual-only. It is the long-lived VPSmith end-to-end verification path and can be extended by later implementation steps without becoming a per-push or per-pull-request gate.
