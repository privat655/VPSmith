# ADR 0007 — Cloud-init bootstrap and target enrollment

## Scope

This ADR records only implementation decisions left open by VPSmith step 7. Product and ownership decisions remain defined by the finished VPSmith specs.

## Existing seams reused

- `managementstate.Store` remains the only persistent administrative state and encrypted secret store.
- `targetgateway.Gateway.EnsureIdentity` remains the only per-target SSH identity generator. Only its derived public key enters Cloud-init.
- `deployment.Compiler` now specializes its existing `BootstrapArtifact` output through `PrepareBootstrap`; Cloud-init is not an execution bundle.
- `targetgateway.Gateway` remains the TOFU and read-only target inspection seam. Enrollment requires prior explicit host-key confirmation and therefore inherits strict host-key checking and changed-key blocking.

## Primary-source decisions

Cloud-init stays as ordinary readable `#cloud-config`. CI validates the final serialized document with the official `cloud-init schema --config-file` mechanism. No compressed payload, downloader, or VPSmith Github runtime access is introduced.

OpenSSH hardening is emitted in an `sshd_config.d` drop-in and validated with `sshd -t` before reload. Completion and enrollment additionally use `sshd -T` effective values. Forwarding restrictions are explicit even though `DisableForwarding yes` is also present, keeping the security assertions directly observable.

UFW is reset to a closed inbound/routed baseline and permits only TCP 22, 80, and 443. Fail2ban uses the systemd backend and UFW action; completion requires the service and `sshd` jail to answer successfully. Unattended upgrades are enabled while `Unattended-Upgrade::Automatic-Reboot` is explicitly false.

The success marker is removed at the start of the final command, created in the destination directory with `mktemp`, populated only after all effective assertions pass, and atomically renamed into place. A failed run therefore cannot leave a new successful marker.

## Enrollment contract

`Gateway.Enroll` is read-only. It succeeds only when all of these agree:

1. the atomic Cloud-init status exists and reports `status=ok`, version, and completion time;
2. effective SSH, UFW, Fail2ban, and unattended-upgrade facts satisfy Primary Host Hardening;
3. Core is absent;
4. no Modules are present.

Enrollment never invokes the step-6 execution runner and never starts Core installation.

## Verification boundary

The repository CI installs the distribution Cloud-init package in the pinned Go-toolchain job so the schema test cannot silently skip there. Unit/integration tests cover final bytes, deterministic generation, forbidden responsibilities, TOFU behavior already established in step 4, and enrollment consistency. A real fresh VPS/VM is not provisioned by this repository or by step 7; live provider boot verification remains explicitly unclaimed until such a test target is available.
