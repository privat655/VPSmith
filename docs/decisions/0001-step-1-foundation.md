# ADR 0001 — Step 1 executable foundation

Status: accepted for VPSmith Platform step 1

## Context

The finished VPSmith specs leave the implementation language, web framework, workspace/package technique, image registry, exact start command, persistent mount paths, and supported live-integration distribution open. Step 1 must choose stable defaults without introducing product behavior from later implementation steps.

The non-negotiable product boundaries remain:

- VPSmith Studio runs locally on the administrative workstation.
- VPSmith Studio is not a fourth part of the Ziel-VPS; the Ziel-VPS consists only of Cloud-init, Core, and Module.
- The VPSmith Github is read only by the external build/release process. A running VPSmith Platform instance has no read/write path or credentials for it.
- The image must be startable with Docker and Podman.
- VPSmith Studio must listen only on loopback.

## Decisions

### Go and HTTP

The canonical production toolchain is Go 1.26.5. VPSmith Studio uses only the Go standard library in step 1 (`net/http`, `html/template`, JSON and filesystem primitives). The repository is a single Go module; no framework abstraction or package-per-feature hierarchy is introduced.

`go.mod` declares a Go 1.23 language compatibility floor and a preferred `go1.26.5` toolchain. This lets the source remain buildable for local static checks on older developer installations while the canonical container/CI build is fixed to Go 1.26.5.

### Repository areas

- `cmd/vpsmith-studio` — the local executable adapter.
- `internal/releaseinfo` — release identity verification for the image's immutable basis snapshots.
- `internal/studio` — the minimal HTTP adapter only.
- `embedded` — released build inputs for Cloud-init, Core, and the public n8n example module.
- `build` — external build/release and verification mechanics.
- `tests` — cross-module/process integration tests.

Later deep VPSmith Platform modules are added under `internal` only when their real seams exist. Step 1 does not create empty Verwaltungszustand, Quellenbibliothek, Ziel-VPS-Gateway, compiler, lifecycle, or backup packages.

### Embedded-source identity

`embedded/manifest.json` is canonical build metadata for the image input. Each embedded source tree has an explicit version and SHA-256. The SHA-256 is a canonical tree digest over sorted POSIX paths. Regular files contribute path, Unix permission bits, byte size, and content digest; symlinks contribute path and target and are not followed for hashing. A source root may not escape `embedded/` through a symlink. Inner symlinks must use relative targets and must resolve to an existing entry inside the same source tree; dangling, absolute, or escaping targets fail closed. Unsupported filesystem entry types also fail closed.

The embedded directory is release input, not mutable runtime state. It is copied into the runtime image as `root:root` while retaining the release-hashed Unix modes. Group and other write permission is forbidden, and the non-root Studio UID cannot modify these snapshots. This preserves the exact identity verified by the manifest instead of mutating permissions after hashing.

The step-1 source trees are marked `0.1.0-scaffold.1` and are deliberately non-deployable. Historical scripts remain evidence; they are not copied into the new tree as an accidental second architecture.

### Loopback and host networking

The process address is a compile-time constant: `127.0.0.1:8787`. It is not configurable by environment variable or command-line flag. Startup validates that the actual listener is loopback and fails closed otherwise.

The Version 1 administrative workstation support envelope is deliberately **Linux on amd64**. The container uses Linux host networking (`--network host`) so the process itself can bind to loopback without exposing a wildcard container listener. Windows and macOS administrative workstations are not supported in Version 1. Expanding workstation support later requires an explicit replacement or extension of this start/network contract rather than silently weakening the loopback invariant.

The reduced network isolation of host networking is countered by the tiny local-only process, non-root UID, read-only root filesystem, dropped capabilities, `no-new-privileges`, no engine socket mount, and exactly three writable persistent volumes.

Podman normally makes `/tmp`, `/run`, and `/var/tmp` writable tmpfs even when `--read-only` is set. VPSmith disables that Podman default with `--read-only-tmpfs=false` so the only writable runtime locations remain the three declared persistent volumes.

### Persistent mounts

The stable host/container contract is:

- `/var/lib/vpsmith/state`
- `/var/lib/vpsmith/sources`
- `/var/lib/vpsmith/backups`

The corresponding default named volumes are `vpsmith-state`, `vpsmith-sources`, and `vpsmith-backups`. Step 1 checks only existence/writeability and defines no internal persistence schema.

### Container and registry

The build is a multi-stage OCI build. Builder and runtime base images are pinned to explicit upstream digests. The runtime process is UID/GID `10001:10001`. The repository reserves `ghcr.io/privat655/vpsmith-platform` as the image name; step 1 does not publish releases or add registry credentials.

The build receives version, Git revision, and `SOURCE_DATE_EPOCH` explicitly. Go builds use `-trimpath` and `-buildvcs=false`. Docker uses a named `docker-container` Buildx builder pinned to BuildKit 0.30.0 plus the Docker exporter with `SOURCE_DATE_EPOCH`, a fixed `linux/amd64` platform, disabled attestations, and `rewrite-timestamp=true` so filesystem timestamps are normalized as well. Podman uses its native `--source-date-epoch` and `--rewrite-timestamp` build options, and builds Docker image format so the declared `HEALTHCHECK` is preserved. CI checks reproducible image IDs independently for both engines.

### Supported platforms

Version 1 supports the administrative container on **Linux/amd64** with Docker or Podman. Step 1 verifies that contract on GitHub Actions `ubuntu-24.04`. Other administrative-workstation operating systems and architectures are outside the Version 1 support envelope.

For later Ziel-VPS live integration, the initial target baseline is Ubuntu Server 24.04 LTS on amd64. This is only a future integration baseline; step 1 contains no Ziel-VPS operations.

## Consequences

The foundation has only two meaningful current Modules: release identity verification and the thin VPSmith Studio HTTP adapter. There is no speculative runtime seam for the VPSmith Github and no early implementation of Verwaltungszustand, SSH, source editing, generators, Core, Module lifecycle, or Backup.
