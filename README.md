# VPSmith Platform

This repository is the VPSmith Github: the source input for the external VPSmith Platform build/release process.

Step 1 provides only the executable VPSmith Studio foundation. VPSmith Studio runs locally on the administrative workstation and does not yet manage a Ziel-VPS. A Ziel-VPS is always composed of exactly Cloud-init, Core, and Module; VPSmith Studio is not a fourth part.

## Step 1 runtime contract

- VPSmith Studio listens only on `127.0.0.1:8787`.
- The image starts with Docker or Podman on a Linux administrative workstation.
- Runtime state is persistent only through three mount points:
  - `/var/lib/vpsmith/state` — future administrative state;
  - `/var/lib/vpsmith/sources` — future local sources library;
  - `/var/lib/vpsmith/backups` — future local backup storage.
- The image contains identified Cloud-init, Core, and public n8n example-module basis snapshots under `/usr/share/vpsmith/embedded`.
- VPSmith Studio has no runtime remote, token, or credential for the VPSmith Github. Updating the VPSmith Platform image is the only path by which a new released VPSmith Studio/Cloud-init/Core/n8n basis enters a running installation.

The embedded Cloud-init, Core, and n8n directories in step 1 are explicit non-deployable scaffolds. They establish build identity without implementing later lifecycle steps early.

## Build

The canonical toolchain is Go 1.26.5. The container builder and runtime base images are pinned by digest in `Containerfile`.

```sh
make verify-go
./build/build-image.sh docker
# or
./build/build-image.sh podman
```

`go.mod` keeps a Go 1.23 language compatibility floor while declaring Go 1.26.5 as the preferred toolchain. Production builds use the pinned Go 1.26.5 container toolchain.

## Run

The local start contract deliberately uses host networking so the process itself can bind to loopback. There is no published wildcard container port.

```sh
./build/run.sh docker
# or
./build/run.sh podman
```

Then open `http://127.0.0.1:8787/`.

The helper creates the named volumes `vpsmith-state`, `vpsmith-sources`, and `vpsmith-backups`. It also uses a read-only root filesystem, drops all Linux capabilities, sets `no-new-privileges`, and relies on the image's non-root UID `10001`.

## Verification

```sh
make verify-go
./build/verify-container.sh docker
./build/verify-container.sh podman
./build/verify-reproducible-image.sh docker
./build/verify-reproducible-image.sh podman
```

The container checks verify HTTP health, the actual host listener, persistent mount writeability, read-only root filesystem, runtime UID, embedded identities, and the absence of `.git` or VPSmith Github credentials/configuration in the runtime image.
