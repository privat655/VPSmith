#!/usr/bin/env sh
set -eu

# Step 1 reference host adapter. Linux host networking is an implementation
# detail; the stable VPSmith contract is local-only reachability on 127.0.0.1.
host_os=$(uname -s 2>/dev/null || printf 'unknown')
if [ "$host_os" != "Linux" ]; then
  printf 'ERROR: build/run.sh is the Linux reference launcher; no verified VPSmith host adapter exists for %s yet\n' "$host_os" >&2
  exit 2
fi

engine="${1:-docker}"
image="${2:-ghcr.io/privat655/vpsmith-platform:$(tr -d '\r\n' < "$(dirname "$0")/../VERSION")}"
case "$engine" in
  docker|podman) ;;
  *) printf 'ERROR: engine must be docker or podman\n' >&2; exit 2 ;;
esac
command -v "$engine" >/dev/null 2>&1 || { printf 'ERROR: %s is not installed\n' "$engine" >&2; exit 1; }

for volume in vpsmith-state vpsmith-sources vpsmith-backups; do
  "$engine" volume inspect "$volume" >/dev/null 2>&1 || "$engine" volume create "$volume" >/dev/null
done

# /run/vpsmith is only an ephemeral rendezvous directory. VPSmith creates the
# actual SSH credential workspace below it as UID 10001 with mode 0700. Keeping
# uid/gid out of the tmpfs option set makes this contract portable across the
# Docker and Podman Linux launchers while preserving noexec/nosuid/nodev.
set -- run --rm \
  --name vpsmith-platform \
  --network host \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /run/vpsmith:rw,noexec,nosuid,nodev,size=16m,mode=1777
if [ "$engine" = "podman" ]; then
  set -- "$@" --read-only-tmpfs=false
fi
set -- "$@" \
  --volume vpsmith-state:/var/lib/vpsmith/state \
  --volume vpsmith-sources:/var/lib/vpsmith/sources \
  --volume vpsmith-backups:/var/lib/vpsmith/backups \
  "$image"

exec "$engine" "$@"