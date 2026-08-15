#!/usr/bin/env sh
set -eu

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

set -- run --rm \
  --name vpsmith-platform \
  --network host \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges
if [ "$engine" = "podman" ]; then
  set -- "$@" --read-only-tmpfs=false
fi
set -- "$@" \
  --volume vpsmith-state:/var/lib/vpsmith/state \
  --volume vpsmith-sources:/var/lib/vpsmith/sources \
  --volume vpsmith-backups:/var/lib/vpsmith/backups \
  "$image"

exec "$engine" "$@"
