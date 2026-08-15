#!/usr/bin/env sh
set -eu

engine="${1:-docker}"
case "$engine" in
  docker|podman) ;;
  *) printf 'ERROR: engine must be docker or podman\n' >&2; exit 2 ;;
esac
command -v "$engine" >/dev/null 2>&1 || { printf 'ERROR: %s is not installed\n' "$engine" >&2; exit 1; }
cd "$(dirname "$0")/.."

a="vpsmith-repro-${engine}-a:$$"
b="vpsmith-repro-${engine}-b:$$"
cleanup() {
  "$engine" image rm -f "$a" "$b" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

VPSMITH_IMAGE_TAG="$a" VPSMITH_BUILD_NO_CACHE=1 ./build/build-image.sh "$engine" >/dev/null
VPSMITH_IMAGE_TAG="$b" VPSMITH_BUILD_NO_CACHE=1 ./build/build-image.sh "$engine" >/dev/null
id_a=$("$engine" image inspect "$a" --format '{{.Id}}')
id_b=$("$engine" image inspect "$b" --format '{{.Id}}')
[ "$id_a" = "$id_b" ] || {
  printf 'ERROR: %s produced different image IDs from identical clean inputs\nA=%s\nB=%s\n' "$engine" "$id_a" "$id_b" >&2
  exit 1
}
printf '%s reproducible image ID: %s\n' "$engine" "$id_a"
