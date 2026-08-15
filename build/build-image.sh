#!/usr/bin/env sh
set -eu

engine="${1:-docker}"
case "$engine" in
  docker|podman) ;;
  *) printf 'ERROR: engine must be docker or podman\n' >&2; exit 2 ;;
esac
command -v "$engine" >/dev/null 2>&1 || { printf 'ERROR: %s is not installed\n' "$engine" >&2; exit 1; }

cd "$(dirname "$0")/.."
version=$(tr -d '\r\n' < VERSION)
revision="${VPSMITH_REVISION:-}"
source_date_epoch="${SOURCE_DATE_EPOCH:-}"

if [ -z "$revision" ]; then
  revision=$(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown')
fi
if [ -z "$source_date_epoch" ]; then
  source_date_epoch=$(git log -1 --format=%ct 2>/dev/null || printf '0')
fi
case "$source_date_epoch" in
  ''|*[!0-9]*) printf 'ERROR: SOURCE_DATE_EPOCH must be an integer\n' >&2; exit 1 ;;
esac
if [ "$source_date_epoch" -le 0 ]; then
  printf 'ERROR: SOURCE_DATE_EPOCH is required when building outside a git checkout\n' >&2
  exit 1
fi

image="${VPSMITH_IMAGE_TAG:-ghcr.io/privat655/vpsmith-platform:${version}}"

printf 'Building %s with %s (revision %s, SOURCE_DATE_EPOCH=%s)\n' "$image" "$engine" "$revision" "$source_date_epoch" >&2

if [ "$engine" = "docker" ]; then
  set -- buildx build \
    --file Containerfile \
    --build-arg "VERSION=$version" \
    --build-arg "REVISION=$revision" \
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --build-arg "BUILDKIT_MULTI_PLATFORM=1" \
    --provenance=false \
    --sbom=false \
    --output "type=image,name=$image,rewrite-timestamp=true"
  if [ "${VPSMITH_BUILD_NO_CACHE:-0}" = "1" ]; then
    set -- "$@" --no-cache
  fi
  SOURCE_DATE_EPOCH="$source_date_epoch" docker "$@" . >&2
else
  set -- build \
    --file Containerfile \
    --build-arg "VERSION=$version" \
    --build-arg "REVISION=$revision" \
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --tag "$image" \
    --timestamp "$source_date_epoch"
  if [ "${VPSMITH_BUILD_NO_CACHE:-0}" = "1" ]; then
    set -- "$@" --no-cache
  fi
  podman "$@" . >&2
fi

printf '%s\n' "$image"
