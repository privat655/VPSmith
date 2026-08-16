#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
exec go run ./build/cmd/embedded-manifest -root embedded -manifest embedded/manifest.json -check
