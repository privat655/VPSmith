#!/usr/bin/env bash
set -Eeuo pipefail

DESIRED=/var/lib/vpsmith/core/desired.json
INVENTORY=/var/lib/vpsmith/inventory/core.json

[ -r "$DESIRED" ] || { echo "Core desired state is missing" >&2; exit 1; }
[ -r "$INVENTORY" ] || { echo "Installed Core inventory is missing" >&2; exit 1; }

echo "Core update runtime is not active until the generated Step-9 runtime artifacts are present" >&2
exit 78
