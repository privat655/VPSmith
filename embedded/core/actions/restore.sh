#!/usr/bin/env bash
set -Eeuo pipefail

DESIRED=/var/lib/vpsmith/core/desired.json

[ -r "$DESIRED" ] || { echo "Core desired state is missing" >&2; exit 1; }

echo "Core restore runtime is not active until the generated Step-9 restore payload path is present" >&2
exit 78
