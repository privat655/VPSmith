#!/usr/bin/env bash
set -Eeuo pipefail

DESIRED=/var/lib/vpsmith/core/desired.json

[ -r "$DESIRED" ] || { echo "Core desired state is missing" >&2; exit 1; }
python3 - "$DESIRED" <<'PY'
import json, sys
p = sys.argv[1]
with open(p, encoding="utf-8") as f:
    d = json.load(f)
for key in ("source_id", "version", "package_sha256", "core_contract", "admin_user", "domain", "acme_email", "images", "secrets", "swap_mode"):
    if key not in d:
        raise SystemExit(f"Core desired state is missing {key}")
PY

echo "Core install runtime is not active until the generated Step-9 runtime artifacts are present" >&2
exit 78
