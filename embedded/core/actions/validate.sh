#!/usr/bin/env bash
set -Eeuo pipefail

DESIRED=/var/lib/vpsmith/core/desired.json
INVENTORY=/var/lib/vpsmith/inventory/core.json

[ -r "$DESIRED" ] || { echo "Core desired state is missing" >&2; exit 1; }
[ -r "$INVENTORY" ] || { echo "Core inventory is missing" >&2; exit 1; }

python3 - "$DESIRED" "$INVENTORY" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    desired = json.load(f)
with open(sys.argv[2], encoding="utf-8") as f:
    inventory = json.load(f)
for key in ("source_id", "version", "package_sha256"):
    if desired.get(key) != inventory.get(key):
        raise SystemExit(f"Core identity mismatch for {key}")
PY

systemctl is-active --quiet caddy-edge-http.socket
systemctl is-active --quiet caddy-edge-https.socket

uid=$(id -u)
export XDG_RUNTIME_DIR="/run/user/$uid"
systemctl --user is-active --quiet caddy.service
systemctl --user is-active --quiet authelia.service
podman info --format '{{.Host.CgroupVersion}} {{.Host.Security.Rootless}} {{.Host.NetworkBackend}}' >/dev/null
