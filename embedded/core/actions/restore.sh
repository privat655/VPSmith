#!/usr/bin/env bash
set -Eeuo pipefail

apply_core_restore() {
  require_core_inputs
  require_admin_context

  local base=/var/lib/vpsmith/tmp/core-restore
  local claim="$base/active"
  local bundle_id archive candidate
  bundle_id=$(sudo -n cat "$claim/bundle" 2>/dev/null || true)
  case "$bundle_id" in
    ''|*[!A-Za-z0-9_-]*)
      echo "verified Core restore staging claim is missing or invalid" >&2
      return 78
      ;;
  esac
  archive="$base/$bundle_id/payload.tar.zst"
  candidate="$base/$bundle_id/candidate"

  command -v tar >/dev/null
  command -v zstd >/dev/null
  sudo -n test -f "$archive"
  sudo -n test "$(sudo -n stat -c %a -- "$archive")" = 400
  sudo -n tar --zstd -tf "$archive" >/dev/null
  sudo -n rm -rf -- "$candidate"
  sudo -n install -d -o root -g root -m 0700 "$candidate"
  sudo -n tar --numeric-owner --acls --xattrs --xattrs-include='*' --zstd -C "$candidate" -xf "$archive"

  sudo -n test -r "$candidate/management/core-desired.json"
  sudo -n test -r "$candidate/management/core-image-locks.json"
  sudo -n test -d "$candidate/var/lib/vpsmith/core/authelia/data"
  sudo -n test -d "$candidate/var/lib/vpsmith/secrets/core"

  sudo -n python3 - "$CORE_DESIRED" "$candidate/management/core-desired.json" "$candidate/management/core-image-locks.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    generated = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    desired = json.load(handle)
with open(sys.argv[3], encoding="utf-8") as handle:
    locks = json.load(handle)
for key in ("source_id", "version", "core_contract", "domain", "acme_email", "secrets"):
    if generated.get(key) != desired.get(key):
        raise SystemExit(f"Core restore desired state mismatch for {key}")
swap = desired.get("swap") or {}
if generated.get("swap_mode") != swap.get("mode") or generated.get("swap_size_gib", 0) != swap.get("size_gib", 0):
    raise SystemExit("Core restore desired swap mismatch")
for key in ("source_id", "version", "package_sha256"):
    if generated.get(key) != locks.get(key):
        raise SystemExit(f"Core restore image lock mismatch for {key}")
if generated.get("images") != locks.get("images"):
    raise SystemExit("Core restore exact image locks do not match generated bundle")
PY

  # Fail before replacing canonical data if package/runtime prerequisites cannot
  # be established from the approved Core definition.
  install_core_packages
  configure_rootless_podman
  apply_secondary_hardening
  apply_swap

  systemctl --user is-active --quiet caddy.service
  systemctl --user is-active --quiet authelia.service
  systemctl --user stop caddy.service authelia.service

  sudo -n install -d -o root -g "$ADMIN_GROUP" -m 0750 /var/lib/vpsmith/core/authelia
  sudo -n install -d -o root -g "$ADMIN_GROUP" -m 0750 /var/lib/vpsmith/secrets
  sudo -n rm -rf -- /var/lib/vpsmith/core/authelia/data /var/lib/vpsmith/secrets/core
  sudo -n mv -- "$candidate/var/lib/vpsmith/core/authelia/data" /var/lib/vpsmith/core/authelia/data
  sudo -n mv -- "$candidate/var/lib/vpsmith/secrets/core" /var/lib/vpsmith/secrets/core

  # Caddy, Authelia policy, Quadlets, network definitions, hardening and the
  # Core inventory are derived state. Regenerate them from this immutable
  # restore bundle instead of copying historical generated files.
  prepare_runtime_paths
  validate_generated_runtime
  activate_runtime
  validate_runtime_local
  publish_inventory

  sudo -n rm -rf -- "$candidate"
}

apply_core_restore
