#!/usr/bin/env bash
set -Eeuo pipefail

preflight_core_history_restore() {
  local candidate=$1
  local source="$candidate/var/lib/vpsmith/execution"
  local category source_dir target_dir name target

  sudo -n test -d "$source" || { echo "Core restore history is missing" >&2; return 1; }
  for category in bundles proofs claims; do
    source_dir="$source/$category"
    target_dir="/var/lib/vpsmith/execution/$category"
    sudo -n test -d "$source_dir" || continue
    if [ -n "$(sudo -n find "$source_dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]; then
      echo "Core restore history contains non-file entries in $category" >&2
      return 1
    fi
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      case "$name" in
        .*|*[!A-Za-z0-9_.-]*)
          echo "Core restore history contains unsafe file name" >&2
          return 1
          ;;
      esac
      target="$target_dir/$name"
      if sudo -n test -e "$target"; then
        sudo -n test -f "$target" || { echo "Core restore history collides with non-file $category/$name" >&2; return 1; }
        sudo -n cmp -s -- "$source_dir/$name" "$target" || {
          echo "Core restore history collision for $category/$name" >&2
          return 1
        }
      fi
    done < <(sudo -n find "$source_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)
  done
}

rehydrate_core_history() {
  local candidate=$1
  local source="$candidate/var/lib/vpsmith/execution"
  local category mode source_dir target_dir name target

  for category in bundles proofs claims; do
    case "$category" in
      proofs) mode=0600 ;;
      *) mode=0400 ;;
    esac
    source_dir="$source/$category"
    target_dir="/var/lib/vpsmith/execution/$category"
    sudo -n test -d "$source_dir" || continue
    sudo -n install -d -o "$ADMIN_USER" -g "$ADMIN_GROUP" -m 0700 "$target_dir"
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      target="$target_dir/$name"
      if sudo -n test -e "$target"; then
        continue
      fi
      sudo -n install -o "$ADMIN_USER" -g "$ADMIN_GROUP" -m "$mode" -- "$source_dir/$name" "$target"
    done < <(sudo -n find "$source_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)
  done
}

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
  preflight_core_history_restore "$candidate"

  sudo -n python3 - "$CORE_DESIRED" "$candidate/management/core-desired.json" "$candidate/management/core-image-locks.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    generated = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    desired = json.load(handle)
with open(sys.argv[3], encoding="utf-8") as handle:
    locks = json.load(handle)
for key in ("source_id", "version", "core_contract", "domain", "acme_email", "authelia", "secrets"):
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
if desired.get("images") and desired.get("images") != locks.get("images"):
    raise SystemExit("Core restore canonical image locks do not match generated bundle")
PY

  install_core_packages
  configure_rootless_podman
  apply_secondary_hardening
  apply_swap

  systemctl --user stop caddy.service authelia.service >/dev/null 2>&1 || true
  if systemctl --user is-active --quiet caddy.service || systemctl --user is-active --quiet authelia.service; then
    echo "Core services could not be stopped for restore" >&2
    return 1
  fi

  sudo -n install -d -o root -g "$ADMIN_GROUP" -m 0750 /var/lib/vpsmith/core/authelia
  sudo -n install -d -o root -g "$ADMIN_GROUP" -m 0750 /var/lib/vpsmith/secrets
  sudo -n rm -rf -- /var/lib/vpsmith/core/authelia/data /var/lib/vpsmith/secrets/core
  sudo -n mv -- "$candidate/var/lib/vpsmith/core/authelia/data" /var/lib/vpsmith/core/authelia/data
  sudo -n mv -- "$candidate/var/lib/vpsmith/secrets/core" /var/lib/vpsmith/secrets/core

  prepare_runtime_paths
  validate_generated_runtime
  activate_runtime
  validate_runtime_local
  publish_inventory

  rehydrate_core_history "$candidate"

  sudo -n rm -rf -- "$candidate"
}

apply_core_restore
