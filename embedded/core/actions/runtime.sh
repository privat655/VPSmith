#!/usr/bin/env bash
set -Eeuo pipefail

CORE_DESIRED=/var/lib/vpsmith/core/desired.json
CORE_GENERATED_INVENTORY=/var/lib/vpsmith/core/generated/inventory.json
CORE_INVENTORY=/var/lib/vpsmith/inventory/core.json
CORE_SWAP=/var/lib/vpsmith/swapfile
SECRET_ROOT=/var/lib/vpsmith/secrets/core
AUTHELIA_CONFIG=/var/lib/vpsmith/core/authelia/configuration.yml
CADDY_CONFIG=/var/lib/vpsmith/core/caddy/Caddyfile

core_json() {
  local expression=$1
  sudo cat "$CORE_DESIRED" | python3 -c '
import json, sys
data = json.load(sys.stdin)
value = data
for part in sys.argv[1].split("."):
    value = value[part]
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("")
else:
    print(value)
' "$expression"
}

require_core_inputs() {
  sudo test -r "$CORE_DESIRED" || { echo "Core desired state is missing" >&2; return 1; }
  sudo test -r "$CORE_GENERATED_INVENTORY" || { echo "generated Core inventory is missing" >&2; return 1; }
  sudo cat "$CORE_DESIRED" | python3 -c '
import json, sys
data = json.load(sys.stdin)
for key in ("source_id", "version", "package_sha256", "core_contract", "admin_user", "domain", "acme_email", "images", "secrets", "swap_mode"):
    if not data.get(key) and key not in ("images", "secrets"):
        raise SystemExit(f"Core desired state is missing {key}")
for image in ("caddy", "authelia"):
    item = data.get("images", {}).get(image, {})
    if not item.get("ref") or not item.get("digest"):
        raise SystemExit(f"Core desired state is missing exact {image} image identity")
for secret in ("authelia_session", "authelia_storage", "authelia_reset_password", "authelia_users_database"):
    if not data.get("secrets", {}).get(secret):
        raise SystemExit(f"Core desired state is missing {secret} secret reference")
'
}

require_admin_context() {
  ADMIN_USER=$(core_json admin_user)
  [ "$(id -un)" = "$ADMIN_USER" ] || { echo "Core action must run as the Cloud-init administrator" >&2; return 1; }
  ADMIN_UID=$(id -u)
  ADMIN_GID=$(id -g)
  ADMIN_GROUP=$(id -gn)
  export ADMIN_USER ADMIN_UID ADMIN_GID ADMIN_GROUP
  export XDG_RUNTIME_DIR="/run/user/${ADMIN_UID}"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
  sudo -n true
}

wait_for_apt() {
  local locks=(/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock)
  local i
  for i in $(seq 1 180); do
    if ! sudo fuser "${locks[@]}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "apt/dpkg locks are still held" >&2
  return 1
}

remove_unwanted_container_runtime() {
  sudo systemctl disable --now docker.service docker.socket containerd.service >/dev/null 2>&1 || true
  local packages=()
  local package
  for package in docker.io docker-ce docker-ce-cli containerd containerd.io; do
    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
      packages+=("$package")
    fi
  done
  if [ "${#packages[@]}" -gt 0 ]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 purge -y "${packages[@]}"
  fi
}

install_core_packages() {
  wait_for_apt
  remove_unwanted_container_runtime
  sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 update
  sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=900 install -y \
    apparmor apparmor-utils auditd chrony podman uidmap dbus-user-session passt curl jq ca-certificates
  command -v podman >/dev/null
  command -v loginctl >/dev/null
  test -x /usr/lib/systemd/systemd-socket-proxyd
}

ensure_one_subordinate_range() {
  local file=$1
  local kind=$2
  if awk -F: -v u="$ADMIN_USER" '$1 == u && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3 >= 65536 {found=1} END {exit !found}' "$file"; then
    return 0
  fi
  if awk -F: -v u="$ADMIN_USER" '
    $1 != u && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
      start=$2; end=$2+$3-1
      if (!(end < 100000 || start > 165535)) bad=1
    }
    END {exit bad ? 0 : 1}
  ' "$file"; then
    echo "$kind range 100000-165535 overlaps another account" >&2
    return 1
  fi
  if [ "$kind" = uid ]; then
    sudo usermod --add-subuids 100000-165535 "$ADMIN_USER"
  else
    sudo usermod --add-subgids 100000-165535 "$ADMIN_USER"
  fi
}

validate_rootless_podman() {
  command -v podman >/dev/null
  local cgroup network rootless
  rootless=$(podman info --format '{{.Host.Security.Rootless}}')
  [ "$rootless" = true ] || { echo "Podman is not rootless" >&2; return 1; }
  cgroup=$(podman info --format '{{.Host.CgroupVersion}}')
  [ "$cgroup" = v2 ] || { echo "rootless Podman requires cgroup v2" >&2; return 1; }
  network=$(podman info --format '{{.Host.RootlessNetworkCmd}}' 2>/dev/null || true)
  if [ -n "$network" ] && [ "$network" != pasta ]; then
    echo "rootless Podman network command is not pasta" >&2
    return 1
  fi
}

configure_rootless_podman() {
  ensure_one_subordinate_range /etc/subuid uid
  ensure_one_subordinate_range /etc/subgid gid
  sudo loginctl enable-linger "$ADMIN_USER"
  sudo systemctl start "user@${ADMIN_UID}.service"
  [ -S "$XDG_RUNTIME_DIR/bus" ] || { echo "user systemd bus is unavailable" >&2; return 1; }
  podman info >/dev/null
  validate_rootless_podman
}

apply_secondary_hardening() {
  sudo systemctl daemon-reload
  sudo systemctl enable --now apparmor.service auditd.service chrony.service
  command -v aa-enabled >/dev/null
  sudo aa-enabled

  sudo systemctl mask apport.service apport-autoreport.service >/dev/null 2>&1 || true
  sudo systemctl stop apport.service apport-autoreport.service >/dev/null 2>&1 || true

  sudo systemctl enable tmp.mount
  if ! mountpoint -q /tmp; then
    sudo systemctl start tmp.mount
  else
    local fstype
    fstype=$(findmnt -n -o FSTYPE /tmp)
    [ "$fstype" = tmpfs ] || { echo "/tmp is already a non-tmpfs mount" >&2; return 1; }
    sudo mount -o remount,nosuid,nodev,noexec /tmp
  fi

  sudo sysctl --system >/dev/null
  [ "$(sysctl -n net.ipv4.ip_unprivileged_port_start)" = 1024 ]
  [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" = 1 ]

  sudo augenrules --load
  sudo systemctl try-restart systemd-journald.service

  local module
  for module in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc; do
    if lsmod | awk '{print $1}' | grep -qx "$module"; then
      sudo modprobe -r "$module" || true
    fi
    if lsmod | awk '{print $1}' | grep -qx "$module"; then
      echo "blocked kernel module remains loaded: $module" >&2
      return 1
    fi
  done
}

swap_used_bytes() {
  awk '/^SwapTotal:/ {total=$2*1024} /^SwapFree:/ {free=$2*1024} END {print total-free}' /proc/meminfo
}

memory_available_bytes() {
  awk '/^MemAvailable:/ {print $2*1024}' /proc/meminfo
}

safe_swapoff() {
  local target=$1
  local used available
  used=$(swap_used_bytes)
  available=$(memory_available_bytes)
  if [ "$available" -lt "$used" ]; then
    echo "available RAM cannot absorb currently used swap" >&2
    return 1
  fi
  sudo swapoff "$target"
}

active_swap_count() {
  swapon --show=NAME --noheadings | awk 'NF {count++} END {print count+0}'
}

active_swap_name() {
  swapon --show=NAME --noheadings | awk 'NF {$1=$1; print; exit}'
}

core_swap_active() {
  [ "$(active_swap_name)" = "$CORE_SWAP" ]
}

foreign_swap_active() {
  local active
  active=$(active_swap_name)
  [ -n "$active" ] && [ "$active" != "$CORE_SWAP" ]
}

require_swap_v1_runtime() {
  local count
  count=$(active_swap_count)
  [ "$count" -le 1 ] || { echo "Swap V1 supports at most one active swap device" >&2; return 1; }
}

write_swap_fstab() {
  local enable=$1
  local tmp
  tmp=$(mktemp)
  sudo awk '$3 != "swap" {print}' /etc/fstab >"$tmp"
  if [ "$enable" = yes ]; then
    printf '%s none swap sw 0 0\n' "$CORE_SWAP" >>"$tmp"
  fi
  sudo install -o root -g root -m 0644 "$tmp" /etc/fstab
  rm -f "$tmp"
}

apply_swap() {
  local mode size active
  mode=$(core_json swap_mode)
  size=$(core_json effective_swap_bytes)
  require_swap_v1_runtime
  active=$(active_swap_name)

  case "$mode" in
    preserve-existing)
      [ "$size" = 0 ]
      [ -n "$active" ] || { echo "preserve-existing requires active foreign swap" >&2; return 1; }
      [ "$active" != "$CORE_SWAP" ] || { echo "preserve-existing cannot keep a VPSmith swapfile" >&2; return 1; }
      ;;
    none)
      if [ -n "$active" ]; then
        safe_swapoff "$active"
      fi
      write_swap_fstab no
      sudo rm -f "$CORE_SWAP"
      [ "$(active_swap_count)" -eq 0 ] || { echo "swap remains active after disabling it" >&2; return 1; }
      ;;
    swapfile)
      [ "$size" -gt 0 ] || { echo "swapfile requires resolved positive size" >&2; return 1; }
      if [ -n "$active" ]; then
        if [ "$active" != "$CORE_SWAP" ]; then
          safe_swapoff "$active"
          active=""
        else
          local current
          current=$(stat -c %s "$CORE_SWAP")
          if [ "$current" -ne "$size" ]; then
            safe_swapoff "$CORE_SWAP"
            active=""
          fi
        fi
      fi
      if [ -z "$active" ]; then
        sudo install -d -o root -g root -m 0750 /var/lib/vpsmith
        sudo rm -f "$CORE_SWAP"
        sudo fallocate -l "$size" "$CORE_SWAP"
        sudo chmod 0600 "$CORE_SWAP"
        sudo mkswap "$CORE_SWAP" >/dev/null
        sudo swapon "$CORE_SWAP"
      fi
      write_swap_fstab yes
      [ "$(active_swap_count)" -eq 1 ] && core_swap_active || { echo "Core swapfile is not the only active swap device" >&2; return 1; }
      ;;
    *)
      echo "unsupported Core swap mode: $mode" >&2
      return 1
      ;;
  esac
}

prepare_runtime_paths() {
  sudo chown "root:$ADMIN_GROUP" /var/lib/vpsmith/core
  sudo chmod 0750 /var/lib/vpsmith/core
  sudo install -d -o root -g "$ADMIN_GROUP" -m 0750 /var/lib/vpsmith/core/caddy /var/lib/vpsmith/core/authelia /var/lib/vpsmith/core/generated
  sudo install -d -o "$ADMIN_USER" -g "$ADMIN_GROUP" -m 0750 \
    /var/lib/vpsmith/core/caddy/data \
    /var/lib/vpsmith/core/caddy/config \
    /var/lib/vpsmith/core/authelia/data
  sudo install -d -o root -g root -m 0750 /var/lib/vpsmith/inventory
  sudo chown "root:$ADMIN_GROUP" /var/lib/vpsmith/secrets
  sudo chmod 0750 /var/lib/vpsmith/secrets

  local qdir="/home/${ADMIN_USER}/.config/containers/systemd"
  sudo chown "$ADMIN_USER:$ADMIN_GROUP" "/home/${ADMIN_USER}/.config" "/home/${ADMIN_USER}/.config/containers" "$qdir"
  sudo chmod 0700 "/home/${ADMIN_USER}/.config" "/home/${ADMIN_USER}/.config/containers" "$qdir"
  sudo find "$qdir" -maxdepth 1 -type f \
    \( -name '*.network' -o -name '*.container' \) \
    -exec chown "$ADMIN_USER:$ADMIN_GROUP" {} + \
    -exec chmod 0640 {} +

  sudo chown "$ADMIN_USER:$ADMIN_GROUP" "$AUTHELIA_CONFIG"
  sudo chmod 0644 "$AUTHELIA_CONFIG"
  sudo chown root:root "$CADDY_CONFIG"
  sudo chmod 0644 "$CADDY_CONFIG"

  local sid
  for sid in \
    "$(core_json secrets.authelia_session)" \
    "$(core_json secrets.authelia_storage)" \
    "$(core_json secrets.authelia_reset_password)" \
    "$(core_json secrets.authelia_users_database)"; do
    [ -s "$SECRET_ROOT/$sid" ] || { echo "materialized Core secret is missing: $sid" >&2; return 1; }
    sudo chown "$ADMIN_USER:$ADMIN_GROUP" "$SECRET_ROOT/$sid"
    chmod 0600 "$SECRET_ROOT/$sid"
  done

  podman unshare chown -R 1000:1000 /var/lib/vpsmith/core/caddy/data /var/lib/vpsmith/core/caddy/config
  podman unshare chown -R 1000:1000 /var/lib/vpsmith/core/authelia/data
  podman unshare chown 1000:1000 "$AUTHELIA_CONFIG"
  for sid in \
    "$(core_json secrets.authelia_session)" \
    "$(core_json secrets.authelia_storage)" \
    "$(core_json secrets.authelia_reset_password)" \
    "$(core_json secrets.authelia_users_database)"; do
    podman unshare chown 1000:1000 "$SECRET_ROOT/$sid"
  done
}

image_identity() {
  local name=$1
  local ref digest
  ref=$(core_json "images.${name}.ref")
  digest=$(core_json "images.${name}.digest")
  printf '%s@%s\n' "$ref" "$digest"
}

validate_generated_runtime() {
  local caddy_image authelia_image authelia_bin
  caddy_image=$(image_identity caddy)
  authelia_image=$(image_identity authelia)
  podman pull "$caddy_image" >/dev/null
  podman pull "$authelia_image" >/dev/null

  podman run --rm --network none \
    -v "$CADDY_CONFIG:/etc/caddy/Caddyfile:ro" \
    "$caddy_image" caddy validate --config /etc/caddy/Caddyfile

  authelia_bin=$(
    podman run --rm --network none --entrypoint /bin/sh "$authelia_image" -c '
      command -v authelia 2>/dev/null ||
      find / -xdev -type f -name authelia -perm -111 2>/dev/null | head -n 1
    ' | tail -n 1
  )
  [ -n "$authelia_bin" ] || { echo "Authelia binary was not found in pinned image" >&2; return 1; }

  podman run --rm --network none --userns nomap --user 1000:1000 \
    -v "$AUTHELIA_CONFIG:/config/configuration.yml:ro" \
    -v "/var/lib/vpsmith/core/authelia/data:/data" \
    -v "$SECRET_ROOT/$(core_json secrets.authelia_users_database):/config/users_database.yml:ro" \
    -v "$SECRET_ROOT/$(core_json secrets.authelia_session):/run/secrets/session:ro" \
    -v "$SECRET_ROOT/$(core_json secrets.authelia_storage):/run/secrets/storage:ro" \
    -v "$SECRET_ROOT/$(core_json secrets.authelia_reset_password):/run/secrets/reset-password:ro" \
    -e AUTHELIA_SESSION_SECRET_FILE=/run/secrets/session \
    -e AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE=/run/secrets/storage \
    -e AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE=/run/secrets/reset-password \
    --entrypoint "$authelia_bin" \
    "$authelia_image" config validate --config /config/configuration.yml

  systemctl --user daemon-reload
  systemd-analyze --user --generators=true verify \
    vpsmith-core-network.service vpsmith-egress-network.service authelia.service caddy.service
}

activate_runtime() {
  systemctl --user daemon-reload
  systemctl --user start vpsmith-core-network.service vpsmith-egress-network.service
  systemctl --user restart authelia.service
  systemctl --user restart caddy.service

  sudo systemctl daemon-reload
  sudo systemctl enable --now caddy-edge-http.socket caddy-edge-https.socket
}

validate_runtime_local() {
  systemctl --user is-active --quiet authelia.service caddy.service
  sudo systemctl is-active --quiet caddy-edge-http.socket caddy-edge-https.socket

  local userns
  for name in authelia caddy; do
    userns=$(podman inspect "$name" --format '{{.HostConfig.UsernsMode}}')
    [ "$userns" = nomap ] || { echo "$name is not using UserNS=nomap" >&2; return 1; }
  done

  sudo ss -H -ltn | awk '
  {
    local=$4
    if (local ~ /^127\.0\.0\.1:(8080|8443)$/) {found[local]=1; next}
    if (local ~ /:(8080|8443)$/) {print "public Core high-port listener: " $0 > "/dev/stderr"; bad=1}
  }
  END {
    if (!found["127.0.0.1:8080"] || !found["127.0.0.1:8443"]) bad=1
    exit bad
  }'

  local domain ready=0
  domain=$(core_json domain)
  local i
  for i in $(seq 1 60); do
    if curl -fsSI --max-time 10 "https://auth.${domain}" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 5
  done
  [ "$ready" -eq 1 ] || { echo "Caddy Automatic HTTPS did not become ready" >&2; return 1; }
}

publish_inventory() {
  local candidate
  candidate=$(mktemp)
  sudo cat "$CORE_GENERATED_INVENTORY" >"$candidate"
  sudo install -o root -g root -m 0400 "$candidate" "${CORE_INVENTORY}.candidate"
  sudo mv -f "${CORE_INVENTORY}.candidate" "$CORE_INVENTORY"
  rm -f "$candidate"
}

apply_core_runtime() {
  local operation=$1
  require_core_inputs
  require_admin_context
  case "$operation" in
    install|update|reconfigure)
      install_core_packages
      configure_rootless_podman
      apply_secondary_hardening
      apply_swap
      prepare_runtime_paths
      validate_generated_runtime
      activate_runtime
      validate_runtime_local
      publish_inventory
      ;;
    restore)
      echo "Core restore requires the verified replace-not-merge payload path; it is not wired yet" >&2
      return 78
      ;;
    validate)
      validate_rootless_podman
      systemctl --user is-active --quiet authelia.service caddy.service
      sudo systemctl is-active --quiet caddy-edge-http.socket caddy-edge-https.socket
      podman exec caddy caddy validate --config /etc/caddy/Caddyfile
      podman exec authelia /bin/sh -c '
        bin=$(command -v authelia 2>/dev/null || find / -xdev -type f -name authelia -perm -111 2>/dev/null | head -n 1)
        [ -n "$bin" ]
        "$bin" config validate --config /config/configuration.yml
      '
      validate_runtime_local
      sudo test -r "$CORE_INVENTORY" || { echo "Core inventory is missing" >&2; return 1; }
      sudo cat "$CORE_DESIRED" >"${XDG_RUNTIME_DIR}/vpsmith-desired.json"
      sudo cat "$CORE_INVENTORY" >"${XDG_RUNTIME_DIR}/vpsmith-inventory.json"
      python3 - "${XDG_RUNTIME_DIR}/vpsmith-desired.json" "${XDG_RUNTIME_DIR}/vpsmith-inventory.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    desired = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    inventory = json.load(handle)
for key in ("source_id", "version", "package_sha256"):
    if desired.get(key) != inventory.get(key):
        raise SystemExit(f"Core identity mismatch for {key}")
PY
      rm -f "${XDG_RUNTIME_DIR}/vpsmith-desired.json" "${XDG_RUNTIME_DIR}/vpsmith-inventory.json"
      ;;
    *)
      echo "unsupported Core action operation: $operation" >&2
      return 1
      ;;
  esac
}
