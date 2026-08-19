#!/usr/bin/env sh
set -eu

engine="${1:-docker}"
case "$engine" in
  docker|podman) ;;
  *) printf 'ERROR: engine must be docker or podman\n' >&2; exit 2 ;;
esac
command -v "$engine" >/dev/null 2>&1 || { printf 'ERROR: %s is not installed\n' "$engine" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { printf 'ERROR: curl is required\n' >&2; exit 1; }
command -v ss >/dev/null 2>&1 || { printf 'ERROR: ss is required\n' >&2; exit 1; }

cd "$(dirname "$0")/.."
version=$(tr -d '\r\n' < VERSION)
suffix="${engine}-$$"
image="vpsmith-platform-step1:${suffix}"
container="vpsmith-step1-${suffix}"
state="vpsmith-step1-${suffix}-state"
sources="vpsmith-step1-${suffix}-sources"
backups="vpsmith-step1-${suffix}-backups"

cleanup() {
  "$engine" rm -f "$container" >/dev/null 2>&1 || true
  "$engine" volume rm -f "$state" "$sources" "$backups" >/dev/null 2>&1 || true
  "$engine" image rm -f "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

VPSMITH_IMAGE_TAG="$image" ./build/build-image.sh "$engine" >/dev/null
for volume in "$state" "$sources" "$backups"; do
  "$engine" volume create "$volume" >/dev/null
done

set -- run -d \
  --name "$container" \
  --network host \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --tmpfs /run/vpsmith:rw,noexec,nosuid,nodev,size=16m,mode=1777
if [ "$engine" = "podman" ]; then
  set -- "$@" --read-only-tmpfs=false
fi
set -- "$@" \
  --volume "$state:/var/lib/vpsmith/state" \
  --volume "$sources:/var/lib/vpsmith/sources" \
  --volume "$backups:/var/lib/vpsmith/backups" \
  "$image"
"$engine" "$@" >/dev/null

healthy=0
i=0
while [ "$i" -lt 30 ]; do
  if curl --fail --silent --show-error --max-time 1 http://127.0.0.1:8787/healthz >/dev/null 2>&1; then
    healthy=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ "$healthy" -eq 1 ] || { "$engine" logs "$container" >&2 || true; printf 'ERROR: VPSmith Studio did not become healthy\n' >&2; exit 1; }

listeners=$(ss -ltnH '( sport = :8787 )')
printf '%s\n' "$listeners" | grep -Eq '127\.0\.0\.1:8787([[:space:]]|$)' || {
  printf 'ERROR: no loopback listener on 127.0.0.1:8787\n%s\n' "$listeners" >&2
  exit 1
}
if printf '%s\n' "$listeners" | grep -Eq '(^|[[:space:]])(0\.0\.0\.0|\*|\[::\]|:::):?8787'; then
  printf 'ERROR: wildcard VPSmith Studio listener detected\n%s\n' "$listeners" >&2
  exit 1
fi

version_json=$(curl --fail --silent --show-error http://127.0.0.1:8787/version)
printf '%s\n' "$version_json" | grep -F '"version":"'"$version"'"' >/dev/null || {
  printf 'ERROR: /version does not expose expected Studio version\n%s\n' "$version_json" >&2
  exit 1
}
for name in cloud_init core n8n; do
  printf '%s\n' "$version_json" | grep -F '"'"$name"'"' >/dev/null || {
    printf 'ERROR: /version missing %s identity\n' "$name" >&2
    exit 1
  }
done

"$engine" exec "$container" /bin/sh -eu -c '
  for dir in /var/lib/vpsmith/state /var/lib/vpsmith/sources /var/lib/vpsmith/backups; do
    test -d "$dir"
    probe="$dir/.write-check-$$"
    : > "$probe"
    rm -f "$probe"
  done
  test -d /run/vpsmith
  test "$(stat -c %a /run/vpsmith)" = "1777"
  test -d /run/vpsmith/ssh
  test "$(stat -c %u:%g /run/vpsmith/ssh)" = "10001:10001"
  test "$(stat -c %a /run/vpsmith/ssh)" = "700"
  probe=/run/vpsmith/ssh/.write-check-$$
  : > "$probe"
  rm -f "$probe"
  test ! -e /var/lib/vpsmith/state/ssh-runtime
'
if "$engine" exec "$container" /bin/sh -c ': > /tmp/vpsmith-rootfs-write-test' >/dev/null 2>&1; then
  printf 'ERROR: read-only root filesystem accepted a write outside persistent mounts\n' >&2
  exit 1
fi

runtime_uid=$("$engine" exec "$container" /usr/bin/id -u)
[ "$runtime_uid" = "10001" ] || { printf 'ERROR: runtime UID is %s, expected 10001\n' "$runtime_uid" >&2; exit 1; }

"$engine" run --rm --entrypoint /bin/sh "$image" -eu -c '
  embedded=/usr/share/vpsmith/embedded
  test -d "$embedded"
  test "$(stat -c %u:%g "$embedded")" = "0:0"
  test -z "$(find "$embedded" \( ! -user root -o ! -group root \) -print -quit)"
  test -z "$(find "$embedded" -perm /022 -print -quit)"
  if touch "$embedded/.write-check" 2>/dev/null; then
    rm -f "$embedded/.write-check"
    echo "ERROR: runtime user can modify embedded release inputs" >&2
    exit 1
  fi
'

image_env=$("$engine" image inspect "$image" --format '{{range .Config.Env}}{{println .}}{{end}}')
if printf '%s\n' "$image_env" | grep -Eiq '(^|_)(GITHUB_TOKEN|GH_TOKEN|VPSMITH_GITHUB)='; then
  printf 'ERROR: VPSmith Github credential/configuration found in image environment\n%s\n' "$image_env" >&2
  exit 1
fi

"$engine" run --rm --entrypoint /bin/sh "$image" -eu -c '
  test ! -e /.git
  test ! -e /root/.gitconfig
  test -z "$(find / -type d -name .git -print -quit 2>/dev/null)"
  test -z "$(find / -type f \( -name credentials -o -name .gitconfig \) -print -quit 2>/dev/null)"
'

embedded_json=$("$engine" run --rm --entrypoint /usr/local/bin/vpsmith-studio "$image" version)
printf '%s\n' "$embedded_json" | grep -F '"sha256"' >/dev/null || {
  printf 'ERROR: embedded source identities are unavailable in runtime image\n' "$embedded_json" >&2
  exit 1
}

printf '%s container verification passed\n' "$engine"