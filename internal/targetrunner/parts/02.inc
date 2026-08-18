      break
            if id_len > 4096:
                raise RuntimeError("secret id too long")
            sid = stream.read(id_len).decode("utf-8", "strict")
            raw = stream.read(8)
            if len(raw) != 8:
                raise RuntimeError("truncated secret stream")
            n = struct.unpack(">Q", raw)[0]
            if n > 64 * 1024 * 1024:
                raise RuntimeError("secret too large")
            value = stream.read(n)
            if len(value) != n:
                raise RuntimeError("truncated secret material")
            if sid in result:
                raise RuntimeError("duplicate secret id")
            result[sid] = value
    return result


def env_escape(value: bytes) -> str:
    text = value.decode("utf-8", "strict")
    if "\x00" in text or "\n" in text or "\r" in text:
        raise RuntimeError("environment secret must be one UTF-8 line")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def materialize_secrets(manifest: dict[str, Any], values: dict[str, bytes], admin_user: str, validation: bool) -> None:
    expected = {str(x.get("secret_id")) for x in manifest.get("secrets", [])}
    if set(values) != expected:
        raise RuntimeError("secret set does not match manifest")
    if validation:
        return
    uid = pwd.getpwnam(admin_user).pw_uid
    gid = pwd.getpwnam(admin_user).pw_gid
    rendered_env: dict[tuple[str, str], bytes] = {}
    rendered_file: dict[tuple[str, str], bytes] = {}
    for ref in manifest.get("secrets", []):
        sid = str(ref["secret_id"])
        instance, sep, _ = str(ref.get("container", "")).partition("/")
        if not sep or not instance:
            raise RuntimeError("secret container identity is invalid")
        delivery = ref.get("delivery")
        if delivery == "environment":
            target = str(ref.get("target", ""))
            if not target or "=" in target or "\x00" in target or "\n" in target:
                raise RuntimeError("environment secret target is invalid")
            rendered_env[(instance, sid)] = (target + "=" + env_escape(values[sid]) + "\n").encode()
        elif delivery == "file":
            rendered_file[(instance, sid)] = values[sid]
        else:
            raise RuntimeError("unsupported secret delivery")
    for (instance, sid), data in {**rendered_env, **rendered_file}.items():
        directory = SECRET_ROOT / instance
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        os.chown(directory, uid, gid)
        target = directory / (sid + ".env" if (instance, sid) in rendered_env else sid)
        atomic_write(target, data, 0o600)
        os.chown(target, uid, gid)


def redact(data: bytes, secrets: dict[str, bytes]) -> str:
    out = data
    for value in sorted((v for v in secrets.values() if v), key=len, reverse=True):
        out = out.replace(value, b"[REDACTED]")
    if len(out) > MAX_CAPTURE:
        out = out[:MAX_CAPTURE] + b"\n[TRUNCATED]"
    return out.decode("utf-8", "replace")


def run_action(script: Path, admin_user: str, secrets: dict[str, bytes], restrict_host: bool) -> tuple[int, str, str]:
    if not restrict_host:
        cp = subprocess.run(["runuser", "-u", admin_user, "--", str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return cp.returncode, redact(cp.stdout, secrets), redact(cp.stderr, secrets)

    # module.yaml actions are intentionally shell scripts, but module code must
    # not inherit the Cloud-init administrator's host-wide sudo authority.
    # systemd creates the mount/capability sandbox before dropping to the
    # administrator UID, so the action can inspect host state and use ordinary
    # unprivileged interfaces without being able to patch Core or the host.
    command = [
        "systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        f"--uid={admin_user}",
        "--property=Type=exec",
        "--property=UMask=0077",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only",
        "--property=PrivateDevices=yes",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectControlGroups=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=LockPersonality=yes",
        str(script),
    ]
    cp = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return cp.returncode, redact(cp.stdout, secrets), redact(cp.stderr, secrets)


def artifact_by_path(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(a.get("path")): a 