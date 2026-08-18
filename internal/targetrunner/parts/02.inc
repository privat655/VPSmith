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


def systemd_unit_state(unit: str) -> dict[str, str]:
    cp = subprocess.run(
        [
            "systemctl",
            "show",
            "--no-pager",
            "--property=ActiveState",
            "--property=SubState",
            "--property=ExecMainStatus",
            "--property=Result",
            unit,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode != 0:
        detail = cp.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError("cannot inspect module action sandbox" + (f": {detail}" if detail else ""))
    state: dict[str, str] = {}
    for line in cp.stdout.decode("utf-8", "replace").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            state[key] = value
    return state


def read_if_exists(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b""


def run_action(
    script: Path,
    admin_user: str,
    secrets: dict[str, bytes],
    runtime_dir: Path,
    run_id: str,
    restrict_host: bool,
    writable_paths: list[str],
    mutating: bool,
) -> tuple[int, str, str]:
    if not restrict_host:
        cp = subprocess.run(["runuser", "-u", admin_user, "--", str(script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return cp.returncode, redact(cp.stdout, secrets), redact(cp.stderr, secrets)

    # module.yaml actions are intentionally shell scripts, but module code must
    # not inherit the Cloud-init administrator's host-wide sudo authority.
    # The writable scope comes from module persistent_storage, never from an
    # individual action. Validation receives no writable exception at all.
    #
    # Do not use systemd-run --wait/--pipe here. Those modes require systemd's
    # full bus connection, which is intentionally unavailable in the minimal
    # target runner service. Start the transient action service through the
    # manager connection, then observe it through systemctl. Output is captured
    # below /run, redacted by this runner, and removed immediately afterwards so
    # action output containing secrets never has to pass through journald.
    io_dir = runtime_dir / "action-io"
    io_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(io_dir, 0o700)
    token = f"{os.getpid()}-{time.monotonic_ns()}"
    unit = f"vpsmith-action-{token}.service"
    stdout_path = io_dir / (token + ".stdout")
    stderr_path = io_dir / (token + ".stderr")
    for path in (stdout_path, stderr_path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)

    parent_unit = f"vpsmith-exec-{run_id}.service"
    command = [
        "systemd-run",
        "--system",
        "--quiet",
        f"--unit={unit}",
        f"--uid={admin_user}",
        "--property=Type=exec",
        "--property=RemainAfterExit=yes",
        "--property=UMask=0077",
        "--property=StandardInput=null",
        f"--property=StandardOutput=file:{stdout_path}",
        f"--property=StandardError=file:{stderr_path}",
        f"--property=BindsTo={parent_unit}",
        f"--property=After={parent_unit}",
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
    ]
    if mutating and writable_paths:
        command.append("--property=ReadWritePaths=" + " ".join(writable_paths))
    command.append(str(script))

    try:
        cp = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if cp.returncode != 0:
            return cp.returncode, redact(cp.stdout, secrets), redact(cp.stderr, secrets)

        state: dict[str, str]
        while True:
            state = systemd_unit_state(unit)
            active = state.get("ActiveState", "")
            sub = state.get("SubState", "")
            if active in ("failed", "inactive") or sub in ("exited", "failed", "dead"):
                break
            time.sleep(0.05)

        try:
            code = int(state.get("ExecMainStatus", "1"))
        except ValueError:
            code = 1
        if state.get("Result") != "success" and code == 0:
            code = 1
        return code, redact(read_if_exists(stdout_path), secrets), redact(read_if_exists(stderr_path), secrets)
    finally:
        subprocess.run(["systemctl", "stop", "--quiet", unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["systemctl", "reset-failed", "--quiet", unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        for path in (stdout_path, stderr_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        try:
            io_dir.rmdir()
        except OSError:
            pass


def artifact_by_path(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(a.get("path")): a 