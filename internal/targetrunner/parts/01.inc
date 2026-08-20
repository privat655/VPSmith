 files:
            raise ValueError("invalid SHA256SUMS")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise ValueError("invalid SHA256SUMS digest") from exc
        if sha256_bytes(files[name]) != digest:
            raise ValueError(f"bundle member hash mismatch: {name}")
        listed.add(name)
    expected = set(files) - {"SHA256SUMS"}
    if listed != expected:
        raise ValueError("SHA256SUMS does not cover bundle payload exactly")
    runner = manifest.get("runner") or {}
    rpath = runner.get("path")
    if runner.get("version") != "1" or not isinstance(rpath, str) or rpath not in files:
        raise ValueError("runner identity is invalid")
    if sha256_bytes(files[rpath]) != runner.get("sha256"):
        raise ValueError("runner hash mismatch")
    return manifest, files


def root_for_run() -> Path:
    return CORE_ROOT if CORE_MARKER.is_file() else BOOTSTRAP_ROOT


def proof_path(root: Path, run_id: str) -> Path:
    return root / "proofs" / f"{run_id}.json"


def write_proof(path: Path, proof: dict[str, Any]) -> None:
    atomic_write(path, (json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n").encode(), 0o600)


def read_json_optional(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def inventory_modules() -> dict[str, Any]:
    doc = read_json_optional(INVENTORY_ROOT / "modules.json")
    return {str(x.get("instance_id")): x for x in doc.get("modules", []) if x.get("instance_id")}


def check_preconditions(manifest: dict[str, Any]) -> None:
    modules = inventory_modules()
    core: dict[str, Any] | None = None
    for pre in manifest.get("preconditions", []):
        kind = pre.get("kind")
        subject = str(pre.get("subject", ""))
        expected = str(pre.get("expected", ""))
        if kind == "target":
            if manifest.get("target_vps_id") != subject or expected != "same-target":
                raise RuntimeError("target precondition failed")
        elif kind == "module-version":
            if str(modules.get(subject, {}).get("version", "")) != expected:
                raise RuntimeError(f"module version precondition failed: {subject}")
        elif kind == "module-package-sha256":
            if str(modules.get(subject, {}).get("package_sha256", "")) != expected:
                raise RuntimeError(f"module package precondition failed: {subject}")
        elif kind == "artifact-sha256":
            p = Path(subject)
            if not p.is_file() or sha256_file(p) != expected:
                raise RuntimeError(f"artifact precondition failed: {subject}")
        elif kind in ("core-source-id", "core-package-sha256"):
            if core is None:
                core = read_json_optional(INVENTORY_ROOT / "core.json")
            field = "source_id" if kind == "core-source-id" else "package_sha256"
            if str(core.get(field, "")) != expected:
                raise RuntimeError(f"{kind} precondition failed")
        elif kind == "core":
            # Compatibility for already-created historical bundles. New Core
            # bundles use the exact source-id and package-sha256 checks above.
            if core is None:
                core = read_json_optional(INVENTORY_ROOT / "core.json")
            if str(core.get("source_id", "")) != expected and str(core.get("version", "")) != expected:
                raise RuntimeError("core precondition failed")
        else:
            raise RuntimeError(f"unsupported precondition: {kind}")


def read_secrets(fifo: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    with fifo.open("rb", buffering=0) as stream:
        if stream.read(len(SECRET_MAGIC)) != SECRET_MAGIC:
            raise RuntimeError("secret stream magic mismatch")
        while True:
            raw = stream.read(4)
            if len(raw) != 4:
                raise RuntimeError("truncated secret stream")
            id_len = struct.unpack(">I", raw)[0]
            if id_len == 0:
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