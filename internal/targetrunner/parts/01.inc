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
            if core is None:
                core = read_json_optional(INVENTORY_ROOT / "core.json")
            if str(core.get("source_id", "")) != expected and str(core.get("version", "")) != expected:
                raise RuntimeError("core precondition failed")
        else:
            raise RuntimeError(f"unsupported precondition: {kind}")


def is_core_restore(manifest: dict[str, Any]) -> bool:
    if manifest.get("subject_kind") != "core" or manifest.get("subject_id") != "core":
        return False
    return any(str(action.get("id", "")) == "core-restore" for action in manifest.get("actions", []))


def require_root_only_directory(path: Path) -> None:
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError(f"Core restore staging directory is unsafe: {path}")


def require_core_restore_staging(manifest: dict[str, Any]) -> None:
    if not is_core_restore(manifest):
        return
    bundle_id = str(manifest.get("bundle_id", ""))
    if not bundle_id.startswith("bundle_") or "/" in bundle_id or "\\" in bundle_id or "\x00" in bundle_id:
        raise RuntimeError("Core restore bundle identity is invalid")
    active_dir = CORE_RESTORE_ROOT / "active"
    bundle_root = CORE_RESTORE_ROOT / bundle_id
    claim = active_dir / "bundle"
    payload = bundle_root / "payload.tar.zst"
    try:
        require_root_only_directory(CORE_RESTORE_ROOT)
        require_root_only_directory(active_dir)
        require_root_only_directory(bundle_root)
        claim_st = claim.lstat()
        payload_st = payload.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError("verified Core restore payload is not staged") from exc
    if not stat.S_ISREG(claim_st.st_mode) or claim_st.st_uid != 0 or stat.S_IMODE(claim_st.st_mode) != 0o400:
        raise RuntimeError("Core restore staging claim is unsafe")
    try:
        active_bundle = claim.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Core restore staging claim is invalid") from exc
    if active_bundle != bundle_id + "\n":
        raise RuntimeError("Core restore staging claim does not match bundle")
    if not stat.S_ISREG(payload_st.st_mode) or payload_st.st_uid != 0 or stat.S_IMODE(payload_st.st_mode) != 0o400 or payload_st.st_size <= 0:
        raise RuntimeError("Core restore staged payload is unsafe")


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
          