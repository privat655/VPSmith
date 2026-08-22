for a in manifest.get("artifacts", [])}


def action_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(a.get("id")): a for a in manifest.get("actions", [])}


def principal_id(name: str, admin_user: str, want_group: bool) -> int:
    if name == "root":
        return 0
    if name == "admin":
        entry = pwd.getpwnam(admin_user)
        return entry.pw_gid if want_group else entry.pw_uid
    raise RuntimeError(f"unsupported directory principal: {name}")


def verify_directory(spec: dict[str, Any], admin_user: str) -> None:
    path = Path(str(spec["path"]))
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"declared target directory is missing: {path}") from exc
    if not stat.S_ISDIR(st.st_mode) or path.is_symlink():
        raise RuntimeError(f"declared target directory is unsafe: {path}")
    expected_uid = principal_id(str(spec["owner"]), admin_user, False)
    expected_gid = principal_id(str(spec["group"]), admin_user, True)
    expected_mode = int(spec["mode"])
    if st.st_uid != expected_uid or st.st_gid != expected_gid or stat.S_IMODE(st.st_mode) != expected_mode:
        raise RuntimeError(f"declared target directory ownership or mode drift: {path}")


def prepare_directories(manifest: dict[str, Any], admin_user: str) -> None:
    for spec in manifest.get("directories", []):
        path = Path(str(spec["path"]))
        if path.exists() or path.is_symlink():
            verify_directory(spec, admin_user)
            continue
        parent = path.parent
        if not parent.is_dir() or parent.is_symlink():
            raise RuntimeError(f"declared target directory parent is missing or unsafe: {parent}")
        uid = principal_id(str(spec["owner"]), admin_user, False)
        gid = principal_id(str(spec["group"]), admin_user, True)
        mode = int(spec["mode"])
        os.mkdir(path, mode)
        os.chown(path, uid, gid)
        os.chmod(path, mode)
        fsync_dir(parent)
        verify_directory(spec, admin_user)


def apply_artifact(spec: dict[str, Any], data: bytes, preconditions: dict[str, str]) -> None:
    target = Path(str(spec["target_path"]))
    desired = str(spec["sha256"])
    if sha256_bytes(data) != desired:
        raise RuntimeError("artifact payload hash mismatch")
    if not target.parent.is_dir() or target.parent.is_symlink():
        raise RuntimeError(f"artifact parent directory is missing or unsafe: {target.parent}")
    if target.exists():
        if not target.is_file() or target.is_symlink():
            raise RuntimeError(f"artifact target is not a regular file: {target}")
        actual = sha256_file(target)
        if actual == desired:
            return
        expected_old = preconditions.get(str(target))
        if not expected_old or actual != expected_old:
            raise RuntimeError(f"artifact drift blocks mutation: {target}")
    atomic_write(target, data, int(spec.get("mode", 0o444)))


def post_state(manifest: dict[str, Any], admin_user: str) -> dict[str, Any]:
    for spec in manifest.get("directories", []):
        verify_directory(spec, admin_user)
    expected = manifest.get("expected_post_state") or {}
    artifacts = expected.get("artifacts") or {}
    observed: dict[str, str] = {}
    for path, digest in artifacts.items():
        p = Path(path)
        if not p.is_file():
            raise RuntimeError(f"post-state artifact missing: {path}")
        got = sha256_file(p)
        if got != digest:
            raise RuntimeError(f"post-state artifact mismatch: {path}")
        observed[path] = got
    return {"target_id": manifest.get("target_vps_id"), "artifacts": observed}


def promote_first_core(bundle: Path, proof: Path, claim: Path) -> None:
    CORE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ("bundles", "proofs", "locks", "claims"):
        (CORE_ROOT / name).mkdir(parents=True, exist_ok=True, mode=0o700)
    dst_bundle = CORE_ROOT / "bundles" / bundle.name
    if dst_bundle.exists() and sha256_file(dst_bundle) != sha256_file(bundle):
        raise RuntimeError("core history already contains different bundle bytes")
    if not dst_bundle.exists():
        shutil.copyfile(bundle, dst_bundle)
        os.chmod(dst_bundle, 0o400)
        with dst_bundle.open("rb") as f:
            os.fsync(f.fileno())
    shutil.copyfile(proof, CORE_ROOT / "proofs" / proof.name)
    os.chmod(CORE_ROOT / "proofs" / proof.name, 0o600)
    if claim.exists():
        shutil.copyfile(claim, CORE_ROOT / "claims" / claim.name)
        os.chmod(CORE_ROOT / "claims" / claim.name, 0o400)
    fsync_dir(CORE_ROOT / "bundles")
    fsync_dir(CORE_ROOT / "proofs")
    fsync_dir(CORE_ROOT / "claims")
    atomic_write(CORE_MARKER, b"v1\n", 0o400)
    fsync_dir(CORE_ROOT)


def execute(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle)
    if sha256_file(bundle) != args.bundle_sha256:
        raise RuntimeError("outer bundle sha256 mismatch")
    manifest, files = read_bundle(bundle)
    if manifest.get("bundle_id") != args.bundle_id or manifest.get("target_vps_id") != args.target_id:
        raise RuntimeError("bundle identity mismatch")
    root = root_for_run()
    for name in ("proofs", "locks", "claims"):
        (root / name).mkdir(parents=True, exist_ok=True, mode=0o700)
    proof_file = proof_path(root, args.run_id)
    validation = manifest.get("kind") == "validation"
    lock_file = root / "locks" / "structural.lock"
    lock_fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
    proof: dict[str, Any] = {
        "format_version": PROOF_VERSION,
        "run_id"