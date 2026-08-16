for a in manifest.get("artifacts", [])}


def action_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(a.get("id")): a for a in manifest.get("actions", [])}


def apply_artifact(spec: dict[str, Any], data: bytes, preconditions: dict[str, str]) -> None:
    target = Path(str(spec["target_path"]))
    desired = str(spec["sha256"])
    if sha256_bytes(data) != desired:
        raise RuntimeError("artifact payload hash mismatch")
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


def post_state(manifest: dict[str, Any]) -> dict[str, Any]:
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