: args.run_id,
        "bundle_id": args.bundle_id,
        "bundle_sha256": args.bundle_sha256,
        "target_vps_id": args.target_id,
        "kind": manifest.get("kind"),
        "status": "running",
        "phase": "verifying",
        "started_at": now(),
        "steps": [],
    }
    write_proof(proof_file, proof)
    claim = root / "claims" / args.bundle_id
    try:
        fcntl.flock(lock_fd, (fcntl.LOCK_SH if validation else fcntl.LOCK_EX) | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            proof.update(status="failed", phase="lock", finished_at=now(), error="structural operation is locked")
            write_proof(proof_file, proof)
            return 75
        raise
    try:
        proof["phase"] = "preconditions"
        write_proof(proof_file, proof)
        check_preconditions(manifest)
        require_core_restore_staging(manifest)
        if not validation:
            try:
                claim_fd = os.open(claim, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
            except FileExistsError:
                proof.update(status="failed", phase="duplicate", finished_at=now(), error="bundle was already started")
                write_proof(proof_file, proof)
                return 76
            else:
                os.write(claim_fd, (args.run_id + "\n").encode())
                os.fsync(claim_fd)
                os.close(claim_fd)
                fsync_dir(claim.parent)
        fifo = Path(args.secret_fifo)
        fifo.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.mkfifo(fifo, 0o600)
        except FileExistsError:
            st = fifo.lstat()
            if not stat.S_ISFIFO(st.st_mode):
                raise RuntimeError("secret channel path is not a FIFO")
        proof["phase"] = "awaiting-secrets"
        write_proof(proof_file, proof)
        secrets = read_secrets(fifo)
        materialize_secrets(manifest, secrets, args.admin_user, validation)
        proof["phase"] = "steps"
        write_proof(proof_file, proof)
        artifacts = artifact_by_path(manifest)
        actions = action_by_id(manifest)
        artifact_pre = {str(p["subject"]): str(p["expected"]) for p in manifest.get("preconditions", []) if p.get("kind") == "artifact-sha256"}
        for step in manifest.get("steps", []):
            started = now()
            result: dict[str, Any] = {"id": step.get("id"), "started_at": started}
            try:
                if validation and step.get("mutating"):
                    raise RuntimeError("validation bundle contains a mutating step")
                if step.get("kind") == "apply-artifact":
                    if validation or not step.get("mutating"):
                        raise RuntimeError("artifact application requires a mutating structural bundle")
                    rel = str(step.get("artifact", ""))
                    spec = artifacts.get(rel)
                    if spec is None or rel not in files:
                        raise RuntimeError("step references unknown artifact")
                    apply_artifact(spec, files[rel], artifact_pre)
                    code, out, err = 0, "", ""
                elif step.get("kind") == "action":
                    action = actions.get(str(step.get("action", "")))
                    if action is None:
                        raise RuntimeError("step references unknown action")
                    rel = str(action.get("path"))
                    data = files.get(rel)
              