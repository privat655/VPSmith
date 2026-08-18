      if data is None or sha256_bytes(data) != action.get("sha256"):
                        raise RuntimeError("action payload hash mismatch")
                    work_dir = Path(args.work_dir)
                    os.chmod(work_dir, 0o711)
                    action_dir = work_dir / "actions"
                    action_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                    uid = pwd.getpwnam(args.admin_user).pw_uid
                    gid = pwd.getpwnam(args.admin_user).pw_gid
                    os.chown(action_dir, uid, gid)
                    script = action_dir / (str(step.get("action")) + ".sh")
                    atomic_write(script, data, 0o500)
                    os.chown(script, uid, gid)
                    code, out, err = run_action(
                        script,
                        args.admin_user,
                        secrets,
                        manifest.get("subject_kind") == "module",
                        [str(p) for p in manifest.get("action_writable_paths", [])],
                        bool(step.get("mutating")),
                    )
                else:
                    raise RuntimeError("unsupported execution step")
                result.update(exit_code=code, stdout=out, stderr=err, finished_at=now())
                proof["steps"].append(result)
                write_proof(proof_file, proof)
                if code != 0:
                    raise RuntimeError(f"step {step.get('id')} exited with {code}")
            except Exception as exc:
                if not result.get("finished_at"):
                    result.update(exit_code=1, stdout="", stderr="", finished_at=now())
                    proof["steps"].append(result)
                raise exc
        proof["phase"] = "post-validation"
        write_proof(proof_file, proof)
        proof["post_state"] = post_state(manifest)
        if root == BOOTSTRAP_ROOT and manifest.get("subject_kind") == "core":
            proof["phase"] = "promoting-history"
            write_proof(proof_file, proof)
            promote_first_core(bundle, proof_file, claim)
            proof_file = proof_path(CORE_ROOT, args.run_id)
        proof.update(status="success", phase="finished", finished_at=now())
        write_proof(proof_file, proof)
        return 0
    except Exception as exc:
        proof.update(status="failed", phase="failed", finished_at=now(), error=redact(str(exc).encode(), locals().get("secrets", {})))
        write_proof(proof_file, proof)
        return 1
    finally:
        try:
            os.unlink(args.secret_fifo)
        except FileNotFoundError:
            pass
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--bundle", required=True)
    p.add_argument("--bundle-id", required=True)
    p.add_argument("--bundle-sha256", required=True)
    p.add_argument("--target-id", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--admin-user", required=True)
    p.add_argument("--secret-fifo", required=True)
    p.add_argument("--work-dir", required=True)
    return p.parse_args()


def main() -> int:
    try:
        return execute(parse_args())
    except Exception as exc:
        print(f"vpsmith target runner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
