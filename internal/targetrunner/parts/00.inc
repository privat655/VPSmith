#!/usr/bin/env python3
"""VPSmith bundle-local target runner.

The runner is deliberately self-contained in the Python standard library.  It
never owns desired state; it only executes the immutable manifest that is
already inside the approved bundle.
"""
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import io
import json
import os
import pwd
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

PROOF_VERSION = 1
MANIFEST_VERSION = 2
MAX_CAPTURE = 16 * 1024
SECRET_MAGIC = b"VPSMITH-SECRETS-1\n"
BOOTSTRAP_ROOT = Path("/var/tmp/vpsmith-execution")
CORE_ROOT = Path("/var/lib/vpsmith/execution")
CORE_MARKER = CORE_ROOT / ".active"
INVENTORY_ROOT = Path("/var/lib/vpsmith/inventory")
SECRET_ROOT = Path("/var/lib/vpsmith/secrets")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=False) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
        os.chmod(path, mode)
        fsync_dir(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def safe_member(member: tarfile.TarInfo) -> bool:
    p = Path(member.name)
    if member.name.startswith("/") or ".." in p.parts or "\\" in member.name:
        return False
    return member.isfile()


def read_bundle(bundle: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    files: dict[str, bytes] = {}
    with tarfile.open(bundle, "r:") as tf:
        seen: set[str] = set()
        for member in tf.getmembers():
            if not safe_member(member) or member.name in seen:
                raise ValueError(f"unsafe bundle member: {member.name}")
            seen.add(member.name)
            extracted = tf.extractfile(member)
            if extracted is None:
                raise ValueError(f"cannot read bundle member: {member.name}")
            files[member.name] = extracted.read()
    try:
        manifest = json.loads(files["manifest.json"])
        sums = files["SHA256SUMS"].decode("utf-8", "strict")
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("bundle metadata is invalid") from exc
    if manifest.get("format_version") != MANIFEST_VERSION:
        raise ValueError("unsupported bundle format version")
    listed: set[str] = set()
    for line in sums.splitlines():
        if not line:
            continue
        digest, sep, name = line.partition("  ")
        if not sep or len(digest) != 64 or name in listed or name not in