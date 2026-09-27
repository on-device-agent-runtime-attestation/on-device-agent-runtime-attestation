from __future__ import annotations

import hashlib
from pathlib import Path


def stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact(path: Path, expected_digest: str) -> bool:
    return stream_sha256(path) == expected_digest
