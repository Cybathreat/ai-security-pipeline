"""Helper utilities."""

import hashlib
import re
from pathlib import Path
from typing import Optional


def sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def severity_to_int(severity: str) -> int:
    mapping = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get(severity.lower(), 0)


def truncate_string(value: str, max_length: int = 100) -> str:
    if len(value) <= max_length:
        return value
    return value[:max_length] + "..."


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)
