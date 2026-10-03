"""Unseen-set integrity: a SHA-256 manifest of the held-out attack files.

Authored in M1 (before any defence exists). The manifest lets us prove the unseen attacks
were not edited after the freeze. The full freeze protocol (clean git tree, run-once log)
lands in M7; this module provides the hashing it builds on.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from agentguard.config import SUITES_DIR

UNSEEN_DIR = SUITES_DIR / "attacks" / "unseen"
MANIFEST = UNSEEN_DIR / "MANIFEST.sha256"


def _hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _yaml_files(directory: Path) -> list[Path]:
    return sorted(p for p in directory.glob("*.yaml"))


def build_manifest(directory: Path = UNSEEN_DIR) -> str:
    lines = [f"{_hash(p)}  {p.name}" for p in _yaml_files(directory)]
    return "\n".join(lines) + "\n" if lines else ""


def write_manifest(directory: Path = UNSEEN_DIR) -> Path:
    MANIFEST.write_text(build_manifest(directory), encoding="utf-8")
    return MANIFEST


def verify_manifest(directory: Path = UNSEEN_DIR) -> list[str]:
    """Return a list of discrepancies; empty means the unseen set matches the manifest."""
    if not MANIFEST.exists():
        return ["MANIFEST.sha256 is missing"]
    recorded = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split(maxsplit=1)
            recorded[name.strip()] = digest
    current = {p.name: _hash(p) for p in _yaml_files(directory)}
    problems = []
    for name in sorted(set(recorded) | set(current)):
        if name not in current:
            problems.append(f"{name}: in manifest but missing on disk")
        elif name not in recorded:
            problems.append(f"{name}: present on disk but not in manifest")
        elif recorded[name] != current[name]:
            problems.append(f"{name}: hash changed since freeze")
    return problems
