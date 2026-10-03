"""Paths and environment-driven settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
SUITES_DIR = ROOT / "suites"

load_dotenv(ROOT / ".env", override=False)

LLM_MODES = ("off", "record", "replay", "auto")


@dataclass(frozen=True)
class Settings:
    runs_dir: Path
    cache_dir: Path
    llm_mode: str  # off | record | replay
    max_steps: int = 12
    retrieval_k: int = 8


def _path_from_env(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    if not value:
        return default
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def load_settings(llm_mode: str | None = None) -> Settings:
    mode = llm_mode or os.environ.get("AGENTGUARD_LLM_MODE", "record")
    if mode not in LLM_MODES:
        raise ValueError(f"llm_mode must be one of {LLM_MODES}, got {mode!r}")
    return Settings(
        runs_dir=_path_from_env("AGENTGUARD_RUNS_DIR", ROOT / "runs"),
        cache_dir=_path_from_env("AGENTGUARD_CACHE_DIR", ROOT / "cache" / "llm"),
        llm_mode=mode,
    )
