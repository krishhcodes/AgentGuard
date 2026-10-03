"""LLM gateway: per-role model factory, record/replay cache, and a scripted test double.

Cache modes:
  off     live calls, nothing stored
  record  live calls, every response stored (default; enables later offline replay)
  replay  cache only; a miss raises CacheMiss (never a silent live call)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from langchain_core.messages import AIMessage, BaseMessage, message_to_dict, messages_from_dict

from dotenv import dotenv_values

from agentguard.config import CONFIG_DIR, ROOT


RATE_LIMIT_ATTEMPTS = 6
_RETRY_IN_RE = re.compile(r"try again in ([0-9.]+)\s*(ms|s)\b", re.IGNORECASE)
# Full duration parse (handles "1h2m3.4s", "7m12s", "172.5ms", "30s") for daily-vs-minute classification.
_DUR_RE = re.compile(r"try again in\s+((?:[0-9.]+\s*(?:h|ms|m|s)\s*)+)", re.IGNORECASE)  # ms before m
_DUR_PART_RE = re.compile(r"([0-9.]+)\s*(h|ms|m|s)", re.IGNORECASE)
_DAILY_RETRY_THRESHOLD_S = 90.0  # a reset longer than this is a per-day cap, not a per-minute one


def rate_limit_wait(error: Exception) -> float | None:
    """Seconds to wait before retrying a rate-limited call, or None if it isn't a rate limit."""
    text = str(error)
    if "rate_limit" not in text and "429" not in text and type(error).__name__ != "RateLimitError":
        return None
    match = _RETRY_IN_RE.search(text)
    if not match:
        return 5.0
    seconds = float(match.group(1)) / (1000 if match.group(2).lower() == "ms" else 1)
    return min(seconds + 0.5, 60.0)


def _parse_retry_seconds(text: str) -> float | None:
    match = _DUR_RE.search(text)
    if not match:
        return None
    units = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}
    total = sum(float(v) * units[u.lower()] for v, u in _DUR_PART_RE.findall(match.group(1)))
    return total or None


def classify_rate_limit(error: Exception) -> tuple[str | None, float]:
    """(kind, wait_seconds). kind is 'tpd' (per-day cap -> rotate key), 'tpm' (per-minute ->
    back off), or None (not a rate limit)."""
    text = str(error)
    low = text.lower()
    if ("rate_limit" not in low and "rate limit" not in low and "429" not in text
            and type(error).__name__ != "RateLimitError"):
        return None, 0.0
    secs = _parse_retry_seconds(text)
    daily = ("per day" in low or "tpd" in low or "rpd" in low
             or (secs is not None and secs > _DAILY_RETRY_THRESHOLD_S))
    return ("tpd" if daily else "tpm"), min((secs if secs is not None else 5.0) + 0.5, 60.0)


def load_groq_keys() -> list[str]:
    """All configured Groq keys, in order, de-duplicated. Reads os.environ and .env, accepting
    GROQ_API_KEYS (comma/space/newline separated) and GROQ_API_KEY / GROQ_API_KEY1.. / GROQ_API_KEY_1.."""
    env = {**dotenv_values(ROOT / ".env"), **os.environ}
    raw: list[str] = []
    if env.get("GROQ_API_KEYS"):
        raw += re.split(r"[,\s]+", env["GROQ_API_KEYS"].strip())
    names = ["GROQ_API_KEY"] + [f"GROQ_API_KEY{i}" for i in range(1, 9)] + [f"GROQ_API_KEY_{i}" for i in range(1, 9)]
    raw += [env[n] for n in names if env.get(n)]
    seen: set[str] = set()
    keys: list[str] = []
    for k in (s.strip() for s in raw):
        if k and k not in seen:
            seen.add(k)
            keys.append(k)
    return keys


class _KeyRing:
    """Process-wide Groq key cursor. Rotation is one-way: a daily-capped key is left behind for the
    rest of the day, so later clients start from the first key that still has budget."""

    def __init__(self, keys: list[str]):
        self.keys = keys
        self.idx = 0

    def current(self) -> str | None:
        return self.keys[self.idx] if self.keys else None

    def rotate(self) -> bool:
        if self.idx < len(self.keys) - 1:
            self.idx += 1
            return True
        return False

    def __len__(self) -> int:
        return len(self.keys)


_KEY_RING: _KeyRing | None = None


def groq_key_ring() -> _KeyRing:
    """Process-wide ring, rebuilt only when the configured key set changes. Rebuilding on change
    keeps the rotation cursor across the many short-lived clients in one eval run, while staying
    correct if the environment is reconfigured (e.g. between tests)."""
    global _KEY_RING
    keys = load_groq_keys()
    if _KEY_RING is None or _KEY_RING.keys != keys:
        _KEY_RING = _KeyRing(keys)
    return _KEY_RING


class LLMUnavailable(RuntimeError):
    """The model could not be reached or returned an unusable response."""


class CacheMiss(LLMUnavailable):
    """Replay mode found no recorded response for this exact request."""


@dataclass(frozen=True)
class RoleConfig:
    provider: str
    model: str
    temperature: float = 0.0
    timeout_s: float = 30.0
    max_retries: int = 1


def load_role_config(role: str, path: Path | None = None) -> RoleConfig:
    with open(path or CONFIG_DIR / "models.yaml", encoding="utf-8") as f:
        roles = yaml.safe_load(f)
    if role not in roles:
        raise KeyError(f"no model configured for role {role!r} in models.yaml")
    return RoleConfig(**roles[role])


def _message_key(m: BaseMessage) -> dict[str, Any]:
    # Message ids are random (assigned by add_messages); exclude them so keys are stable.
    return {
        "type": m.type,
        "content": m.content,
        "tool_calls": [
            {"name": tc["name"], "args": tc["args"], "id": tc.get("id")} for tc in getattr(m, "tool_calls", []) or []
        ],
        "tool_call_id": getattr(m, "tool_call_id", None),
    }


def cache_key(role: str, model: str, messages: Sequence[BaseMessage], tools: Sequence[dict]) -> str:
    payload = json.dumps(
        {"role": role, "model": model, "messages": [_message_key(m) for m in messages], "tools": list(tools)},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _build_live_model(cfg: RoleConfig, api_key: str | None = None):
    if cfg.provider == "groq":
        # Explicit key (from the key ring) wins; otherwise fall back to env / .env (the .env read
        # also covers a long-running process, e.g. the Streamlit server, that predates the key).
        key = api_key or os.environ.get("GROQ_API_KEY") or dotenv_values(ROOT / ".env").get("GROQ_API_KEY")
        if not key:
            raise LLMUnavailable("No GROQ API key is set. Add GROQ_API_KEY (or GROQ_API_KEYS) to .env.")
        os.environ["GROQ_API_KEY"] = key  # the groq sdk and ChatGroq read this at construction
        from langchain_groq import ChatGroq

        return ChatGroq(model=cfg.model, temperature=cfg.temperature, timeout=cfg.timeout_s, max_retries=cfg.max_retries)
    raise LLMUnavailable(f"unsupported provider {cfg.provider!r}")


class LLMClient:
    """Invokes one role's model with tools bound, through the record/replay cache."""

    def __init__(
        self,
        role: str,
        model_name: str,
        tools: Sequence[dict],
        mode: str,
        cache_dir: Path,
        inner: Any = None,
    ):
        self.role = role
        self.model_name = model_name
        self.tools = list(tools)
        self.mode = mode
        self.cache_dir = cache_dir
        self._inner = inner  # a chat model, or anything with .invoke(messages) -> AIMessage
        self._bound = None
        self._sleep = time.sleep
        self.last_latency_ms: float = 0.0  # provider latency of the last call; replays report the recorded one

    @classmethod
    def from_config(cls, role: str, tools: Sequence[dict], mode: str, cache_dir: Path) -> LLMClient:
        cfg = load_role_config(role)
        return cls(role, cfg.model, tools, mode, cache_dir, inner=_LazyLive(cfg))

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / key[:2] / f"{key}.json"

    def _bind(self, lazy, ring):
        if self._bound is not None:
            return self._bound
        model = lazy.get(ring.current()) if lazy is not None else self._inner
        self._bound = model.bind_tools(self.tools) if self.tools and hasattr(model, "bind_tools") else model
        return self._bound

    def _live_invoke(self, messages: Sequence[BaseMessage]) -> AIMessage:
        if self._inner is None:
            raise LLMUnavailable("no live model configured")
        lazy = self._inner if isinstance(self._inner, _LazyLive) else None
        ring = groq_key_ring() if lazy is not None else None
        tpm_attempts = 0
        while True:
            try:
                t0 = time.perf_counter()
                result = self._bind(lazy, ring).invoke(list(messages))
                self.last_latency_ms = (time.perf_counter() - t0) * 1000  # excludes rate-limit backoff
                break
            except LLMUnavailable:
                raise
            except Exception as e:  # provider/network errors -> typed error for callers
                if lazy is None:  # test double / non-groq: original backoff semantics
                    tpm_attempts += 1
                    wait = rate_limit_wait(e)
                    if wait is None or tpm_attempts >= RATE_LIMIT_ATTEMPTS:
                        raise LLMUnavailable(f"{type(e).__name__}: {e}") from e
                    self._sleep(wait)
                    continue
                kind, wait = classify_rate_limit(e)
                if kind is None:
                    raise LLMUnavailable(f"{type(e).__name__}: {e}") from e
                if kind == "tpd":  # daily cap: abandon this key for another, no sleep
                    if ring.rotate():
                        self._bound = None
                        continue
                    raise LLMUnavailable("all Groq API keys hit their daily token limit") from e
                tpm_attempts += 1  # per-minute cap: wait, then rotate once waiting is exhausted
                if tpm_attempts >= RATE_LIMIT_ATTEMPTS:
                    if ring.rotate():
                        self._bound = None
                        tpm_attempts = 0
                        continue
                    raise LLMUnavailable(f"rate limited after {tpm_attempts} attempts: {e}") from e
                self._sleep(wait)
        if not isinstance(result, AIMessage):
            raise LLMUnavailable(f"model returned {type(result).__name__}, expected AIMessage")
        return result

    def invoke(self, messages: Sequence[BaseMessage]) -> AIMessage:
        key = cache_key(self.role, self.model_name, messages, self.tools)
        path = self._cache_path(key)
        # replay and auto both reuse a recorded response when present (free, offline).
        if self.mode in ("replay", "auto") and path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            self.last_latency_ms = float(data.get("latency_ms", 0.0))
            return messages_from_dict([data["response"]])[0]
        if self.mode == "replay":
            raise CacheMiss(f"no recorded {self.role} response for this request (key {key[:12]})")
        result = self._live_invoke(messages)
        if self.mode in ("record", "auto"):  # auto records the live calls it had to make
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"role": self.role, "model": self.model_name, "response": message_to_dict(result),
                            "latency_ms": round(self.last_latency_ms, 1)}),
                encoding="utf-8",
            )
        return result


class _LazyLive:
    """Defers building the provider client until first live call. Caches one model per API key so
    key rotation (the key ring) doesn't rebuild on every call."""

    def __init__(self, cfg: RoleConfig):
        self.cfg = cfg
        self._models: dict[str | None, Any] = {}

    def get(self, api_key: str | None = None):
        if api_key not in self._models:
            self._models[api_key] = _build_live_model(self.cfg, api_key)
        return self._models[api_key]


Step = AIMessage | Callable[[Sequence[BaseMessage]], AIMessage]


class ScriptedChatModel:
    """Deterministic test double: returns predetermined AIMessages in order.

    Used by tests, and later by the `compromised_agent` config (an agent that always
    emits the attacker's calls). A step may be a callable that inspects the history.
    """

    def __init__(self, steps: Sequence[Step]):
        self.steps = list(steps)
        self.calls = 0

    def bind_tools(self, tools):  # tools are irrelevant to a script
        return self

    def invoke(self, messages: Sequence[BaseMessage]) -> AIMessage:
        if self.calls >= len(self.steps):
            return AIMessage(content="(script exhausted)")
        step = self.steps[self.calls]
        self.calls += 1
        return step(messages) if callable(step) else step


def tool_call(name: str, args: dict[str, Any], call_id: str) -> dict[str, Any]:
    return {"name": name, "args": args, "id": call_id, "type": "tool_call"}
