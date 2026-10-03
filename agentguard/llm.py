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


def _build_live_model(cfg: RoleConfig):
    if cfg.provider == "groq":
        if not os.environ.get("GROQ_API_KEY"):
            # A long-running process (the Streamlit server) may predate the key being added.
            key = dotenv_values(ROOT / ".env").get("GROQ_API_KEY")
            if key:
                os.environ["GROQ_API_KEY"] = key
        if not os.environ.get("GROQ_API_KEY"):
            raise LLMUnavailable("GROQ_API_KEY is not set. Add it to the .env file in the project root.")
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

    @classmethod
    def from_config(cls, role: str, tools: Sequence[dict], mode: str, cache_dir: Path) -> LLMClient:
        cfg = load_role_config(role)
        return cls(role, cfg.model, tools, mode, cache_dir, inner=_LazyLive(cfg))

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / key[:2] / f"{key}.json"

    def _live_invoke(self, messages: Sequence[BaseMessage]) -> AIMessage:
        if self._inner is None:
            raise LLMUnavailable("no live model configured")
        if self._bound is None:
            inner = self._inner.get() if isinstance(self._inner, _LazyLive) else self._inner
            self._bound = inner.bind_tools(self.tools) if self.tools and hasattr(inner, "bind_tools") else inner
        for attempt in range(1, RATE_LIMIT_ATTEMPTS + 1):
            try:
                result = self._bound.invoke(list(messages))
                break
            except LLMUnavailable:
                raise
            except Exception as e:  # provider/network errors -> typed error for callers
                wait = rate_limit_wait(e)
                if wait is None or attempt == RATE_LIMIT_ATTEMPTS:
                    raise LLMUnavailable(f"{type(e).__name__}: {e}") from e
                self._sleep(wait)
        if not isinstance(result, AIMessage):
            raise LLMUnavailable(f"model returned {type(result).__name__}, expected AIMessage")
        return result

    def invoke(self, messages: Sequence[BaseMessage]) -> AIMessage:
        key = cache_key(self.role, self.model_name, messages, self.tools)
        path = self._cache_path(key)
        if self.mode == "replay":
            if not path.exists():
                raise CacheMiss(f"no recorded {self.role} response for this request (key {key[:12]})")
            data = json.loads(path.read_text(encoding="utf-8"))
            return messages_from_dict([data["response"]])[0]
        result = self._live_invoke(messages)
        if self.mode == "record":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps({"role": self.role, "model": self.model_name, "response": message_to_dict(result)}),
                encoding="utf-8",
            )
        return result


class _LazyLive:
    """Defers building the provider client (and the API-key check) until first live call."""

    def __init__(self, cfg: RoleConfig):
        self.cfg = cfg
        self._model = None

    def get(self):
        if self._model is None:
            self._model = _build_live_model(self.cfg)
        return self._model


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
