"""Content Firewall (ARCHITECTURE 6.8): clean what the agent reads. M5 = deterministic stages
(normalise, decode, heuristics) + spotlighting; the LLM classifier is M6."""

from agentguard.firewall.pipeline import (
    FLAG,
    PASS,
    QUARANTINE,
    SANITIZE,
    FirewallVerdict,
    clear_cache,
    scan,
)
from agentguard.firewall.spotlight import SPOTLIGHT_CLAUSE, make_nonce, spotlight

__all__ = ["scan", "FirewallVerdict", "clear_cache", "spotlight", "make_nonce", "SPOTLIGHT_CLAUSE",
           "PASS", "FLAG", "SANITIZE", "QUARANTINE"]
