"""Agent base class and the strict-JSON completion helper.

Every agent turns a payload into a (system, user) prompt, asks a provider, and
parses a JSON object back. :func:`run_json` centralises the "models sometimes
wrap JSON in prose or code fences" problem: it extracts the first JSON object,
and on a parse failure retries **once** with an explicit "JSON only" nudge.
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Dict

from .provider import LLMProvider, ProviderError

_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


class AgentError(RuntimeError):
    """Raised when an agent cannot produce a usable structured result."""


def _extract_json(text: str) -> Dict[str, Any]:
    """Parse the first JSON object out of a model response (tolerates fences/prose)."""
    if not text:
        raise ValueError("empty response")
    candidate = text.strip()
    fence = _FENCE.search(candidate)
    if fence:
        candidate = fence.group(1).strip()
    try:
        obj = json.loads(candidate)
    except json.JSONDecodeError:
        # Fall back to the outermost {...} span.
        start, end = candidate.find("{"), candidate.rfind("}")
        if start == -1 or end <= start:
            raise
        obj = json.loads(candidate[start:end + 1])
    if not isinstance(obj, dict):
        raise ValueError("response was not a JSON object")
    return obj


def run_json(provider: LLMProvider, system: str, user: str, *, max_tokens: int = 1024) -> Dict[str, Any]:
    """Complete and parse a JSON object, retrying once on malformed output."""
    try:
        raw = provider.complete(system, user, max_tokens=max_tokens)
        return _extract_json(raw)
    except ProviderError:
        raise
    except Exception:
        nudge = user + "\n\nReturn ONLY a single valid JSON object, no prose, no code fences."
        try:
            raw = provider.complete(system, nudge, max_tokens=max_tokens)
            return _extract_json(raw)
        except ProviderError:
            raise
        except Exception as exc:
            raise AgentError(f"model did not return valid JSON: {exc}") from exc


class Agent(ABC):
    """One AI task over a finding or a scan."""

    name: str = "agent"

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        ...

    @abstractmethod
    def build_user(self, payload: Dict[str, Any]) -> str:
        """Render the user-side prompt from the agent's input."""

    def run(self, payload: Dict[str, Any], *, max_tokens: int = 1024) -> Dict[str, Any]:
        return run_json(self.provider, self.system_prompt, self.build_user(payload),
                        max_tokens=max_tokens)
