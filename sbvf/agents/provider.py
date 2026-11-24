"""Provider-agnostic LLM access for the optional AI-agents layer.

Three adapters behind one small interface:

* :class:`ClaudeProvider`  — Anthropic (``anthropic`` SDK, lazy-imported)
* :class:`OpenAIProvider`  — OpenAI (``openai`` SDK, lazy-imported)
* :class:`OllamaProvider`  — a local Ollama server (standard-library ``urllib``)

Everything here is optional. :func:`get_provider` returns ``None`` when nothing
is configured, and the rest of the application treats AI as simply switched off
— exactly like the persistence layer degrades without ``DATABASE_URL``. Nothing
in this module is imported by the stdlib-only core scanner.

Configuration (environment):

* ``SBVF_AI_PROVIDER``  — force ``claude`` | ``openai`` | ``ollama`` (optional).
* ``ANTHROPIC_API_KEY`` — enables Claude (the default when several are set).
* ``OPENAI_API_KEY``    — enables OpenAI.
* ``OLLAMA_URL``        — enables a local Ollama server, e.g. ``http://localhost:11434``.
* ``SBVF_AI_MODEL``     — override the model for the selected provider.
"""
from __future__ import annotations

import json
import os
import urllib.request
from abc import ABC, abstractmethod
from typing import List, Optional

# Default models per provider. Deliberately overridable via SBVF_AI_MODEL — the
# repo cannot know which models a given account/host can reach, so these are only
# sensible, widely-available starting points.
_DEFAULT_MODELS = {
    "claude": "claude-3-5-sonnet-latest",
    "openai": "gpt-4o-mini",
    "ollama": "llama3.1",
}

# Preference order when SBVF_AI_PROVIDER is not set and more than one is configured.
_PREFERENCE = ("claude", "openai", "ollama")


class ProviderError(RuntimeError):
    """Raised when a configured provider cannot complete a request."""


class LLMProvider(ABC):
    """Minimal chat interface shared by every provider adapter."""

    name: str = "base"

    def __init__(self, model: Optional[str] = None):
        self.model = model or os.environ.get("SBVF_AI_MODEL") or _DEFAULT_MODELS.get(self.name, "")
        self._client = None  # cached SDK client, created on first use

    @abstractmethod
    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        """Return the model's text response to a (system, user) prompt pair."""


class ClaudeProvider(LLMProvider):
    name = "claude"

    def _client_or_raise(self):
        if self._client is None:
            try:
                import anthropic  # lazy: optional dependency
            except ImportError as exc:  # pragma: no cover - env-specific
                raise ProviderError("the 'anthropic' package is not installed") from exc
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise ProviderError("ANTHROPIC_API_KEY is not set")
            self._client = anthropic.Anthropic(api_key=key)
        return self._client

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        client = self._client_or_raise()
        try:
            msg = client.messages.create(
                model=self.model, max_tokens=max_tokens, system=system,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(
                getattr(block, "text", "") for block in msg.content
                if getattr(block, "type", None) == "text"
            ).strip()
        except Exception as exc:  # network / auth / model errors
            raise ProviderError(f"Claude request failed: {exc}") from exc


class OpenAIProvider(LLMProvider):
    name = "openai"

    def _client_or_raise(self):
        if self._client is None:
            try:
                import openai  # lazy: optional dependency
            except ImportError as exc:  # pragma: no cover - env-specific
                raise ProviderError("the 'openai' package is not installed") from exc
            key = os.environ.get("OPENAI_API_KEY")
            if not key:
                raise ProviderError("OPENAI_API_KEY is not set")
            self._client = openai.OpenAI(api_key=key)
        return self._client

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        client = self._client_or_raise()
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": user}]
        try:
            try:
                resp = client.chat.completions.create(
                    model=self.model, max_tokens=max_tokens, messages=messages)
            except Exception as exc:
                # Newer OpenAI models reject `max_tokens` and require
                # `max_completion_tokens`; retry once with the new parameter.
                if "max_completion_tokens" not in str(exc):
                    raise
                resp = client.chat.completions.create(
                    model=self.model, max_completion_tokens=max_tokens, messages=messages)
            return (resp.choices[0].message.content or "").strip()
        except Exception as exc:
            raise ProviderError(f"OpenAI request failed: {exc}") from exc


class OllamaProvider(LLMProvider):
    """Talks to a local Ollama server using only the standard library."""

    name = "ollama"

    def __init__(self, model: Optional[str] = None, url: Optional[str] = None):
        super().__init__(model)
        self.url = (url or os.environ.get("OLLAMA_URL") or "http://localhost:11434").rstrip("/")

    def complete(self, system: str, user: str, *, max_tokens: int = 1024) -> str:
        payload = {
            "model": self.model, "stream": False,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "options": {"num_predict": max_tokens},
        }
        req = urllib.request.Request(
            f"{self.url}/api/chat", data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 (local URL)
                data = json.loads(resp.read().decode("utf-8"))
            return (data.get("message", {}).get("content") or "").strip()
        except Exception as exc:
            raise ProviderError(f"Ollama request failed: {exc}") from exc


_CLASSES = {"claude": ClaudeProvider, "openai": OpenAIProvider, "ollama": OllamaProvider}


def available_providers() -> List[str]:
    """Names of the providers that are configured in the environment (pref. order)."""
    out = []
    if os.environ.get("ANTHROPIC_API_KEY"):
        out.append("claude")
    if os.environ.get("OPENAI_API_KEY"):
        out.append("openai")
    if os.environ.get("OLLAMA_URL"):
        out.append("ollama")
    return [p for p in _PREFERENCE if p in out]


def is_enabled() -> bool:
    """True when at least one provider is configured."""
    return bool(available_providers())


def get_provider(name: Optional[str] = None) -> Optional[LLMProvider]:
    """Resolve a provider: explicit ``name`` → ``SBVF_AI_PROVIDER`` → preference.

    Returns ``None`` when the requested (or any) provider is not configured, so
    callers can degrade gracefully. Claude is preferred when several are set.
    """
    configured = available_providers()
    if not configured:
        return None
    chosen = (name or os.environ.get("SBVF_AI_PROVIDER") or "").strip().lower() or configured[0]
    if chosen not in _CLASSES or chosen not in configured:
        return None
    return _CLASSES[chosen]()
