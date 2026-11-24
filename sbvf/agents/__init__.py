"""Optional, provider-agnostic AI agents over stored SBVF scans.

Isolated from the stdlib-only core scanner and from the persistence layer:
importing this package pulls in no third-party dependency until a provider is
actually used (``anthropic`` / ``openai`` are lazy-imported; Ollama uses only the
standard library). When no provider is configured, :func:`is_enabled` is False
and callers treat AI as switched off — the scanner and history run unchanged.
"""
from __future__ import annotations

from . import provider, runner

__all__ = ["provider", "runner", "is_enabled", "available_providers"]


def is_enabled() -> bool:
    return provider.is_enabled()


def available_providers():
    return provider.available_providers()
