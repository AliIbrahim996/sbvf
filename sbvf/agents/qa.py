"""The Q&A agent: answer natural-language questions about the scan history.

Unlike the finding agents, Q&A returns prose (not JSON), so it calls the provider
directly instead of :func:`base.run_json`. Answers are constrained to the
retrieved context so the model does not invent scans or findings.
"""
from __future__ import annotations

from .base import Agent
from .provider import LLMProvider

_SYSTEM = (
    "You are a security assistant answering questions about a user's static-analysis "
    "scan history for their own codebases. Answer ONLY from the provided context "
    "(scan summaries and findings). If the answer is not in the context, say you "
    "don't have that information rather than guessing. Be concise and specific; cite "
    "scan numbers and file:line locations when relevant."
)


class QAAgent(Agent):
    name = "qa"

    @property
    def system_prompt(self) -> str:
        return _SYSTEM

    def build_user(self, payload) -> str:
        question = payload.get("question", "")
        context = payload.get("context", "")
        return f"Context:\n{context}\n\nQuestion: {question}"

    def ask(self, question: str, context: str, *, max_tokens: int = 700) -> str:
        return self.provider.complete(self.system_prompt,
                                       self.build_user({"question": question, "context": context}),
                                       max_tokens=max_tokens)


def new_agent(provider: LLMProvider) -> QAAgent:
    return QAAgent(provider)
