"""The three finding/scan agents: triage, remediation and prioritization.

Each builds a compact view of the SAST finding(s) — never the whole file, only
the offending line and its taint metadata — and asks for a small JSON object.
Results are normalised to known types so the caller/DB never sees surprises.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Agent


def _finding_brief(f: Dict[str, Any]) -> str:
    """A compact, prompt-friendly description of one finding."""
    lines = [
        f"Title: {f.get('title') or f.get('vuln')}",
        f"CWE: {f.get('cwe')}   Severity: {f.get('severity')}",
        f"Location: {f.get('location') or (str(f.get('file')) + ':' + str(f.get('line')))}",
        f"Framework: {f.get('framework')}",
        f"Tainted input (source): {f.get('source')}",
        f"Dangerous sink: {f.get('sink')}",
    ]
    if f.get("param"):
        lines.append(f"Request parameter: {f.get('param')} (via {f.get('method')})")
    if f.get("how_in"):
        lines.append(f"How it got in: {f.get('how_in')}")
    if f.get("code"):
        lines.append(f"Offending line:\n{str(f.get('code')).strip()}")
    return "\n".join(lines)


def _clamp01(value: Any, default: float = 0.5) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, v))


class TriageAgent(Agent):
    """Judge whether a finding is a likely false positive."""

    name = "triage"

    @property
    def system_prompt(self) -> str:
        return (
            "You are a senior application-security engineer triaging the output of a "
            "static taint analyzer. Decide whether the reported finding is a TRUE "
            "positive (a real, reachable vulnerability) or a FALSE positive. Judge "
            "only from the taint path and the offending line shown; if the evidence "
            "is insufficient, lean towards it being a true positive but say so. "
            'Respond as JSON: {"is_false_positive": bool, "confidence": number '
            "0-1, \"rationale\": string (<=60 words)}."
        )

    def build_user(self, payload: Dict[str, Any]) -> str:
        return "Triage this static finding:\n\n" + _finding_brief(payload)

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "is_false_positive": bool(raw.get("is_false_positive", False)),
            "confidence": _clamp01(raw.get("confidence")),
            "rationale": str(raw.get("rationale", "")).strip(),
        }


class RemediationAgent(Agent):
    """Produce a code-specific remediation and a one-line summary."""

    name = "remediation"

    @property
    def system_prompt(self) -> str:
        return (
            "You are a secure-coding expert. Given one static finding, explain how to "
            "fix THIS specific code: name the correct API/pattern (parameterized "
            "queries, output encoding, allow-lists, etc.) for the framework shown and "
            "show a short corrected snippet where useful. Be concrete and concise. "
            'Respond as JSON: {"summary": string (<=20 words), "remediation": string '
            "(markdown, <=180 words)}."
        )

    def build_user(self, payload: Dict[str, Any]) -> str:
        return "Give a remediation for this static finding:\n\n" + _finding_brief(payload)

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "summary": str(raw.get("summary", "")).strip(),
            "remediation": str(raw.get("remediation", "")).strip(),
        }


class PrioritizationAgent(Agent):
    """Rank a scan's findings by exploitation risk and summarise the posture."""

    name = "prioritization"

    @property
    def system_prompt(self) -> str:
        return (
            "You are a security lead prioritising remediation work for one codebase "
            "scan. Rank the findings from most to least urgent, considering severity, "
            "exploitability, exposure and blast radius. Keep the given index for each "
            'finding. Respond as JSON: {"summary": string (<=60 words on the overall '
            'risk posture), "ranking": [{"idx": int, "risk_score": number 0-100, '
            '"reason": string (<=25 words)}]}. Include every index exactly once.'
        )

    def build_user(self, payload: Dict[str, Any]) -> str:
        findings: List[Dict[str, Any]] = payload.get("findings", [])
        blocks = []
        for i, f in enumerate(findings):
            blocks.append(
                f"[idx {i}] {f.get('title') or f.get('vuln')} "
                f"({f.get('severity')}, {f.get('cwe')}) at "
                f"{f.get('location') or ''} — sink {f.get('sink')}, source {f.get('source')}"
            )
        return ("Prioritise these findings from one scan:\n\n" + "\n".join(blocks)
                if blocks else "There are no findings to prioritise.")

    def normalize(self, raw: Dict[str, Any], count: int) -> Dict[str, Any]:
        ranking = []
        seen = set()
        for item in raw.get("ranking", []) or []:
            if not isinstance(item, dict):
                continue
            try:
                idx = int(item.get("idx"))
            except (TypeError, ValueError):
                continue
            if idx < 0 or idx >= count or idx in seen:
                continue
            seen.add(idx)
            try:
                score = float(item.get("risk_score", 0))
            except (TypeError, ValueError):
                score = 0.0
            ranking.append({"idx": idx, "risk_score": max(0.0, min(100.0, score)),
                            "reason": str(item.get("reason", "")).strip()})
        # Any findings the model omitted keep their original order at the end.
        for i in range(count):
            if i not in seen:
                ranking.append({"idx": i, "risk_score": 0.0, "reason": ""})
        return {"summary": str(raw.get("summary", "")).strip(), "ranking": ranking}
