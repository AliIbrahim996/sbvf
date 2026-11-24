"""Lightweight grounding context for the Q&A agent.

No vector database: a keyword-overlap ranker over the findings the repository
already stores, plus a short overview of recent scans. Enough to ground answers
about the scan history for a research prototype, and keeps the core dependency
-free. ``rank_findings`` is pure (no DB) so it can be unit-tested directly.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..store import repository

_WORD = re.compile(r"[a-z0-9]+")
# Generic words that carry no signal for matching a question to a finding.
_STOP = {
    "the", "a", "an", "of", "in", "to", "and", "or", "is", "are", "what", "which",
    "how", "do", "does", "did", "my", "me", "for", "on", "with", "that", "this",
    "show", "list", "find", "was", "were", "any", "all", "most", "common", "have",
    "has", "scan", "scans", "finding", "findings", "there", "about", "many", "much",
}


def query_terms(question: str) -> List[str]:
    """Significant lowercase terms from a question (deduped, order preserved)."""
    seen, out = set(), []
    for w in _WORD.findall((question or "").lower()):
        if len(w) > 2 and w not in _STOP and w not in seen:
            seen.add(w)
            out.append(w)
    return out


def _haystack(f: Dict[str, Any]) -> str:
    return " ".join(str(f.get(k, "")) for k in
                    ("title", "vuln", "cwe", "severity", "file", "message", "sink", "source")).lower()


def rank_findings(findings: List[Dict[str, Any]], question: str) -> List[Dict[str, Any]]:
    """Findings sorted by keyword overlap with the question (stable; ties keep order)."""
    terms = query_terms(question)
    if not terms:
        return list(findings)
    scored = []
    for i, f in enumerate(findings):
        hay = _haystack(f)
        score = sum(1 for t in terms if t in hay)
        scored.append((score, i, f))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [f for _, _, f in scored]


def _loc(f: Dict[str, Any]) -> str:
    return f.get("location") or f"{f.get('file', '')}:{f.get('line', '')}"


def build_context(question: str, *, scan_id: Optional[int] = None,
                  max_scans: int = 10, max_findings: int = 20) -> Dict[str, Any]:
    """Assemble grounding text + citable sources from the repository."""
    lines: List[str] = []
    sources: List[Dict[str, Any]] = []

    if scan_id is not None:
        scan = repository.get_scan(scan_id)
        if not scan:
            return {"text": f"Scan #{scan_id} was not found in the history.", "sources": []}
        lines.append(f"Scan #{scan_id} — {scan.get('root', '')} ({scan.get('scan_type')}), "
                     f"{scan.get('files_scanned')} files, status {scan.get('status')}.")
        for f in rank_findings(scan.get("findings", []), question)[:max_findings]:
            loc = _loc(f)
            lines.append(f"- [{f.get('severity')}] {f.get('title')} ({f.get('cwe')}) at {loc} — "
                         f"{f.get('message') or f.get('how_in', '')}")
            sources.append({"scan_id": scan_id, "location": loc,
                            "severity": f.get("severity"), "cwe": f.get("cwe")})
        return {"text": "\n".join(lines), "sources": sources}

    scans = repository.list_scans(max_scans)
    lines.append(f"There are {len(scans)} recent scan(s) in the history:")
    for s in scans:
        lines.append(f"- scan #{s['id']}: {s.get('root', '')} ({s.get('scan_type')}) — "
                     f"{s.get('findings_count')} findings, {s.get('files_scanned')} files, "
                     f"{s.get('created_at')}")
    matches = repository.search_findings(question, limit=max_findings)
    if matches:
        lines.append("")
        lines.append("Relevant findings across scans:")
        for m in matches:
            loc = _loc(m)
            lines.append(f"- scan #{m.get('scan_id')}: [{m.get('severity')}] "
                         f"{m.get('title')} ({m.get('cwe')}) at {loc}")
            sources.append({"scan_id": m.get("scan_id"), "location": loc,
                            "severity": m.get("severity"), "cwe": m.get("cwe")})
    return {"text": "\n".join(lines), "sources": sources}
