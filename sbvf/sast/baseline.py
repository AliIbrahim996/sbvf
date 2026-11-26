"""Baseline suppression for the static analyzer (improvement 7.3).

A baseline records the findings that already exist (or have been accepted) so a
later scan reports only what is *new*. Unlike diff mode (7.2), which keys off the
lines a change touched, baseline mode compares the whole finding set by content
fingerprint — so it still flags a newly introduced vulnerability whose sink sits
on an untouched line, and it stays quiet about a known finding even after edits
shift its line number.

Workflow:

    # once, on a known-good commit: snapshot the current findings
    py -3.12 -m sbvf.scan_code . --write-baseline .sbvf-baseline.json

    # thereafter: report only findings not in the baseline
    py -3.12 -m sbvf.scan_code . --baseline .sbvf-baseline.json

The finding identity is :func:`sbvf.sast.sarif.finding_fingerprint` (vuln, file,
source, sink, trimmed code — independent of line number), so baseline and SARIF
agree on what "the same finding" means. Stdlib only; nothing is executed.
"""
from __future__ import annotations

import datetime
import json
from typing import Dict, List, Set

from .engine import counts_of_dicts
from .sarif import finding_fingerprint

BASELINE_VERSION = 1


def build_baseline(result: Dict) -> Dict:
    """Build the baseline document (fingerprint -> small human-readable record)."""
    fps: Dict[str, Dict] = {}
    for f in result.get("findings", []):
        fp = finding_fingerprint(f)
        # First occurrence wins; identical flows on different lines share a key.
        fps.setdefault(fp, {
            "file": f.get("file", ""),
            "line": f.get("line", 0),
            "vuln": f.get("vuln", ""),
            "title": f.get("title", ""),
        })
    return {
        "version": BASELINE_VERSION,
        "tool": "sbvf",
        "created": datetime.datetime.now(datetime.timezone.utc)
                   .replace(microsecond=0).isoformat(),
        "count": len(fps),
        "fingerprints": fps,
    }


def write_baseline(result: Dict, path: str) -> int:
    """Write a baseline of *result*'s findings to *path*; return the fingerprint count."""
    doc = build_baseline(result)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False, sort_keys=True)
    return doc["count"]


def load_baseline(path: str) -> Set[str]:
    """Load a baseline file and return its set of fingerprints.

    Raises :class:`ValueError` if the file is not a recognisable baseline, so the
    CLI can tell "no such baseline / wrong file" from "no new findings".
    """
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or "fingerprints" not in doc:
        raise ValueError(f"{path} is not an SBVF baseline file")
    return set(doc["fingerprints"].keys())


def apply_baseline(result: Dict, baseline: Set[str]) -> Dict:
    """Return a copy of *result* keeping only findings whose fingerprint is NOT in
    *baseline* (i.e. new since the baseline), with recomputed counts and a summary.
    """
    findings: List[Dict] = result.get("findings", [])
    kept = [f for f in findings if finding_fingerprint(f) not in baseline]
    out = dict(result)
    out["findings"] = kept
    out["counts"] = counts_of_dicts(kept)
    out["baseline"] = {
        "baseline_size": len(baseline),
        "total_findings": len(findings),
        "new_findings": len(kept),
        "suppressed": len(findings) - len(kept),
    }
    return out
