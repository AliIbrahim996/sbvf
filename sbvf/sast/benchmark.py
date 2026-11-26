"""Precision/recall benchmark for the static analyzer over the labelled testbed.

Improvement 4.7: turn "the scanner detects X" into *measured* numbers.

Ground truth comes from the inline ``VULN:`` markers the sample apps already carry
on each vulnerable sink line (and the absence of markers on their safe
counterparts). For each sample we scan the code and compare the reported
findings' ``(file, line)`` against the marked lines:

    recall        = marked lines with >= 1 finding / marked lines
    class_recall  = marked lines with a finding of the *matching* class / marked lines
    precision     = findings on a marked line / all reported findings

This is a line-level measure over the code the analyzer scans (``.php`` / ``.py``
/ ``.js``). Markers that map to no modelled class, and samples that use section
headers instead of per-line markers, contribute no ground truth and are listed
separately. Nothing is executed -- this is a pure static measurement.

Run it with::

    py -3.12 -m sbvf.sast.benchmark [SAMPLES_DIR] [--json OUT]
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

from .detect import iter_source_files
from .engine import scan_path

_MARKER = re.compile(r"VULN:\s*(.+)")
# Marker free-text -> canonical vulnerability class (first match wins).
_CLASS_KEYWORDS: List[Tuple[str, Tuple[str, ...]]] = [
    ("sqli", ("sql",)),
    ("command_injection", ("command",)),
    ("code_injection", ("code injection",)),
    ("open_redirect", ("open redirect",)),
    ("path_traversal", ("path traversal",)),
    ("file_inclusion", ("file inclusion",)),
    ("ssrf", ("ssrf",)),
    ("idor", ("idor",)),
    ("xss", ("xss", "cross-site")),
]


def _class_of(text: str) -> Optional[str]:
    low = text.lower()
    for cls, kws in _CLASS_KEYWORDS:
        if any(k in low for k in kws):
            return cls
    return None


def _ground_truth(root: str) -> Dict[Tuple[str, int], str]:
    """``{(relfile, line): class}`` for every VULN marker in a scanned source file."""
    base = root if os.path.isdir(root) else os.path.dirname(root)
    out: Dict[Tuple[str, int], str] = {}
    for path in iter_source_files(root):
        rel = os.path.relpath(path, base).replace("\\", "/")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            m = _MARKER.search(line)
            if m:
                cls = _class_of(m.group(1))
                if cls:
                    out[(rel, i)] = cls
    return out


# A VULN marker comment may sit a line or two from the sink it labels, so a
# finding matches a marker when it is in the same file, of the same class, within
# this many lines. Matching is class-aware: a finding of the wrong class nearby
# does not count. Precision still penalises a finding with no marker anywhere near.
_LINE_TOLERANCE = 2


def benchmark_sample(root: str) -> Dict:
    """Scan one sample dir and score it against its VULN markers (class-aware,
    with a small line tolerance for marker/sink placement)."""
    expected = _ground_truth(root)                      # (file, line) -> class
    findings = [(f["file"], f["line"], f["vuln"]) for f in scan_path(root)["findings"]]

    def finding_matches_a_marker(file, line, vuln) -> bool:
        return any(mf == file and mc == vuln and abs(ml - line) <= _LINE_TOLERANCE
                   for (mf, ml), mc in expected.items())

    def marker_is_hit(mf, ml, mc) -> bool:
        return any(f == mf and v == mc and abs(l - ml) <= _LINE_TOLERANCE
                   for (f, l, v) in findings)

    hit = {(mf, ml) for (mf, ml), mc in expected.items() if marker_is_hit(mf, ml, mc)}
    tp_findings = [t for t in findings if finding_matches_a_marker(*t)]
    fp = [t for t in findings if not finding_matches_a_marker(*t)]
    return {
        "sample": os.path.basename(os.path.normpath(root)),
        "expected": len(expected),
        "reported": len(findings),
        "true_positive": len(hit),
        "matched_findings": len(tp_findings),
        "false_negative": sorted(f"{f}:{ln} ({expected[(f, ln)]})"
                                 for (f, ln) in set(expected) - hit),
        "false_positive": sorted(f"{f}:{ln} ({v})" for (f, ln, v) in fp),
        "precision": (len(tp_findings) / len(findings)) if findings else 1.0,
        "recall": (len(hit) / len(expected)) if expected else None,
    }


def run(samples_dir: str) -> Dict:
    """Benchmark every immediate sub-directory of *samples_dir* that has markers."""
    rows = []
    no_truth = []
    for name in sorted(os.listdir(samples_dir)):
        path = os.path.join(samples_dir, name)
        if not os.path.isdir(path):
            continue
        row = benchmark_sample(path)
        if row["expected"] == 0:
            no_truth.append(row["sample"])
        else:
            rows.append(row)

    exp = sum(r["expected"] for r in rows)
    tp = sum(r["true_positive"] for r in rows)
    rep = sum(r["reported"] for r in rows)
    matched = sum(r["matched_findings"] for r in rows)
    precision = matched / rep if rep else 1.0
    recall = tp / exp if exp else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    agg = {
        "samples": len(rows),
        "expected": exp,
        "reported": rep,
        "true_positive": tp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }
    return {"aggregate": agg, "per_sample": rows, "no_ground_truth": no_truth}


def _print(report: Dict) -> None:
    a = report["aggregate"]
    print("\n=== SBVF static-analysis precision/recall "
          "(line-level, labelled testbed) ===\n")
    hdr = f"{'sample':22} {'exp':>4} {'rep':>4} {'TP':>4} {'prec':>6} {'rec':>6}"
    print(hdr)
    print("-" * len(hdr))
    for r in report["per_sample"]:
        print(f"{r['sample']:22} {r['expected']:>4} {r['reported']:>4} "
              f"{r['true_positive']:>4} {r['precision']:>6.2f} {r['recall']:>6.2f}")
    print("-" * len(hdr))
    print(f"{'AGGREGATE':22} {a['expected']:>4} {a['reported']:>4} {a['true_positive']:>4} "
          f"{a['precision']:>6.2f} {a['recall']:>6.2f}")
    print(f"\nprecision={a['precision']}  recall={a['recall']}  F1={a['f1']}")
    if report["no_ground_truth"]:
        print("\nNo per-line ground truth (rule-based / section-header samples): "
              + ", ".join(report["no_ground_truth"]))


def main(argv=None) -> int:
    import argparse
    default_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "testbed", "sast_samples")
    ap = argparse.ArgumentParser(
        prog="python -m sbvf.sast.benchmark",
        description="Precision/recall benchmark for the static analyzer over the "
                    "labelled testbed (ground truth from inline VULN: markers).")
    ap.add_argument("samples_dir", nargs="?", default=default_dir,
                    help="directory of sample sub-projects to score "
                         "(default: the bundled testbed/sast_samples)")
    ap.add_argument("--json", metavar="OUT", help="also write the full report as JSON")
    args = ap.parse_args(argv)

    report = run(args.samples_dir)
    _print(report)
    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nreport written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
