"""Third-party SAST benchmark: scan known-vulnerable *external* apps.

The in-repo benchmark (:mod:`sbvf.sast.benchmark`) is self-graded — it scores the
analyzer against samples this project wrote and labelled. A buyer will not accept
that as proof. This harness instead scans **real, third-party vulnerable apps** at
a pinned commit and reports how many of their *documented* vulnerability classes
SBVF recovers.

What it measures, honestly:
  * **documented-class recall** — of the vulnerability classes a given app is known
    to contain, how many SBVF reports at least one finding for;
  * **total findings** — a rough noise signal.

It does **not** claim precision on these apps: their code is not exhaustively
labelled, so a finding with no matching documented class may be a real,
undocumented bug rather than a false positive. Precision needs manual triage.

Each app is shallow-cloned (reusing :func:`sbvf.sast.repo.clone_repo`), scanned
with :func:`sbvf.sast.engine.scan_path`, then deleted. Cloning needs network, so
this is a documented command and a committed results snapshot — not a CI gate.

    py -3.12 -m sbvf.sast.thirdparty_benchmark [--only dvna,dsvw] [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import subprocess
from typing import Dict, List, Optional

from .engine import scan_path
from .repo import clone_repo, remove_tree

# Documented vulnerability classes per app. Keys are model.VULN_INFO classes. An
# optional file_hint narrows a class to findings whose path contains the substring.
# Sources: each app's own documentation and the SBVF thesis scan write-ups.
TARGETS: List[Dict] = [
    {
        "name": "dvna",
        "repo_url": "https://github.com/appsecco/dvna",
        "ref": None,                       # resolved HEAD sha is recorded per run
        "about": "Damn Vulnerable NodeJS Application (Express + EJS)",
        # DVNA's documented OWASP-mapped flaws that SBVF's static classes cover.
        "expected": [
            {"vuln": "sqli"},
            {"vuln": "command_injection"},
            {"vuln": "code_injection"},            # math.js eval / node-serialize RCE
            {"vuln": "open_redirect"},
            {"vuln": "xss"},                       # EJS <%- %> unescaped output
        ],
    },
    {
        "name": "dsvw",
        "repo_url": "https://github.com/stamparm/DSVW",
        "ref": None,
        "about": "Damn Small Vulnerable Web (single-file Python app)",
        "expected": [
            {"vuln": "sqli"},
            {"vuln": "command_injection"},
            {"vuln": "code_injection"},
            {"vuln": "path_traversal"},
            {"vuln": "xss"},
            {"vuln": "open_redirect"},
        ],
    },
]


def match(findings: List[Dict], expected: List[Dict]) -> Dict:
    """Score *findings* against the *expected* documented classes.

    A documented class counts as found when at least one finding has that vuln
    class (and, when a ``file_hint`` is given, a file path containing it). Pure —
    no network or disk — so it is unit-testable.
    """
    found, missed = [], []
    for exp in expected:
        vuln = exp["vuln"]
        hint = exp.get("file_hint")
        hit = any(f.get("vuln") == vuln
                  and (not hint or hint in str(f.get("file", "")))
                  for f in findings)
        (found if hit else missed).append(vuln)
    n = len(expected)
    return {
        "expected": [e["vuln"] for e in expected],
        "found": found,
        "missed": missed,
        "recall": (len(found) / n) if n else None,
    }


def _head_sha(repo_dir: str) -> str:
    try:
        out = subprocess.run(["git", "-C", repo_dir, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip()[:12] if out.returncode == 0 else ""
    except Exception:
        return ""


def _checkout_ref(repo_dir: str, ref: str) -> None:
    """Best-effort pin to a specific commit/tag (servers may refuse a bare sha)."""
    for cmd in (["git", "-C", repo_dir, "fetch", "--depth", "1", "origin", ref],
                ["git", "-C", repo_dir, "checkout", "--quiet", ref]):
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except Exception:
            return


def benchmark_target(target: Dict) -> Dict:
    """Clone, scan and score one app. Clone/scan failures are reported, not raised."""
    row = {"name": target["name"], "about": target.get("about", ""),
           "repo_url": target["repo_url"]}
    clone_dir = None
    try:
        clone_dir = clone_repo(target["repo_url"])
        if target.get("ref"):
            _checkout_ref(clone_dir, target["ref"])
        row["sha"] = _head_sha(clone_dir)
        result = scan_path(clone_dir)
        findings = result.get("findings", [])
        row.update(match(findings, target["expected"]))
        row["total_findings"] = len(findings)
        row["files_scanned"] = result.get("files_scanned", 0)
        row["ok"] = True
    except Exception as exc:
        row["ok"] = False
        row["error"] = str(exc)
    finally:
        if clone_dir:
            remove_tree(clone_dir)
    return row


def run(only: Optional[List[str]] = None) -> Dict:
    targets = [t for t in TARGETS if not only or t["name"] in only]
    rows = [benchmark_target(t) for t in targets]
    scored = [r for r in rows if r.get("ok")]
    exp = sum(len(r["expected"]) for r in scored)
    hit = sum(len(r["found"]) for r in scored)
    return {
        "aggregate": {
            "apps": len(scored),
            "expected_classes": exp,
            "found_classes": hit,
            "recall": round(hit / exp, 4) if exp else None,
        },
        "per_app": rows,
    }


def _print(report: Dict) -> None:
    print("\n=== SBVF third-party benchmark (documented-class recall on real apps) ===\n")
    hdr = f"{'app':10} {'sha':13} {'exp':>4} {'found':>5} {'recall':>7} {'findings':>9}"
    print(hdr)
    print("-" * len(hdr))
    for r in report["per_app"]:
        if not r.get("ok"):
            print(f"{r['name']:10} {'—':13} {'skipped: ' + r.get('error', '')[:40]}")
            continue
        print(f"{r['name']:10} {r.get('sha', ''):13} {len(r['expected']):>4} "
              f"{len(r['found']):>5} {r['recall']:>7.2f} {r['total_findings']:>9}")
        if r["missed"]:
            print(f"{'':10} missed: {', '.join(r['missed'])}")
    a = report["aggregate"]
    print("-" * len(hdr))
    rec = f"{a['recall']:.2f}" if a["recall"] is not None else "n/a"
    print(f"{'AGGREGATE':10} {'':13} {a['expected_classes']:>4} "
          f"{a['found_classes']:>5} {rec:>7}")
    print("\nRecall is over each app's *documented* vulnerability classes. Precision "
          "is not claimed:\nunlabelled findings may be real undocumented bugs; see the "
          "module docstring.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m sbvf.sast.thirdparty_benchmark",
        description="Scan known third-party vulnerable apps and report "
                    "documented-class recall. Clones each app (needs network).")
    ap.add_argument("--only", help="comma-separated app names to run "
                    f"(default: all — {', '.join(t['name'] for t in TARGETS)})")
    ap.add_argument("--json", metavar="OUT", help="also write the full report as JSON")
    args = ap.parse_args(argv)

    only = [s.strip() for s in args.only.split(",")] if args.only else None
    report = run(only)
    _print(report)
    if args.json:
        import os
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nreport written to {args.json}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
