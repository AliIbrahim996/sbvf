"""Command-line entry point for the static (SAST) analyzer.

Scan a local directory, a single file, or a GitHub repository (cloned shallowly,
scanned, then deleted). Unlike the dynamic ``scan_repo`` flow, static analysis
never starts or contacts the application, so it does not need a running server
and performs no network requests to the target.

Examples
--------
    # scan a local project
    python -m sbvf.scan_code path/to/project

    # scan a bundled sample
    python -m sbvf.scan_code testbed/sast_samples/php_laravel

    # clone, scan and remove a public repository
    python -m sbvf.scan_code --repo https://github.com/user/project

    # machine-readable output
    python -m sbvf.scan_code path/to/project --json report.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from .sast import scan_path
from .sast.model import Step


def _clone(repo: str) -> str:
    dest = tempfile.mkdtemp(prefix="sbvf_sast_")
    print(f"[*] Cloning {repo} (shallow) ...")
    subprocess.run(["git", "clone", "--depth", "1", repo, dest], check=True)
    return dest


def _printer(verbose: bool):
    def on_step(step: Step):
        if step.kind in ("detect", "summary"):
            print(f"[*] {step.text}")
        elif step.kind == "finding":
            print(f"    {step.text}")
        elif verbose and step.kind in ("file", "source"):
            print(f"    {step.text}")
    return on_step


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="SBVF static source-code vulnerability analyzer (SAST).")
    ap.add_argument("path", nargs="?", help="local directory or file to scan")
    ap.add_argument("--repo", help="clone this git URL, scan it, then delete it")
    ap.add_argument("--json", help="write the full report to this JSON file")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="also print every file and taint source")
    args = ap.parse_args(argv)

    if not args.path and not args.repo:
        ap.error("provide a PATH to scan or --repo URL")

    cleanup = None
    target = args.path
    if args.repo:
        target = cleanup = _clone(args.repo)

    try:
        result = scan_path(target, on_step=_printer(args.verbose))
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)
            print(f"[*] Removed temporary clone.")

    counts = result["counts"]
    print("\n=== Summary ===")
    print(f"  files scanned : {result['files_scanned']}")
    print(f"  frameworks    : " +
          ", ".join(f"{k}={v}" for k, v in result["frameworks"].items() if v))
    print(f"  findings      : {len(result['findings'])} "
          f"(high={counts['by_severity'].get('high', 0)}, "
          f"medium={counts['by_severity'].get('medium', 0)}, "
          f"low={counts['by_severity'].get('low', 0)})")
    for vuln, n in sorted(counts["by_vuln"].items()):
        print(f"    - {vuln}: {n}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        print(f"  report written to {args.json}")

    # non-zero exit if any high-severity finding (useful in CI gates)
    return 1 if counts["by_severity"].get("high", 0) else 0


if __name__ == "__main__":
    sys.exit(main())
