"""Command-line entry point for the static (SAST) analyzer.

Scan a local directory, a single file, or a remote repository on GitHub, GitLab
or Bitbucket (cloned shallowly into a temp folder, scanned, then deleted). Other
hosts are rejected; see :mod:`sbvf.sast.repo` for the clone safeguards. Unlike the dynamic ``scan_repo`` flow, static analysis
never starts or contacts the application, so it does not need a running server
and performs no network requests to the target.

Examples
--------
    # scan a local project
    python -m sbvf.scan_code path/to/project

    # scan a bundled sample
    python -m sbvf.scan_code testbed/sast_samples/php_laravel

    # clone, scan and remove a public repository (GitHub / GitLab / Bitbucket)
    python -m sbvf.scan_code https://github.com/user/project
    python -m sbvf.scan_code --repo https://gitlab.com/group/project

    # machine-readable output
    python -m sbvf.scan_code path/to/project --json report.json

    # SARIF for GitHub code scanning / GitLab SAST ingestion
    python -m sbvf.scan_code path/to/project --sarif results.sarif

    # diff mode: only findings on lines changed vs a base ref (pull-request CI)
    python -m sbvf.scan_code . --diff origin/main --sarif results.sarif

    # baseline: snapshot known findings once, then report only new ones
    python -m sbvf.scan_code . --write-baseline .sbvf-baseline.json
    python -m sbvf.scan_code . --baseline .sbvf-baseline.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .sast import scan_path
from .sast.model import Step
from .sast.repo import RepoURLError, clone_repo, is_repo_url, normalize_repo_url, remove_tree


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
    ap.add_argument("path", nargs="?",
                    help="local folder/file, or a GitHub/GitLab/Bitbucket repo URL")
    ap.add_argument("--repo", help="GitHub/GitLab/Bitbucket URL to clone, scan, delete")
    ap.add_argument("--json", help="write the full report to this JSON file")
    ap.add_argument("--sarif", help="write findings as a SARIF 2.1.0 log to this "
                    "file (for GitHub code scanning / GitLab SAST ingestion)")
    ap.add_argument("--diff", metavar="BASE",
                    help="report only findings on lines changed vs BASE (a git ref "
                    "or SHA, e.g. origin/main) — diff mode for pull-request CI")
    ap.add_argument("--diff-by", choices=("line", "file"), default="line",
                    help="granularity of --diff: 'line' (default) keeps findings on "
                    "changed lines; 'file' keeps any finding in a changed file")
    ap.add_argument("--write-baseline", metavar="FILE",
                    help="snapshot the current findings to FILE as a baseline, then "
                    "exit (use on a known-good commit)")
    ap.add_argument("--baseline", metavar="FILE",
                    help="suppress findings present in this baseline FILE; report only "
                    "findings new since it was written")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="also print every file and taint source")
    args = ap.parse_args(argv)

    if not args.path and not args.repo:
        ap.error("provide a PATH to scan or --repo URL")
    if args.diff and (args.repo or (args.path and is_repo_url(args.path))):
        ap.error("--diff compares the working tree against a base ref; it needs a "
                 "local checkout, not a remote repository URL")

    cleanup = None
    target = args.repo or args.path
    if args.repo or is_repo_url(target):
        try:
            url = normalize_repo_url(target)
        except RepoURLError as exc:
            ap.error(f"{exc} (accepted: a local folder or a GitHub, GitLab or "
                     f"Bitbucket repository URL)")
        print(f"[*] Cloning {url} (shallow) ...")
        try:
            target = cleanup = clone_repo(url)
        except RuntimeError as exc:
            print(f"[x] {exc}", file=sys.stderr)
            return 2

    try:
        result = scan_path(target, on_step=_printer(args.verbose))
    finally:
        if cleanup:
            remove_tree(cleanup)
            print("[*] Removed temporary clone.")

    if args.write_baseline:
        from .sast.baseline import write_baseline
        n = write_baseline(result, args.write_baseline)
        print(f"[*] Baseline written: {n} finding(s) -> {args.write_baseline}")
        return 0

    if args.baseline:
        from .sast.baseline import load_baseline, apply_baseline
        try:
            keys = load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"[x] {exc}", file=sys.stderr)
            return 2
        result = apply_baseline(result, keys)
        b = result["baseline"]
        print(f"[*] Baseline vs {args.baseline}: {b['new_findings']} new of "
              f"{b['total_findings']} finding(s) ({b['suppressed']} already in the "
              f"baseline of {b['baseline_size']}).")

    if args.diff:
        from .sast.diffscan import git_diff, changed_lines, filter_result
        try:
            diff_text = git_diff(os.path.abspath(target), args.diff)
        except RuntimeError as exc:
            print(f"[x] {exc}", file=sys.stderr)
            return 2
        changed = changed_lines(diff_text)
        result = filter_result(result, changed, by=args.diff_by)
        d = result["diff"]
        print(f"[*] Diff mode vs {args.diff}: {d['base_changed_files']} changed "
              f"file(s); reporting {d['reported_findings']} of {d['total_findings']} "
              f"finding(s) ({d['suppressed']} outside the diff, by {d['mode']}).")

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

    if args.sarif:
        from .sast.sarif import to_sarif
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(to_sarif(result), fh, indent=2, ensure_ascii=False)
        print(f"  SARIF written to {args.sarif}")

    # non-zero exit if any high-severity finding (useful in CI gates)
    return 1 if counts["by_severity"].get("high", 0) else 0


if __name__ == "__main__":
    sys.exit(main())
