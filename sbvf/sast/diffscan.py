"""Diff-aware reporting for the static analyzer (improvement 7.2).

In CI, a pull request only wants the findings it *introduced*, not the whole
backlog. ``--diff BASE`` scans the working tree as usual, then keeps only the
findings that land on lines the change added or modified relative to ``BASE``
(e.g. ``origin/main`` or a commit SHA). This is exactly the set that becomes
inline PR annotations.

The parsing is a pure function over unified-diff text, so it is unit-testable
without a git repo:

    changed_lines(diff_text) -> {relpath: {new_line_numbers_added}}

:func:`filter_result` then narrows a :func:`sbvf.sast.engine.scan_path` result
to those lines (or, with ``by="file"``, to any finding in a changed file) and
recomputes the counts. Nothing is executed; stdlib only. The git invocation that
produces the diff text lives in :func:`git_diff`, kept thin so the core stays
testable.

Trade-off: line-level filtering reports a finding only when its *sink line* is in
the diff. A change that introduces a vulnerability whose sink sits on an
untouched line is better caught by baseline mode (7.3), which diffs the whole
finding set by fingerprint. Use ``by="file"`` for a looser, file-level gate.
"""
from __future__ import annotations

import os
import re
import subprocess
from typing import Dict, Optional, Set

from .engine import counts_of_dicts  # reuse the single counts implementation

# A hunk header: @@ -oldStart[,oldLen] +newStart[,newLen] @@
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _strip_prefix(path: str) -> str:
    """Drop a leading ``a/`` or ``b/`` git diff prefix and normalise separators."""
    if path.startswith(("a/", "b/")):
        path = path[2:]
    return path.replace("\\", "/")


def changed_lines(diff_text: str) -> Dict[str, Set[int]]:
    """Parse unified-diff text -> ``{relpath: {added/modified new-line numbers}}``.

    Only lines present on the *new* side (added with ``+``) are recorded, keyed by
    the post-image path (``+++ b/<path>``). Deleted files (``+++ /dev/null``) and
    pure deletions contribute nothing.
    """
    out: Dict[str, Set[int]] = {}
    cur_file: Optional[str] = None
    new_line = 0
    in_hunk = False                    # inside a hunk body (after an @@ header)?
    for raw in diff_text.splitlines():
        # A new file section always begins with "diff --git"; reset header state so
        # a body line that happens to read like a header can't leak across files.
        if raw.startswith("diff --git "):
            in_hunk, cur_file = False, None
            continue
        if raw.startswith("@@"):
            m = _HUNK.match(raw)
            if m:
                new_line = int(m.group(1))
                in_hunk = True
            continue
        if not in_hunk:
            # Header territory: only here do "+++ "/"--- " mean file paths.
            if raw.startswith("+++ "):
                target = raw[4:].split("\t", 1)[0].strip()   # drop any tab-timestamp
                cur_file = None if target == "/dev/null" else _strip_prefix(target)
            continue
        # Hunk body: the first character is the diff marker; the rest is content,
        # so a line reading "+++ x" here is an *added* line, not a header.
        if cur_file is None:
            continue
        marker = raw[:1]
        if marker == "+":
            out.setdefault(cur_file, set()).add(new_line)
            new_line += 1
        elif marker == "-":
            pass                       # old side only: new-side counter unchanged
        elif marker == "\\":
            pass                       # "\ No newline at end of file"
        else:
            new_line += 1              # context line advances the new-side counter
    return out


def git_diff(root: str, base: str, *, unified: int = 0) -> str:
    """Return ``git diff`` text for the working tree vs *base*, rooted at *root*.

    Uses ``BASE...`` (two-dot would compare to the index); ``--unified=0`` keeps
    only changed lines. ``--relative`` makes paths relative to *root* and limits
    the diff to it, so they line up with finding paths (which are relative to the
    scanned root) whether *root* is the repo root or a subdirectory. Raises
    :class:`RuntimeError` with git's stderr on failure so the CLI can report a
    bad ref clearly.
    """
    cmd = ["git", "-C", root, "diff", f"--unified={unified}", "--no-color",
           "--relative", f"{base}..."]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:                       # git not installed
        raise RuntimeError(f"git is required for --diff but was not found: {exc}")
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"git diff against '{base}' failed: {msg}")
    return proc.stdout


def filter_result(result: Dict, changed: Dict[str, Set[int]], *, by: str = "line") -> Dict:
    """Return a copy of *result* keeping only findings touched by *changed*.

    ``by="line"`` (default) keeps a finding when its file is changed AND its line
    is among the added/modified lines; ``by="file"`` keeps any finding in a
    changed file. Counts are recomputed; other keys are preserved. A ``diff``
    block records how many findings were dropped, for the CLI/report to show.
    """
    findings = result.get("findings", [])
    kept = []
    for f in findings:
        rel = str(f.get("file", "")).replace("\\", "/")
        if rel not in changed:
            continue
        if by == "file" or int(f.get("line", 0) or 0) in changed[rel]:
            kept.append(f)

    out = dict(result)
    out["findings"] = kept
    out["counts"] = counts_of_dicts(kept)
    out["diff"] = {
        "base_changed_files": len(changed),
        "total_findings": len(findings),
        "reported_findings": len(kept),
        "suppressed": len(findings) - len(kept),
        "mode": by,
    }
    return out
