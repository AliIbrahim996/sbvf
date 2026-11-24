"""Dependency-manifest checks for OWASP A03 (Supply Chain).

Unlike the taint analyzers and the line/regex rule engine (which read PHP /
Python / JS *source*), this scanner reads *dependency manifests* — package.json,
composer.json and requirements*.txt — and flags two supply-chain weaknesses:

* ``unpinned_dependency`` (CWE-1104): a floating / unbounded version spec
  (``*``, ``latest``, a ``1.x`` wildcard, an open ``>=`` range, or no version at
  all) that lets a later — possibly malicious — release enter the build without
  review. Caret/tilde (``^1.2`` / ``~1.2``) and pip's compatible-release
  (``~=1.2``) are treated as PINNED: they bound the version and are the
  ecosystem norm, so flagging them would only cry wolf.
* ``insecure_dependency_source`` (CWE-829): a dependency fetched over an
  untrusted channel — ``http://`` (no TLS), ``git://`` or ``git+http://`` — so
  the code can be tampered with in transit or served from a hostile host.

Stdlib only (``json`` + ``re``); no network and no CVE feed, so it never tells
you a *specific* version is vulnerable — only that the declaration itself is a
supply-chain risk. Heuristic: a manifest with unusual syntax may be missed.
"""
from __future__ import annotations

import json
import os
import re
from typing import Callable, List, Optional

from .detect import SKIP_DIRS
from .model import Finding, Step

# Manifest filenames we understand.
_JSON_MANIFESTS = {"package.json", "composer.json"}
_REQ_RE = re.compile(r"requirements.*\.txt$", re.I)
# composer platform requirements / PHP extensions are not real packages.
_NOT_A_PACKAGE = re.compile(r"^(?:php|hhvm|ext-|lib-)", re.I)
# dependency-map keys in npm (first four) and composer (last two).
_DEP_KEYS = ("dependencies", "devDependencies", "peerDependencies",
             "optionalDependencies", "require", "require-dev")


def _insecure_source(spec: str) -> bool:
    """A dependency pulled over a non-TLS / unverified channel."""
    s = spec.strip().lower()
    return "http://" in s or s.startswith(("git://", "git+http://"))


def _npm_unpinned(spec: str) -> bool:
    """True for a floating/unbounded npm or composer version spec.

    Pinned (False): exact ``1.2.3``, caret ``^1.2.3``, tilde ``~1.2.3``, or a
    URL/VCS source (handled separately). Unpinned (True): ``*`` / ``latest`` /
    empty, a ``1.x`` / ``1.*`` wildcard, or an open ``>=`` / ``>`` range.
    """
    s = spec.strip().lower()
    if not s or s in ("*", "latest", "x"):
        return True
    if s.startswith(("^", "~")):            # bounded major/minor — the norm
        return False
    if s.startswith((">", ">=", "<", "<=")):  # open-ended range
        return True
    if ".x" in s or ".*" in s or s.endswith((".x", ".*")):  # 1.x / 1.2.*
        return True
    return False                            # exact or anything we can't judge


def _find_line(raw: str, needle: str) -> int:
    for ln, line in enumerate(raw.splitlines(), 1):
        if needle in line:
            return ln
    return 1


def _emit(vuln: str, rule: str, rel: str, line: int, sink: str, code: str,
          message: str) -> Finding:
    return Finding(
        vuln=vuln, file=rel, line=line, sink=sink[:80], source="dependency manifest",
        framework="", code=code.strip()[:200], message=message, method="", rule=rule,
        how=f"Rule {rule} matched `{sink[:80]}` in the dependency manifest "
            f"{rel}:{line}. {message}")


_UNPINNED_MSG = ("A dependency is declared with a floating or unbounded version "
                 "instead of a pinned one, so a later (possibly malicious) release "
                 "can enter the build without review.")
_SOURCE_MSG = ("A dependency is fetched over an untrusted channel (http:// / git:// "
               "/ git+http), so the code can be tampered with in transit.")


def _scan_json_manifest(rel: str, raw: str) -> List[Finding]:
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: List[Finding] = []
    for key in _DEP_KEYS:
        deps = data.get(key)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            if _NOT_A_PACKAGE.match(name):          # php / ext-* platform reqs
                continue
            line = _find_line(raw, f'"{name}"')
            sink = f"{name}: {spec}"
            if _insecure_source(spec):
                out.append(_emit("insecure_dependency_source", "A03-insecure-source",
                                 rel, line, sink, sink, _SOURCE_MSG))
            elif _npm_unpinned(spec):
                out.append(_emit("unpinned_dependency", "A03-unpinned-dependency",
                                 rel, line, sink, sink, _UNPINNED_MSG))
    return out


def _scan_requirements(rel: str, raw: str) -> List[Finding]:
    out: List[Finding] = []
    for ln, line in enumerate(raw.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if _insecure_source(s):                      # http:// index or git+http VCS
            out.append(_emit("insecure_dependency_source", "A03-insecure-source",
                             rel, ln, s, line, _SOURCE_MSG))
            continue
        if s.startswith("-"):                        # -r / -e https / --hash / options
            continue
        req = s.split("#")[0].split(";")[0].strip()  # drop comment + env marker
        # pinned iff an exact (==) or compatible-release (~=) operator, or a
        # direct URL requirement (name @ url) is present.
        if "==" in req or "~=" in req or "@" in req:
            continue
        out.append(_emit("unpinned_dependency", "A03-unpinned-dependency",
                         rel, ln, req, line, _UNPINNED_MSG))
    return out


def iter_manifests(root: str) -> List[str]:
    """Absolute paths of dependency manifests under *root* (skips vendor dirs)."""
    if os.path.isfile(root):
        base = os.path.basename(root)
        return [root] if base in _JSON_MANIFESTS or _REQ_RE.search(base) else []
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn in _JSON_MANIFESTS or _REQ_RE.search(fn):
                found.append(os.path.join(dirpath, fn))
    return sorted(found)


def scan_supply_chain(root: str, on_step: Optional[Callable[[Step], None]] = None,
                      ) -> List[Finding]:
    """Walk *root* and return supply-chain findings from dependency manifests."""
    root = os.path.abspath(root)
    base = root if os.path.isdir(root) else os.path.dirname(root)
    findings: List[Finding] = []
    for path in iter_manifests(root):
        rel = os.path.relpath(path, base).replace("\\", "/")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            continue
        fname = os.path.basename(path)
        parsed = (_scan_json_manifest(rel, raw) if fname in _JSON_MANIFESTS
                  else _scan_requirements(rel, raw))
        for f in parsed:
            findings.append(f)
            if on_step:
                on_step(Step(
                    kind="finding",
                    text=f"   [{f.severity.upper()}] {f.title} ({f.cwe}) "
                         f"{f.location()} - {f.rule} -> {f.sink}",
                    data={"finding": f.to_dict()}))
    return findings
