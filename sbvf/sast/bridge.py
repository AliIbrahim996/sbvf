"""Bridge the static analyzer to the dynamic, search-based engine.

The static analyzer (``sbvf.sast``) reads an open-source codebase and reports
tainted source -> sink paths with ``file:line``. On its own it only proves a
flow *exists*. This module turns those findings into concrete HTTP injection
points so the search algorithms (GA / CS / RS) can try to *confirm* them against
the running application:

    static taint analysis  ->  candidate endpoints  ->  GA/CS/RS confirmation

That makes "run our algorithm on an open-source project" automatic: instead of
hand-writing ``--endpoints /:id:sqli``, the static pass discovers the parameters
and the search decides which are actually exploitable.

Scope and honesty
-----------------
Only findings that can be mapped to an HTTP GET request are turned into dynamic
targets, because the dynamic oracle confirms XSS/SQLi over GET:

* the vulnerability class must be ``xss`` or ``sqli`` (what the oracle checks);
* the input must arrive by ``GET`` or ``REQUEST`` (POST/COOKIE/header inputs are
  reported statically but not auto-confirmed here);
* the route must be derivable. For **native PHP** the URL path is the ``.php``
  file's path under the web root, so ``shop/item.php`` with ``$_GET['id']`` maps
  to ``/shop/item.php?id=``. Framework routing tables (Laravel/Yii/Django/
  FastAPI) are *not* file-based, so those endpoints are listed as static-only.

These limitations are documented in the thesis as threats to validity.
"""
from __future__ import annotations

from typing import List, Tuple

from ..external import ExternalEndpoint

# Vulnerability classes the dynamic oracle can confirm.
DYNAMIC_VULNS = {"xss", "sqli"}
# Input methods reachable by a GET request.
GET_METHODS = {"GET", "REQUEST"}
# PHP frameworks whose URL routing is file-based (path == file path).
FILE_ROUTED_PHP = {"php-native"}


def _route_for(file_path: str, strip_prefix: str = "") -> str:
    """Map a source file path to its served URL path (native PHP convention)."""
    rel = file_path.replace("\\", "/")
    if strip_prefix:
        pfx = strip_prefix.strip("/")
        if rel == pfx:
            rel = ""
        elif rel.startswith(pfx + "/"):
            rel = rel[len(pfx) + 1:]
    return "/" + rel.lstrip("/")


def derive_endpoints(findings: List[dict], strip_prefix: str = ""
                     ) -> Tuple[List[ExternalEndpoint], List[dict]]:
    """Split *findings* into dynamic endpoints and static-only leftovers.

    *findings* are ``Finding.to_dict()`` records. Returns
    ``(endpoints, skipped)`` where *endpoints* are de-duplicated
    :class:`ExternalEndpoint` objects for the search to confirm, and *skipped*
    is the findings that could not be mapped (with a ``reason`` added).
    """
    endpoints: List[ExternalEndpoint] = []
    skipped: List[dict] = []
    seen = set()

    for f in findings:
        reason = _unmappable_reason(f)
        if reason:
            skipped.append({**f, "reason": reason})
            continue
        route = _route_for(f["file"], strip_prefix)
        key = (route, f["param"], f["vuln"])
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(ExternalEndpoint(
            path=route, param=f["param"], vuln=f["vuln"], label="sast",
            note=f"{f['vuln']} at {f['location']} ({f['method']})"))
    return endpoints, skipped


def _unmappable_reason(f: dict):
    """Return why a finding cannot become a GET endpoint, or None if it can."""
    if f.get("vuln") not in DYNAMIC_VULNS:
        return f"class {f.get('vuln')} not confirmable over HTTP GET"
    if f.get("framework") not in FILE_ROUTED_PHP:
        return f"routing for framework '{f.get('framework')}' is not file-based"
    if f.get("method") not in GET_METHODS:
        return f"input via {f.get('method')} is not a GET parameter"
    if not f.get("param"):
        return "request parameter could not be recovered"
    return None
