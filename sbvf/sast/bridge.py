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
targets, because the dynamic oracle confirms XSS/SQLi by injecting a GET query
parameter:

* the vulnerability class must be ``xss`` or ``sqli`` (what the oracle checks);
* the input must be a GET/REQUEST query parameter (POST bodies, cookies, headers
  and URL *path* segments are reported statically but not auto-confirmed);
* the route must be recoverable:
    - **native PHP** is file-routed: ``shop/item.php`` + ``$_GET['id']`` ->
      ``/shop/item.php?id=``;
    - **Django / FastAPI** routes are read from ``urls.py`` / route decorators
      by :mod:`sbvf.sast.routes` and matched to the handler that holds the sink;
    - Laravel / Yii / native Python have no statically-recoverable route table
      here, so their findings stay static-only.

These limitations are documented in the thesis as threats to validity.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..external import ExternalEndpoint
from .routes import Route, RouteKey, lookup

# Vulnerability classes the dynamic oracle can confirm.
DYNAMIC_VULNS = {"xss", "sqli"}
# Input methods reachable by a GET request.
GET_METHODS = {"GET", "REQUEST"}
# PHP frameworks whose URL routing is file-based (path == file path).
FILE_ROUTED_PHP = {"php-native"}
# Python frameworks whose routes sbvf.sast.routes can recover.
ROUTED_PY = {"django", "fastapi"}


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


def derive_endpoints(findings: List[dict], strip_prefix: str = "",
                     routes: Optional[Dict[RouteKey, List[Route]]] = None
                     ) -> Tuple[List[ExternalEndpoint], List[dict]]:
    """Split *findings* into dynamic endpoints and static-only leftovers.

    *findings* are ``Finding.to_dict()`` records; *routes* comes from
    :func:`sbvf.sast.routes.extract_routes` (needed for Django/FastAPI).
    Returns ``(endpoints, skipped)``: de-duplicated :class:`ExternalEndpoint`
    objects for the search to confirm, and the findings that could not be
    mapped, each with a ``reason``.
    """
    endpoints: List[ExternalEndpoint] = []
    skipped: List[dict] = []
    seen = set()

    for f in findings:
        path, reason = _resolve(f, strip_prefix, routes or {})
        if reason:
            skipped.append({**f, "reason": reason})
            continue
        key = (path, f["param"], f["vuln"])
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(ExternalEndpoint(
            path=path, param=f["param"], vuln=f["vuln"], label="sast",
            note=f"{f['vuln']} at {f['location']} ({f['method']})"))
    return endpoints, skipped


def _resolve(f: dict, strip_prefix: str, routes) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(url_path, None)`` for a GET-testable finding, else ``(None, reason)``."""
    if f.get("vuln") not in DYNAMIC_VULNS:
        return None, f"class {f.get('vuln')} not confirmable over HTTP GET"
    method = f.get("method")
    if method == "PATH":
        return None, "input is a URL path segment; the oracle injects query parameters"
    if method not in GET_METHODS:
        return None, f"input via {method} is not a GET parameter"
    if not f.get("param"):
        return None, "request parameter could not be recovered"

    fw = f.get("framework")
    if fw in FILE_ROUTED_PHP:
        return _route_for(f["file"], strip_prefix), None
    if fw in ROUTED_PY:
        fn = f.get("function")
        if not fn:
            return None, "sink is not inside a request handler"
        candidates = lookup(routes, f["file"], fn)
        if not candidates:
            return None, f"no URL route found for handler {fn}()"
        getable = [r for r in candidates if "GET" in r.methods or "*" in r.methods]
        if not getable:
            return None, f"route for {fn}() does not accept GET"
        route = getable[0]
        if f["param"] in route.path_params:
            return None, "input is a URL path segment; the oracle injects query parameters"
        return route.path, None
    return None, f"routing for framework '{fw}' is not file-based or recoverable"
