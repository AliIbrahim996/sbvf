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
Only findings that can be mapped to an HTTP request are turned into dynamic
targets, because the dynamic oracle confirms a vulnerability by actually sending a
request and inspecting the response:

* the vulnerability class must be one the oracle checks -- ``xss``, ``sqli``,
  ``command_injection``, ``open_redirect`` or ``idor`` (each IDOR endpoint is also
  probed for missing authentication, i.e. a public endpoint);
* the input must be a recoverable request parameter -- a GET/REQUEST query
  parameter, a URL *path* segment on a routed framework, or a POST body (cookies
  and headers are reported statically but not auto-confirmed);
* the route must be recoverable:
    - **native PHP** is file-routed: ``shop/item.php`` + ``$_GET['id']`` ->
      ``/shop/item.php?id=``;
    - **Django / FastAPI / Express / NestJS** routes are read from routing code
      (``urls.py``, decorators, ``app.get``/``app.use``, ``@Controller``/``@Get``)
      by :mod:`sbvf.sast.routes` and matched to the handler that holds the sink;
    - Laravel / Yii / native Python / native Node have no statically-recoverable
      route table here, so their findings stay static-only.

These limitations are documented in the thesis as threats to validity.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..external import ExternalEndpoint
from .routes import Route, RouteKey, lookup

PATH_SENTINEL = "__SBVF__"       # must match sbvf.oracles.Oracle.PATH_SENTINEL

# Vulnerability classes the dynamic oracle can confirm. Besides the injection
# classes, access-control findings are confirmable too: an IDOR endpoint is driven
# by enumerating object ids as a low-privilege user, and every IDOR endpoint is also
# probed for missing authentication (is the same sensitive data served with no
# identity at all -> a public endpoint, CWE-306).
DYNAMIC_VULNS = {"xss", "sqli", "command_injection", "open_redirect", "idor"}
# Input methods the search can drive, mapped to (http method, injection site).
INPUT_METHODS = {
    "GET": ("GET", "query"), "REQUEST": ("GET", "query"),
    "POST": ("POST", "body"), "PATH": ("GET", "path"),
}
# PHP frameworks whose URL routing is file-based (path == file path).
FILE_ROUTED_PHP = {"php-native"}
# Frameworks whose routes sbvf.sast.routes can recover from routing code.
ROUTED = {"django", "fastapi", "flask", "express", "nestjs"}

# Route-template placeholders: <int:uid> / <uid> (Django), {uid} (FastAPI/Nest), :uid (Express).
_PLACEHOLDER = re.compile(r"<(?:\w+:)?(\w+)>|\{(\w+)(?::[^}]*)?\}|:(\w+)")


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


def _path_template(route: Route, param: str) -> str:
    """Concrete URL for *route* with *param*'s segment replaced by the sentinel
    and every other placeholder filled with a requestable value."""
    def sub(m):
        name = m.group(1) or m.group(2) or m.group(3)
        return PATH_SENTINEL if name == param else "1"
    return _PLACEHOLDER.sub(sub, route.template)


def derive_endpoints(findings: List[dict], strip_prefix: str = "",
                     routes: Optional[Dict[RouteKey, List[Route]]] = None
                     ) -> Tuple[List[ExternalEndpoint], List[dict]]:
    """Split *findings* into dynamic endpoints and static-only leftovers.

    *findings* are ``Finding.to_dict()`` records; *routes* comes from
    :func:`sbvf.sast.routes.extract_routes` (needed for the routed frameworks).
    Returns ``(endpoints, skipped)``: de-duplicated :class:`ExternalEndpoint`
    objects for the search to confirm, and the findings that could not be
    mapped, each with a ``reason``.
    """
    endpoints: List[ExternalEndpoint] = []
    skipped: List[dict] = []
    seen = set()

    for f in findings:
        spec, reason = _resolve(f, strip_prefix, routes or {})
        if reason:
            skipped.append({**f, "reason": reason})
            continue
        for vuln in _confirm_classes(f["vuln"]):
            key = (spec["path"], spec["path_template"], f["param"], vuln, spec["where"])
            if key in seen:
                continue
            seen.add(key)
            note = (f"public-endpoint check for {f['location']}" if vuln == "missing_auth"
                    else f"{vuln} at {f['location']} ({f['method']})")
            endpoints.append(ExternalEndpoint(
                path=spec["path"], param=f["param"], vuln=vuln, label="sast",
                note=note, method=spec["method"], where=spec["where"],
                path_template=spec["path_template"]))
    return endpoints, skipped


def _confirm_classes(vuln: str) -> List[str]:
    """Dynamic checks to run for a static finding of class *vuln*.

    An IDOR endpoint is confirmed two ways: as IDOR (read another user's object as a
    low-privilege user) and as a missing-authentication / public endpoint (the same
    sensitive data served with no identity at all). Other classes map one-to-one.
    """
    if vuln == "idor":
        return ["idor", "missing_auth"]
    return [vuln]


def _resolve(f: dict, strip_prefix: str, routes) -> Tuple[Optional[dict], Optional[str]]:
    """Return ``(endpoint_spec, None)`` for a confirmable finding, else
    ``(None, reason)``. The spec carries path, HTTP method, injection site and,
    for path-segment injection, a sentinel-marked path template."""
    if f.get("vuln") not in DYNAMIC_VULNS:
        return None, f"class {f.get('vuln')} is not dynamically confirmable"
    in_method = f.get("method")
    if in_method not in INPUT_METHODS:
        return None, f"input via {in_method} is not reachable by the HTTP oracle"
    http_method, where = INPUT_METHODS[in_method]
    if not f.get("param") and where != "path":
        return None, "request parameter could not be recovered"

    fw = f.get("framework")
    if fw in FILE_ROUTED_PHP:
        if where == "path":
            return None, "path-segment routing is not modelled for native PHP"
        return {"path": _route_for(f["file"], strip_prefix), "method": http_method,
                "where": where, "path_template": None}, None
    if fw in ROUTED:
        fn = f.get("function")
        if not fn:
            return None, "sink is not inside a request handler"
        candidates = lookup(routes, f["file"], fn)
        if not candidates:
            return None, f"no URL route found for handler {fn}()"
        want = "POST" if http_method == "POST" else "GET"
        usable = [r for r in candidates if want in r.methods or "*" in r.methods]
        if not usable:
            return None, f"route for {fn}() does not accept {want}"
        route = usable[0]
        if where == "path":
            if f.get("param") not in route.path_params:
                return None, "handler parameter is not a URL path segment of its route"
            return {"path": route.path, "method": http_method, "where": "path",
                    "path_template": _path_template(route, f["param"])}, None
        return {"path": route.path, "method": http_method, "where": where,
                "path_template": None}, None
    return None, f"routing for framework '{fw}' is not file-based or recoverable"
