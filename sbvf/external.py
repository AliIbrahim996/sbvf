"""Adapter for testing the framework against real open-source applications.

Real apps are the external-validity test set (held out from the deterministic
training apps). Targets still run locally; `allow_remote` must be set explicitly
and is intended only for a local lab instance of a deliberately-vulnerable app.

Provides:
  - ExternalEndpoint : a known injection point (path, param, vuln, optional label).
  - light_crawl      : discover GET query parameters by following same-host links.
  - run_external     : run every method against the endpoints and report results.
"""
from __future__ import annotations

import html
import re
import urllib.parse
from dataclasses import dataclass

from .algorithms import ALL_METHODS
from .oracles import Oracle, Target
from . import stats


@dataclass
class ExternalEndpoint:
    path: str
    param: str
    vuln: str                 # "xss" | "sqli" | "command_injection" | "open_redirect"
    label: str = "unknown"    # "vulnerable" for documented points, else "unknown"
    note: str = ""
    extra: dict | None = None  # fixed extra query params (e.g. DVWA's Submit=Submit)
    method: str = "GET"        # GET | POST
    where: str = "query"       # query | body | path
    path_template: str | None = None  # for where == "path": sentinel-marked URL


# --- Known injection points for DSVW (Damn Small Vulnerable Web, @stamparm) -------
# Derived by reading its source: "/?id=" (SQLi), "/?v=" (reflected XSS),
# "/?comment=" (stored XSS). XPath/XXE/LFI points are out of this framework's scope.
DSVW = {
    "base": "http://127.0.0.1:65412",
    "endpoints": [
        ExternalEndpoint("/", "id", "sqli", "vulnerable", "classic SQL injection"),
        ExternalEndpoint("/", "v", "xss", "vulnerable", "reflected XSS"),
        ExternalEndpoint("/", "comment", "xss", "vulnerable", "stored XSS"),
    ],
}


_LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


def light_crawl(target: Target, start_paths=("/",), max_pages=20) -> list[tuple[str, str]]:
    """Return a de-duplicated list of (path, param) GET injection points found by
    following same-host links that carry query parameters. Intentionally shallow."""
    seen_pages, found = set(), []
    queue = list(start_paths)
    while queue and len(seen_pages) < max_pages:
        path = queue.pop(0)
        if path in seen_pages:
            continue
        seen_pages.add(path)
        try:
            r = target.get(path)
        except Exception:
            continue
        for href in _LINK_RE.findall(r.body):
            href = html.unescape(href)   # &amp; -> & so query params parse correctly
            parsed = urllib.parse.urlparse(href)
            if parsed.netloc and parsed.netloc not in target.base:
                continue  # stay on the same host
            qs = urllib.parse.parse_qs(parsed.query)
            page = parsed.path or "/"
            for param in qs:
                pair = (page, param)
                if pair not in found:
                    found.append(pair)
            if parsed.query == "" and page not in seen_pages:
                queue.append(page)
    return found


def run_external(base_url: str, endpoints, runs: int, budget: int,
                 cookies: dict | None = None, methods=None, allow_remote: bool = False):
    """Run every method against each endpoint; return per-endpoint results."""
    methods = methods or ALL_METHODS
    report = []
    for e in endpoints:
        row = {"path": e.path, "param": e.param, "vuln": e.vuln,
               "label": e.label, "note": e.note, "method": e.method,
               "where": e.where, "methods": {}}
        for name, method in methods.items():
            seeds = [0] if name == "Static" else range(runs)
            confirmed, evals = 0, []
            for seed in seeds:
                t = Target(base_url, allow_remote=allow_remote, cookies=cookies)
                o = Oracle(t, e.path, e.param, e.vuln, extra=e.extra,
                           method=e.method, where=e.where, path_template=e.path_template)
                res = method(o, budget, seed)
                if res.confirmed:
                    confirmed += 1
                    evals.append(res.evals_to_first)
            row["methods"][name] = {
                "detections": confirmed, "runs": len(list(seeds)),
                "median_evals": stats.summary(evals)["median"] if evals else None,
                "example_payload": None,
            }
        report.append(row)
    return report
