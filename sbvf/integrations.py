"""Integrations for real open-source apps that need authentication or REST endpoints.

- WebSession: a cookie-aware GET/POST client for login flows.
- dvwa_prepare: logs into DVWA, resets its database, selects the "low" security level,
  and returns the session cookies to drive the framework's GET-based oracle.
- DVWA / JUICE_SHOP: endpoint configurations for the two apps.

All targets are expected to run locally (the usual ethical constraint applies).
"""
from __future__ import annotations

import http.cookiejar
import re
import urllib.error
import urllib.parse
import urllib.request

from .external import ExternalEndpoint

_TOKEN_RE = re.compile(r"user_token'?\s*value='?([0-9a-f]{20,})", re.IGNORECASE)


class WebSession:
    """Minimal cookie-aware HTTP client for login/setup flows."""

    def __init__(self, base: str, timeout: float = 15.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def _open(self, req):
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def get(self, path: str):
        return self._open(urllib.request.Request(self.base + path))

    def post(self, path: str, data: dict):
        body = urllib.parse.urlencode(data).encode()
        return self._open(urllib.request.Request(self.base + path, body))

    def cookies(self) -> dict:
        return {c.name: c.value for c in self.jar}


def dvwa_prepare(base: str = "http://127.0.0.1:8081",
                 user: str = "admin", password: str = "password") -> dict:
    """Return session cookies for an authenticated DVWA at 'low' security.

    Steps: scrape the login anti-CSRF token and authenticate, create/reset the
    database, then pin the security level to 'low' via the security cookie.
    """
    s = WebSession(base)

    _, body = s.get("/login.php")
    data = {"username": user, "password": password, "Login": "Login"}
    m = _TOKEN_RE.search(body)
    if m:
        data["user_token"] = m.group(1)
    s.post("/login.php", data)

    _, body = s.get("/setup.php")
    d = {"create_db": "Create / Reset Database"}
    m = _TOKEN_RE.search(body)
    if m:
        d["user_token"] = m.group(1)
    s.post("/setup.php", d)

    cookies = s.cookies()
    cookies["security"] = "low"      # DVWA reads the difficulty from this cookie
    return cookies


# DVWA GET injection points (require the authenticated session cookies above).
DVWA = {
    "base": "http://127.0.0.1:8081",
    "endpoints": [
        ExternalEndpoint("/vulnerabilities/sqli/", "id", "sqli", "vulnerable",
                         "classic SQLi", extra={"Submit": "Submit"}),
        ExternalEndpoint("/vulnerabilities/xss_r/", "name", "xss", "vulnerable",
                         "reflected XSS"),
    ],
}

# OWASP Juice Shop: the product-search endpoint is SQL-injectable over GET and returns
# SQLite error text in its JSON body, which the error-based oracle detects. No auth.
JUICE_SHOP = {
    "base": "http://127.0.0.1:3000",
    "endpoints": [
        ExternalEndpoint("/rest/products/search", "q", "sqli", "vulnerable",
                         "REST product search SQLi"),
    ],
}


def main(argv=None):
    """Run the framework against the known real apps (expects them running locally).

    Start them first, e.g. with docker compose:
        docker compose --profile labs up -d dvwa juice-shop
    """
    import argparse
    from .external import run_external
    ap = argparse.ArgumentParser(description="Run SBVF against DVWA / Juice Shop.")
    ap.add_argument("--app", choices=["dvwa", "juice", "all"], default="all")
    ap.add_argument("--runs", type=int, default=15)
    ap.add_argument("--budget", type=int, default=60)
    args = ap.parse_args(argv)

    def show(title, base, eps, cookies=None):
        print(f"\n=== {title} ===")
        for row in run_external(base, eps, args.runs, args.budget, cookies=cookies):
            print(f"[{row['vuln']}] {row['path']}?{row['param']}=  ({row['note']})")
            for m, d in row["methods"].items():
                print(f"   {m:7} {d['detections']}/{d['runs']}  "
                      f"median_evals={d['median_evals']}")

    if args.app in ("dvwa", "all"):
        show("DVWA (authenticated, security=low)", DVWA["base"],
             DVWA["endpoints"], dvwa_prepare(DVWA["base"]))
    if args.app in ("juice", "all"):
        show("OWASP Juice Shop", JUICE_SHOP["base"], JUICE_SHOP["endpoints"])


if __name__ == "__main__":
    main()
