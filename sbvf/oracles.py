"""Oracle and request layer.

Sends a test string to the local target, computes fitness, and counts the number
of evaluations (HTTP requests) -- the primary efficiency metric in SBST research.

Safety constraint: rejects any non-local host unless allow_remote=True is passed
explicitly.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from . import fitness as F

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


@dataclass
class Resp:
    status: int
    body: str
    headers: dict
    elapsed: float


class Target:
    def __init__(self, base_url: str, allow_remote: bool = False, timeout: float = 5.0,
                 cookies: dict | None = None):
        host = urllib.parse.urlparse(base_url).hostname or ""
        if host not in LOCAL_HOSTS and not allow_remote:
            raise ValueError(
                f"Target host '{host}' is not local. The framework is restricted to "
                f"localhost for ethical reasons. Pass allow_remote=True only for targets "
                f"you have explicit authorization to test.")
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.cookies = cookies or {}   # session cookies for authenticated real apps
        self.requests = 0  # evaluation counter

    def _cookie_header(self) -> dict:
        if not self.cookies:
            return {}
        return {"Cookie": "; ".join(f"{k}={v}" for k, v in self.cookies.items())}

    def get(self, path: str, params: dict | None = None) -> Resp:
        return self.send("GET", path, query=params)

    def post(self, path: str, data: dict | None = None,
             query: dict | None = None) -> Resp:
        return self.send("POST", path, query=query, body=data)

    def send(self, method: str, path: str, query: dict | None = None,
             body: dict | None = None, follow_redirects: bool = True) -> Resp:
        """Issue one request. With follow_redirects=False a 3xx is returned as-is
        (needed by the open-redirect oracle to read the Location header)."""
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = self._cookie_header()
        data = None
        if body is not None:
            data = urllib.parse.urlencode(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.requests += 1
        t0 = time.perf_counter()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        opener = self._opener(follow_redirects)
        try:
            with opener.open(req, timeout=self.timeout) as r:
                text = r.read().decode("utf-8", "replace")
                return Resp(r.status, text, dict(r.headers), time.perf_counter() - t0)
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            return Resp(e.code, text, dict(e.headers), time.perf_counter() - t0)

    def _opener(self, follow_redirects: bool) -> urllib.request.OpenerDirector:
        if follow_redirects:
            return urllib.request.build_opener()
        return urllib.request.build_opener(_NoRedirect())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return the 3xx response instead of following it, so the oracle can inspect
    the Location header (the open-redirect target)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Oracle:
    """Binds a vulnerability type to an endpoint and evaluates a single individual."""

    # Sentinel in a path template marking where a path-segment payload is injected.
    PATH_SENTINEL = "__SBVF__"

    def __init__(self, target: Target, path: str, param: str | None, vuln: str,
                 selenium_checker=None, low_priv_token: str = "u1",
                 extra: dict | None = None, method: str = "GET",
                 where: str = "query", path_template: str | None = None):
        self.target = target
        self.path = path
        self.param = param
        self.vuln = vuln
        self.selenium = selenium_checker
        self.low_priv_token = low_priv_token  # identity used for access-control tests
        self.extra = extra or {}  # fixed extra query params (e.g. DVWA's Submit=Submit)
        self.method = method.upper()          # GET | POST
        self.where = where                    # query | body | path
        self.path_template = path_template    # for where == "path"
        self._baseline = None  # cached benign response for boolean-based SQLi
        self._baseline_elapsed = 0.0          # benign timing for time-based cmd injection

    def _params(self, payload) -> dict:
        p = dict(self.extra)
        if self.param:
            p[self.param] = payload
        return p

    def _dispatch(self, payload, follow_redirects: bool = True) -> Resp:
        """Send *payload* at the configured location (query / body / path)."""
        if self.where == "path":
            tpl = self.path_template or (self.path.rstrip("/") + "/" + self.PATH_SENTINEL)
            req_path = tpl.replace(self.PATH_SENTINEL, urllib.parse.quote(str(payload), safe=""))
            return self.target.send(self.method, req_path, query=self.extra or None,
                                    follow_redirects=follow_redirects)
        if self.where == "body" or self.method == "POST":
            return self.target.send("POST", self.path, query=self.extra or None,
                                    body=self._params(payload),
                                    follow_redirects=follow_redirects)
        return self.target.send("GET", self.path, query=self._params(payload),
                                follow_redirects=follow_redirects)

    def evaluate(self, individual) -> tuple[float, bool]:
        payload = individual.render()
        if self.vuln == "xss":
            r = self._dispatch(payload)
            fit, confirmed = F.xss_fitness(payload, r.body)
            if confirmed and self.selenium is not None:
                confirmed = self.selenium.confirm_xss(self.path, self.param, payload)
            return fit, confirmed
        if self.vuln == "sqli":
            r = self._dispatch(payload)
            # Benign baseline, constant per endpoint, fetched once for boolean detection.
            if self._baseline is None:
                self._baseline = self._dispatch("zzz_no_such_value")
            return F.sqli_fitness(payload, r, self._baseline)
        if self.vuln == "command_injection":
            if self._baseline_elapsed == 0.0:
                self._baseline_elapsed = self._dispatch("127.0.0.1").elapsed
            r = self._dispatch(payload)
            return F.command_injection_fitness(payload, r, self._baseline_elapsed)
        if self.vuln == "open_redirect":
            r = self._dispatch(payload, follow_redirects=False)
            return F.open_redirect_fitness(payload, r)
        if self.vuln == "idor":
            # Act as the low-privilege user; the payload is the object id tried.
            # Route it through _dispatch so the id lands at the configured site
            # (query / path / body) -- a path-segment id must go in the path, not
            # the query -- while the low-priv token rides along as a query param.
            saved = self.extra
            self.extra = {**self.extra, "token": self.low_priv_token}
            try:
                r = self._dispatch(payload)
            finally:
                self.extra = saved
            return F.idor_fitness(r.body, r.status, self.low_priv_token)
        if self.vuln == "missing_auth":
            # Public-endpoint test: request the object with NO identity. The payload
            # is a benign object id; _dispatch sends it at the configured site
            # (query / path / body). Any session cookies are dropped for this one
            # request so the result reflects a truly unauthenticated caller.
            saved = self.target.cookies
            self.target.cookies = {}
            try:
                r = self._dispatch(payload)
            finally:
                self.target.cookies = saved
            return F.missing_auth_fitness(r.body, r.status)
        if self.vuln == "rbac":
            # Non-admin request plus an optional tampered key=value escalation vector.
            params = {"token": self.low_priv_token}
            vec = payload.strip()
            if "=" in vec:
                k, v = vec.split("=", 1)
                params[k] = v
            r = self.target.get(self.path, params)
            return F.rbac_fitness(r.body, r.status)
        if self.vuln == "clickjacking":
            r = self.target.get(self.path)
            framed = None
            if self.selenium is not None:
                framed = self.selenium.confirm_framing(self.path)
            return F.clickjacking_fitness(r.headers, framed)
        raise ValueError(self.vuln)
