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
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        self.requests += 1
        t0 = time.perf_counter()
        req = urllib.request.Request(url, headers=self._cookie_header())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", "replace")
                return Resp(r.status, body, dict(r.headers), time.perf_counter() - t0)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            return Resp(e.code, body, dict(e.headers), time.perf_counter() - t0)


class Oracle:
    """Binds a vulnerability type to an endpoint and evaluates a single individual."""

    def __init__(self, target: Target, path: str, param: str | None, vuln: str,
                 selenium_checker=None, low_priv_token: str = "u1",
                 extra: dict | None = None):
        self.target = target
        self.path = path
        self.param = param
        self.vuln = vuln
        self.selenium = selenium_checker
        self.low_priv_token = low_priv_token  # identity used for access-control tests
        self.extra = extra or {}  # fixed extra query params (e.g. DVWA's Submit=Submit)
        self._baseline = None  # cached benign response for boolean-based SQLi

    def _params(self, payload) -> dict:
        p = dict(self.extra)
        p[self.param] = payload
        return p

    def evaluate(self, individual) -> tuple[float, bool]:
        payload = individual.render()
        if self.vuln == "xss":
            r = self.target.get(self.path, self._params(payload))
            fit, confirmed = F.xss_fitness(payload, r.body)
            if confirmed and self.selenium is not None:
                confirmed = self.selenium.confirm_xss(self.path, self.param, payload)
            return fit, confirmed
        if self.vuln == "sqli":
            r = self.target.get(self.path, self._params(payload))
            # Benign baseline, constant per endpoint, fetched once for boolean detection.
            if self._baseline is None:
                self._baseline = self.target.get(
                    self.path, self._params("zzz_no_such_value"))
            return F.sqli_fitness(payload, r, self._baseline)
        if self.vuln == "idor":
            # Act as the low-privilege user; the payload is the object id tried.
            r = self.target.get(self.path, {self.param: payload,
                                            "token": self.low_priv_token})
            return F.idor_fitness(r.body, r.status, self.low_priv_token)
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
