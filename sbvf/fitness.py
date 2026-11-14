"""Fitness functions and oracle predicates.

This is the core research contribution: instead of a binary signal (pass/fail) as in
traditional scanners, we return a continuous value measuring how close a test string
is to exploiting the vulnerability, giving the search algorithm a gradient to climb.

Each function returns (fitness: float in [0,1], confirmed: bool).
confirmed=True means the oracle actually confirmed the vulnerability (not just proximity).
"""
from __future__ import annotations

import re

# Common database error signatures (error-based SQLi oracle).
SQL_ERRORS = [
    r"SQL error", r"sqlite3\.", r"unrecognized token", r"syntax error",
    r"near \".*\": syntax", r"no such column", r"SQLITE_ERROR",
    r"you have an error in your sql syntax", r"ORA-\d{5}", r"PostgreSQL",
]
SQL_ERR_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)

# Proof of XSS execution. Each pattern requires a *literal* unescaped "<", so escaped
# text such as "&lt;img onerror=alert(1)&gt;" does NOT match. This is what distinguishes
# a real injection from safely-encoded output.
XSS_PROOFS = [
    r"<script>alert\(1\)</script>",                       # body-context script tag
    r"<\w+[^>]*\son\w+\s*=\s*alert\(1\)",                 # any tag + injected event handler
                                                          # (covers <img>, <svg>, <details>,
                                                          #  and attribute breakout via <input>)
    r"<\w+[^>]*\ssrc\s*=\s*[\"']?javascript:",            # javascript: URI in a tag
]
XSS_PROOF_RE = re.compile("|".join(XSS_PROOFS), re.IGNORECASE)

DANGEROUS_CHARS = ['<', '>', '"', "'"]


def xss_fitness(payload: str, body: str) -> tuple[float, bool]:
    """XSS fitness = fraction of dangerous chars surviving unencoded + proof bonus."""
    if XSS_PROOF_RE.search(body):
        return 1.0, True
    # How many of the payload's dangerous chars survived literally in the response?
    present = [c for c in DANGEROUS_CHARS if c in payload]
    if not present:
        return 0.0, False
    survived = sum(1 for c in present if c in body)
    base = survived / len(present)  # [0,1)
    # Bonus if the payload is reflected (context is breakable).
    reflected_bonus = 0.3 if payload[:12] and payload[:12] in body else 0.0
    return min(0.95, 0.6 * base + reflected_bonus), False


def sqli_fitness(payload: str, resp_main, resp_baseline=None) -> tuple[float, bool]:
    """SQLi fitness, payload-dependent so the search genuinely matters.

    error-based: an error signature in the body -> confirmed.
    boolean-based: the payload changes the result set relative to a benign baseline
    (e.g. a tautology returns rows the baseline did not) -> confirmed. This depends on
    the payload actually injecting a working condition past any filter.
    """
    body = resp_main.body
    if SQL_ERR_RE.search(body):
        return 1.0, True
    # Boolean signal: payload altered the response vs a benign baseline.
    if resp_baseline is not None and resp_main.status == 200:
        if body != resp_baseline.body and _looks_positive(body) and not _looks_positive(resp_baseline.body):
            return 1.0, True
    # Proximity gradient: the payload carries injection characters that survived.
    gradient = 0.0
    if any(c in body for c in ["'", '"']) and any(c in payload for c in ["'", '"']):
        gradient = 0.3
    if "error" in body.lower():
        gradient = max(gradient, 0.5)
    return gradient, False


def _looks_positive(body: str) -> bool:
    """Heuristic that a SQL response indicates matched rows / successful auth."""
    b = body.lower()
    if "welcome" in b:
        return True
    m = re.search(r"(?:rows?|found)[^0-9]*(\d+)", b)
    return bool(m and int(m.group(1)) > 0)


def clickjacking_fitness(headers: dict, framed_ok: bool | None = None) -> tuple[float, bool]:
    """Clickjacking fitness: absence of header protection (+ iframe-load confirmation
    via Selenium when available)."""
    xfo = (headers.get("X-Frame-Options", "") or "").upper()
    csp = (headers.get("Content-Security-Policy", "") or "").lower()
    protected = ("DENY" in xfo or "SAMEORIGIN" in xfo or "frame-ancestors" in csp)
    if protected:
        return 0.0, False
    if framed_ok is True:            # Selenium confirmed load inside an iframe
        return 1.0, True
    if framed_ok is None:            # no browser check: missing header is a strong signal
        return 0.9, True
    return 0.0, False
