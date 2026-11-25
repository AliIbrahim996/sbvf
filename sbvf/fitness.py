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


# A harmless, unique token the command-injection grammar asks the shell to echo.
# If it appears in the response, an injected command actually executed. Using a
# benign `echo` (not a destructive command) keeps the oracle safe on local labs.
CMDI_MARKER = "SBVFcmdi7r3"


def command_injection_fitness(payload: str, resp, baseline_elapsed: float = 0.0
                              ) -> tuple[float, bool]:
    """Command-injection fitness.

    confirmed: the marker that the injected ``echo`` would print appears in the
    response body (output-based), or the response is far slower than a benign
    baseline when the payload carries a delay command (time-based). Both prove the
    shell actually ran the injected command rather than treating it as data.
    Otherwise a gradient rewards shell metacharacters surviving into the output.
    """
    body = resp.body
    if CMDI_MARKER in body:
        return 1.0, True
    if baseline_elapsed and resp.elapsed > baseline_elapsed + 1.5 \
            and re.search(r"sleep\s+\d|timeout\s+/t|ping\b.*-[nc]\s*\d", payload, re.I):
        return 1.0, True
    gradient = 0.0
    if any(c in payload for c in [";", "|", "&", "`", "$("]):
        gradient = 0.3
        if any(c in body for c in [";", "|", "`"]):      # metachars reflected unfiltered
            gradient = 0.5
    return gradient, False


def open_redirect_fitness(payload: str, resp) -> tuple[float, bool]:
    """Open-redirect fitness.

    confirmed: the response is a redirect (3xx) or a meta refresh whose target is
    the attacker-controlled location carried by the payload -- an absolute URL or
    a scheme-relative ``//host`` pointing off-site. A same-path reflection that is
    not used as a redirect target does not count.
    """
    loc = (resp.headers.get("Location") or resp.headers.get("location") or "").strip()
    target = payload.strip()
    off_site = re.match(r"(?:https?:)?//|https?:\\\\|/\\", target) is not None
    if resp.status in (301, 302, 303, 307, 308) and loc:
        if loc == target or (off_site and target in loc) or loc.startswith(("//", "http")):
            return 1.0, True
        return 0.5, False
    # meta-refresh fallback (some apps redirect in HTML rather than a header)
    m = re.search(r"url=([^\"'>\s]+)", resp.body, re.I)
    if m and off_site and target in m.group(1):
        return 1.0, True
    return (0.3 if off_site else 0.0), False


def idor_fitness(body: str, status: int, my_token: str) -> tuple[float, bool]:
    """IDOR fitness for a low-privilege identity `my_token`.

    Confirmed when the response discloses an object owned by a *different* user
    (an owner marker that is not mine, together with a secret). A 200 for my own
    object is partial progress; a 403/404 is a dead end.
    """
    if status in (401, 403, 404):
        return 0.0, False
    m = re.search(r"owner=(\w+)", body)
    has_secret = "secret=" in body or "FLAG" in body
    if m and has_secret:
        if m.group(1) != my_token:
            return 1.0, True            # read another user's record -> IDOR confirmed
        return 0.4, False               # reached a record, but it is my own
    return 0.2 if status == 200 else 0.0, False


# Markers of a sensitive response body (same testbed vocabulary as the IDOR/RBAC
# oracles): an owned record with a secret, a planted flag, or admin-only content.
_SENSITIVE_RE = re.compile(r"owner=\w+|secret=|FLAG|ADMIN_ONLY", re.IGNORECASE)
# Signals that the app is asking the caller to authenticate rather than serving data.
_LOGIN_RE = re.compile(r"login required|please log in|sign in|unauthori[sz]ed", re.IGNORECASE)


def missing_auth_fitness(body: str, status: int) -> tuple[float, bool]:
    """Missing-authentication (public-endpoint, CWE-306) fitness.

    The request carried NO identity. Confirmed when the endpoint still serves
    sensitive data (an owned record / secret / admin-only content) with a 200. A
    401/403, a redirect to a login page, or a "login required" body is the endpoint
    correctly refusing anonymous access.

    Sensitive data served with a 200 means the endpoint is public, so that check
    comes first: a page that both leaks a record and carries an incidental "sign in"
    nav link is still a public endpoint, not a login prompt.
    """
    if status == 200 and _SENSITIVE_RE.search(body):
        return 1.0, True                      # sensitive data served with no auth -> public
    if status in (401, 403):
        return 0.0, False
    if status in (301, 302, 303, 307, 308):
        return 0.0, False                     # redirected (typically to a login page)
    if status == 200 and _LOGIN_RE.search(body):
        return 0.0, False                     # 200 but it is a login prompt, not data
    return (0.2 if status == 200 else 0.0), False


def rbac_fitness(body: str, status: int) -> tuple[float, bool]:
    """RBAC / broken-access-control fitness for a non-admin identity.

    Confirmed when admin-only content is served to the non-admin caller.
    """
    if status in (401, 403):
        return 0.0, False
    if status == 200 and "ADMIN_ONLY" in body:
        return 1.0, True                # privileged content reached as non-admin
    if status == 200:
        return 0.5, False               # authenticated but no privilege escalation yet
    return 0.1, False


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
