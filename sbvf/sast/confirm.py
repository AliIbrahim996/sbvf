"""Live confirmation of static findings against a running target.

After the static scan, the dashboard can optionally *confirm* findings by driving
the search-based engine against a running instance of the application:

    static finding  ->  derived endpoint  ->  GA search  ->  confirmed / not reproduced

This is **connect-only**: it never launches the application (the user runs it
themselves) and only sends HTTP requests to a base URL they provide. The
:class:`~sbvf.oracles.Target` layer refuses any non-local host unless
``allow_remote`` is set, so by default confirmation is restricted to localhost.

Only the HTTP-observable classes are confirmable (``xss``, ``sqli``,
``command_injection``, ``open_redirect``, ``idor`` and the ``missing_auth`` /
public-endpoint probe derived from each IDOR). Code-level findings (crypto,
deserialization, supply chain, exception handling) carry no response signal, so
they are left untouched and simply report no dynamic confirmation.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .bridge import derive_endpoints
from .model import Step
from .routes import Route, RouteKey

# A short, human label per confirmable class for the streamed step text.
_LABEL = {
    "xss": "XSS", "sqli": "SQL injection", "command_injection": "command injection",
    "open_redirect": "open redirect", "idor": "IDOR",
    "missing_auth": "missing authentication (public endpoint)",
}


def _where_suffix(param: Optional[str], where: str) -> str:
    if where == "path":
        return f" [path {param}]"
    if where == "body":
        return f" [POST {param}]"
    return f"?{param}=" if param else ""


class TargetUnreachable(RuntimeError):
    """The base URL could not be reached (the app is probably not running)."""


def confirm_findings(findings: List[dict], base_url: str, *,
                     routes: Optional[Dict[RouteKey, List[Route]]] = None,
                     strip_prefix: str = "", budget: int = 60,
                     algorithm: str = "GA", allow_remote: bool = False,
                     cookies: Optional[dict] = None,
                     on_step: Optional[Callable] = None) -> dict:
    """Confirm *findings* against the app running at *base_url*, in place.

    Each confirmable finding is mapped to one or more endpoints and driven by the
    search; a confirmed finding gains a ``dynamic`` key::

        {"confirmed": True, "checks": [{vuln, path, param, method, where,
                                        algorithm, evals, payload}, ...]}

    Returns ``{"attempted": n, "confirmed": m, "findings": k}`` where *attempted*
    and *confirmed* count probes (so they share a unit) and *findings* is how many
    distinct findings were confirmed. Raises :class:`TargetUnreachable`
    if the base URL cannot be reached at all (so the caller can report it without
    losing the static result). ``Target`` raises ``ValueError`` for a non-local
    host unless *allow_remote* is set.
    """
    from ..oracles import Target
    from ..oracles import Oracle
    from ..algorithms import ALGORITHMS

    algo = ALGORITHMS.get(algorithm) or ALGORITHMS["GA"]

    def step(kind: str, text: str, **data):
        if on_step:
            on_step(Step(kind=kind, text=text, data=data))

    # Preflight: a fresh Target validates the host (ValueError if non-local) and a
    # single request proves the app is actually up before we spend the search budget.
    probe = Target(base_url, allow_remote=allow_remote, cookies=cookies)
    try:
        probe.get("/")
    except Exception as exc:  # URLError / socket error -> not running / wrong port
        raise TargetUnreachable(
            f"could not reach {base_url} - is the application running there? ({exc})")

    attempted = confirmed = findings_confirmed = 0
    for f in findings:
        eps, _ = derive_endpoints([f], strip_prefix, routes or {})
        if not eps:
            continue
        checks = []
        for e in eps:
            attempted += 1
            label = _LABEL.get(e.vuln, e.vuln)
            where = _where_suffix(e.param, e.where)
            try:
                t = Target(base_url, allow_remote=allow_remote, cookies=cookies)
                o = Oracle(t, e.path, e.param, e.vuln, extra=e.extra, method=e.method,
                           where=e.where, path_template=e.path_template)
                res = algo(o, budget, 0)
            except Exception as exc:
                step("confirm", f"   could not test {label} at {e.path}{where}: {exc}")
                continue
            if res.confirmed:
                checks.append({
                    "vuln": e.vuln, "path": e.path, "param": e.param,
                    "method": e.method, "where": e.where, "algorithm": res.algorithm,
                    "evals": res.evals_to_first, "payload": res.best_payload})
                step("confirm", f"   CONFIRMED {label}: {e.method} {e.path}{where} "
                                f"in {res.evals_to_first} request(s)")
            else:
                step("confirm", f"   not reproduced: {label} at {e.path}{where}")
        if checks:
            f["dynamic"] = {"confirmed": True, "checks": checks}
            confirmed += len(checks)         # confirmed probes, same unit as attempted
            findings_confirmed += 1
    return {"attempted": attempted, "confirmed": confirmed,
            "findings": findings_confirmed}
