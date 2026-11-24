"""Orchestrates the finding/scan agents over a stored scan and persists results.

``run_finding_agents`` loads a scan from the repository, resolves a provider,
runs the selected agents (triage + remediation per finding, prioritization once),
writes the outcomes to the persistence layer, and streams progress through an
optional ``on_progress`` callback (used by the SSE endpoint).

Degrades gracefully: no provider configured, a missing scan, or a per-finding
model failure are all reported, never raised out of the request path. A hard
provider error (e.g. a bad API key) short-circuits the remaining findings so the
provider is not hammered with doomed calls.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from ..store import repository
from .base import AgentError
from .finders import PrioritizationAgent, RemediationAgent, TriageAgent
from .provider import ProviderError, get_provider

ALL_AGENTS = ("triage", "remediation", "prioritization")
_MAX_WORKERS = 4


def _assess_one(finding: Dict[str, Any], triage: Optional[TriageAgent],
                remed: Optional[RemediationAgent], stop: threading.Event) -> Dict[str, Any]:
    """Run the per-finding agents for a single finding, catching their errors."""
    out: Dict[str, Any] = {"errors": []}
    if stop.is_set():
        out["errors"].append("aborted")
        return out
    for agent, key in ((triage, "triage"), (remed, "remediation")):
        if agent is None or stop.is_set():
            continue
        try:
            out[key] = agent.normalize(agent.run(finding))
        except ProviderError as exc:
            stop.set()  # the provider itself is broken — stop the whole run
            out["errors"].append(f"{key}: {exc}")
        except AgentError as exc:
            out["errors"].append(f"{key}: {exc}")
    return out


def run_finding_agents(scan_id: int, *, agents: Optional[List[str]] = None,
                       provider_name: Optional[str] = None,
                       on_progress: Optional[Callable[[str, Dict[str, Any]], None]] = None,
                       ) -> Dict[str, Any]:
    emit = on_progress or (lambda event, data: None)

    scan = repository.get_scan(scan_id)
    if scan is None:
        emit("agents_error", {"message": "scan not found (persistence may be disabled)"})
        return {"ok": False, "error": "scan not found"}

    provider = get_provider(provider_name)
    if provider is None:
        emit("agents_error", {"message": "no AI provider is configured"})
        return {"ok": False, "error": "no AI provider configured"}

    selected = [a for a in (agents or ALL_AGENTS) if a in ALL_AGENTS] or list(ALL_AGENTS)
    findings: List[Dict[str, Any]] = scan.get("findings", []) or []
    idmap = repository.finding_ids(scan_id)

    emit("start", {"agents": selected, "provider": provider.name, "model": provider.model,
                   "findings": len(findings)})

    results_by_idx: Dict[int, Dict[str, Any]] = {}
    stop = threading.Event()

    want_triage = "triage" in selected
    want_remed = "remediation" in selected
    if (want_triage or want_remed) and findings:
        triage = TriageAgent(provider) if want_triage else None
        remed = RemediationAgent(provider) if want_remed else None
        started = time.monotonic()
        errors = 0
        with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(findings))) as ex:
            futs = {ex.submit(_assess_one, f, triage, remed, stop): i
                    for i, f in enumerate(findings)}
            for fut in as_completed(futs):
                i = futs[fut]
                res = fut.result()
                results_by_idx[i] = res
                if res.get("errors"):
                    errors += 1
                repository.save_assessment(
                    scan_id, i, finding_id=idmap.get(i), provider=provider.name,
                    model=provider.model, triage=res.get("triage"),
                    remediation=res.get("remediation"))
                emit("assessed", {"idx": i, "triage": res.get("triage"),
                                  "remediation": res.get("remediation"),
                                  "errors": res.get("errors", [])})
        dur = int((time.monotonic() - started) * 1000)
        aborted = stop.is_set()
        for name in [n for n in ("triage", "remediation") if n in selected]:
            repository.save_agent_run(
                scan_id, name, provider.name, provider.model,
                status="error" if aborted and errors >= len(findings) else "completed",
                duration_ms=dur,
                details={"findings": len(findings), "with_errors": errors, "aborted": aborted})

    prioritization: Optional[Dict[str, Any]] = None
    if "prioritization" in selected and findings and not stop.is_set():
        pa = PrioritizationAgent(provider)
        started = time.monotonic()
        try:
            prioritization = pa.normalize(pa.run({"findings": findings}, max_tokens=1500),
                                          len(findings))
            repository.save_prioritization(
                scan_id, provider=provider.name, model=provider.model,
                summary=prioritization["summary"], ranking=prioritization["ranking"])
            repository.save_agent_run(
                scan_id, "prioritization", provider.name, provider.model,
                status="completed", duration_ms=int((time.monotonic() - started) * 1000),
                details={"ranked": len(prioritization["ranking"])})
            emit("prioritized", prioritization)
        except (ProviderError, AgentError) as exc:
            repository.save_agent_run(
                scan_id, "prioritization", provider.name, provider.model, status="error",
                duration_ms=int((time.monotonic() - started) * 1000), error=str(exc))
            emit("agent_error", {"agent": "prioritization", "message": str(exc)})

    out = {"ok": True, "provider": provider.name, "model": provider.model,
           "assessments": results_by_idx, "prioritization": prioritization,
           "aborted": stop.is_set()}
    emit("agents_done", {"provider": provider.name, "model": provider.model,
                         "assessed": len(results_by_idx), "aborted": stop.is_set()})
    return out
