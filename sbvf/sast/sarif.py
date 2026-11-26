"""SARIF 2.1.0 output for the static analyzer (improvement 7.1).

Turns a :func:`sbvf.sast.engine.scan_path` result into a SARIF log so SBVF plugs
straight into GitHub code scanning (``github/codeql-action/upload-sarif``),
GitLab SAST ingestion and any other SARIF-aware tool. Findings then show up as
inline annotations on pull requests, with CWE links and remediation guidance.

Mapping, finding -> SARIF:
  * each distinct vulnerability class becomes a ``reportingDescriptor`` (rule)
    built from :data:`sbvf.sast.model.VULN_INFO` — CWE ``helpUri``, a
    ``security-severity`` score (GitHub reads this to rank the alert), the
    ``security`` / ``external/cwe/cwe-N`` tags code scanning expects, and the
    remediation steps as ``help`` text/markdown;
  * each finding becomes a ``result`` anchored to ``file:line[:column]`` with a
    ``partialFingerprint`` derived from the *content* of the flow (not the line
    number) so an alert stays the same across edits that only shift lines —
    which is what lets later diff/baseline work (7.2/7.3) track it.

Nothing is executed; this only reshapes an existing scan result. Stdlib only.

    py -3.12 -m sbvf.scan_code path/to/project --sarif out.sarif
"""
from __future__ import annotations

import hashlib
from typing import Dict, List

from .model import VULN_INFO

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/AliIbrahim996/sbvf"

# SARIF "level" per our severity tier.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
# GitHub code scanning reads properties["security-severity"] (a 0.0-10.0 CVSS-like
# score) to assign the alert's Critical/High/Medium/Low bucket. Map our tiers to a
# representative score in each band.
_SECURITY_SEVERITY = {"critical": "9.3", "high": "8.1", "medium": "5.5", "low": "3.1"}


def _cwe_number(cwe: str) -> str:
    """"CWE-89" -> "89" (``""`` if not a CWE id)."""
    if cwe and cwe.upper().startswith("CWE-"):
        return cwe[4:]
    return ""


def _rule_for(vuln: str) -> Dict:
    """Build the SARIF reportingDescriptor (rule) for one vulnerability class."""
    info = VULN_INFO.get(vuln, {})
    cwe = info.get("cwe", "")
    num = _cwe_number(cwe)
    title = info.get("title", vuln)
    desc = info.get("desc", title)
    severity = info.get("severity", "low")

    fix_steps = info.get("fix", [])
    impact = info.get("impact", "")
    help_text_parts = [desc]
    if impact:
        help_text_parts.append("Impact: " + impact)
    if fix_steps:
        help_text_parts.append("Remediation:\n" + "\n".join(f"- {s}" for s in fix_steps))
    help_text = "\n\n".join(help_text_parts)
    help_md_parts = [f"**{title}** ({cwe})", desc]
    if impact:
        help_md_parts.append(f"**Impact:** {impact}")
    if fix_steps:
        help_md_parts.append("**Remediation:**\n" + "\n".join(f"- {s}" for s in fix_steps))
    help_md = "\n\n".join(help_md_parts)

    tags = ["security"]
    if num:
        tags.append(f"external/cwe/cwe-{num}")
    props: Dict = {"tags": tags, "security-severity": _SECURITY_SEVERITY.get(severity, "3.1")}
    if cwe:
        props["cwe"] = cwe

    rule: Dict = {
        "id": vuln,
        "name": "".join(w.capitalize() for w in vuln.split("_")),
        "shortDescription": {"text": title},
        "fullDescription": {"text": desc},
        "defaultConfiguration": {"level": _LEVEL.get(severity, "note")},
        "help": {"text": help_text, "markdown": help_md},
        "properties": props,
    }
    if num:
        rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{num}.html"
    return rule


def _fingerprint(f: Dict) -> str:
    """Stable per-finding id from the flow's *content*, not its line number.

    Hashing (vuln, file, source, sink, trimmed code) keeps the fingerprint the
    same when unrelated edits shift the finding up or down the file, so code
    scanning treats it as the same alert across commits.
    """
    parts = [str(f.get("vuln", "")), str(f.get("file", "")),
             str(f.get("source", "")), str(f.get("sink", "")),
             str(f.get("code", "")).strip()]
    digest = hashlib.sha256("\u0000".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def _message(f: Dict) -> str:
    msg = (f.get("message") or "").strip()
    if msg:
        return msg
    title = f.get("title") or f.get("vuln", "Finding")
    src, sink = f.get("source", ""), f.get("sink", "")
    if src and sink:
        return f"{title}: untrusted input from {src} reaches {sink}."
    return title


def _result_for(f: Dict, rule_index: Dict[str, int]) -> Dict:
    vuln = f.get("vuln", "")
    severity = f.get("severity", "low")
    region: Dict = {"startLine": max(1, int(f.get("line", 1) or 1))}
    col = int(f.get("column", 0) or 0)
    if col >= 1:
        region["startColumn"] = col
    snippet = (f.get("code") or "").strip()
    if snippet:
        region["snippet"] = {"text": snippet}

    result: Dict = {
        "ruleId": vuln,
        "level": _LEVEL.get(severity, "note"),
        "message": {"text": _message(f)},
        "locations": [{
            "physicalLocation": {
                # URIs are already relative to the scanned root, which GitHub
                # resolves against the repository root; no uriBaseId needed.
                "artifactLocation": {"uri": f.get("file", "")},
                "region": region,
            }
        }],
        "partialFingerprints": {"sbvfFlow/v1": _fingerprint(f)},
    }
    if vuln in rule_index:
        result["ruleIndex"] = rule_index[vuln]
    props: Dict = {}
    if f.get("cwe"):
        props["cwe"] = f["cwe"]
    if f.get("framework"):
        props["framework"] = f["framework"]
    if f.get("function"):
        props["function"] = f["function"]
    if props:
        result["properties"] = props
    return result


def to_sarif(result: Dict, *, tool_version: str = None) -> Dict:
    """Convert a :func:`scan_path` result dict into a SARIF 2.1.0 log dict."""
    if tool_version is None:
        from .. import __version__ as tool_version  # lazy: avoid import cycle

    findings: List[Dict] = result.get("findings", [])
    # Distinct vuln classes in first-seen order -> one rule each.
    ordered_vulns: List[str] = []
    for f in findings:
        v = f.get("vuln", "")
        if v and v not in ordered_vulns:
            ordered_vulns.append(v)
    rule_index = {v: i for i, v in enumerate(ordered_vulns)}
    rules = [_rule_for(v) for v in ordered_vulns]
    results = [_result_for(f, rule_index) for f in findings]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SBVF",
                    "informationUri": INFORMATION_URI,
                    "version": tool_version,
                    "rules": rules,
                }
            },
            "results": results,
            "columnKind": "unicodeCodePoints",
        }],
    }
