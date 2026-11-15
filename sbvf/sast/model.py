"""Shared data model for the static analyzer: vulnerability classes and findings.

Kept framework- and language-agnostic so the PHP and Python analyzers emit the
same ``Finding`` records and the dashboard/CLI can render them uniformly.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


# Canonical vulnerability classes with their CWE id, default severity and a short
# human description. The analyzers reference these keys so reporting stays uniform.
VULN_INFO = {
    "sqli": {
        "cwe": "CWE-89", "severity": "high",
        "title": "SQL Injection",
        "desc": "User input reaches a SQL query without parameterization or escaping.",
    },
    "xss": {
        "cwe": "CWE-79", "severity": "high",
        "title": "Cross-Site Scripting (XSS)",
        "desc": "User input is written to an HTML response without output encoding.",
    },
    "command_injection": {
        "cwe": "CWE-78", "severity": "high",
        "title": "OS Command Injection",
        "desc": "User input reaches an operating-system command interpreter.",
    },
    "code_injection": {
        "cwe": "CWE-94", "severity": "high",
        "title": "Code Injection",
        "desc": "User input reaches a dynamic code-evaluation sink (eval/exec).",
    },
    "file_inclusion": {
        "cwe": "CWE-98", "severity": "high",
        "title": "File Inclusion",
        "desc": "User input controls an include/require path.",
    },
    "path_traversal": {
        "cwe": "CWE-22", "severity": "medium",
        "title": "Path Traversal",
        "desc": "User input controls a filesystem path passed to a file operation.",
    },
    "open_redirect": {
        "cwe": "CWE-601", "severity": "medium",
        "title": "Open Redirect",
        "desc": "User input controls a redirect target.",
    },
    "ssrf": {
        "cwe": "CWE-918", "severity": "medium",
        "title": "Server-Side Request Forgery",
        "desc": "User input controls the URL of an outbound server request.",
    },
}

# Severity ordering for sorting the report (most serious first).
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    """One statically-detected vulnerability, anchored to a source location."""

    vuln: str                     # key into VULN_INFO, e.g. "sqli"
    file: str                     # path relative to the scanned root
    line: int                     # 1-based line number of the sink
    sink: str                     # the dangerous construct, e.g. "mysqli_query"
    source: str                   # where the taint originated, e.g. "$_GET['id']"
    framework: str                # "php-native" | "yii" | "laravel" | ...
    code: str = ""                # the offending source line (trimmed)
    message: str = ""             # human-readable explanation
    column: int = 0               # best-effort column of the sink

    @property
    def cwe(self) -> str:
        return VULN_INFO.get(self.vuln, {}).get("cwe", "CWE-000")

    @property
    def severity(self) -> str:
        return VULN_INFO.get(self.vuln, {}).get("severity", "low")

    @property
    def title(self) -> str:
        return VULN_INFO.get(self.vuln, {}).get("title", self.vuln)

    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(cwe=self.cwe, severity=self.severity, title=self.title,
                 location=self.location())
        return d

    def __str__(self) -> str:
        return (f"[{self.severity.upper():6}] {self.title} ({self.cwe})  "
                f"{self.location()}\n"
                f"         source: {self.source}  ->  sink: {self.sink}\n"
                f"         {self.code.strip()[:120]}")


@dataclass
class Step:
    """A single progress event emitted while scanning (streamed to the UI)."""

    kind: str                     # "detect" | "file" | "source" | "finding" | "summary"
    text: str                     # one-line log message
    data: dict = field(default_factory=dict)
