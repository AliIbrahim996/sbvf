"""Orchestrator: walk a codebase, run the right analyzer per file, stream steps.

Unlike the dynamic framework, static analysis never sends a network request: it
only reads source files on disk, so it is inherently safe to run offline. The
engine emits :class:`~sbvf.sast.model.Step` events (detect / file / source /
finding / summary) so the live dashboard and the CLI can show every step.
"""
from __future__ import annotations

import os
import re
from typing import Callable, Dict, List, Optional

from .model import Finding, Step, SEVERITY_RANK, VULN_INFO
from .detect import SKIP_DIRS, iter_source_files, detect_frameworks, framework_for
from .php import PhpAnalyzer
from .python_analyzer import PythonAnalyzer
from .js import JsAnalyzer


class Scanner:
    """Runs the static analysis over a path and reports findings."""

    def __init__(self, on_step: Optional[Callable[[Step], None]] = None):
        self.on_step = on_step

    def _step(self, kind: str, text: str, **data):
        if self.on_step:
            self.on_step(Step(kind=kind, text=text, data=data))

    def _report(self, f: Finding):
        self._step("finding",
                   f"   [{f.severity.upper()}] {f.title} ({f.cwe}) "
                   f"{f.location()} - {f.source} -> {f.sink}",
                   finding=f.to_dict())

    def scan(self, root: str) -> Dict:
        root = os.path.abspath(root)
        if not os.path.exists(root):
            raise FileNotFoundError(root)

        self._step("detect", f"Indexing source files under {os.path.basename(root)} ...")
        files = iter_source_files(root)
        frameworks = detect_frameworks(root, files)
        fw_label = ", ".join(f"{k}={v}" for k, v in frameworks.items() if v) or "none"
        self._step("detect",
                   f"Detected: {fw_label} - {len(files)} source file(s)",
                   frameworks=frameworks, file_count=len(files))

        findings: List[Finding] = []
        template_flows = []           # (js file, flow) from res.render(...) calls
        base = root if os.path.isdir(root) else os.path.dirname(root)

        for idx, path in enumerate(files, 1):
            rel = os.path.relpath(path, base).replace("\\", "/")
            fw = framework_for(path, frameworks)
            self._step("file", f"[{idx}/{len(files)}] {rel}  ({fw})",
                       index=idx, total=len(files), file=rel, framework=fw)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    source = fh.read()
            except Exception as exc:
                self._step("file", f"   ! could not read {rel}: {exc}")
                continue

            def on_source(desc, line, _rel=rel):
                self._step("source", f"   source: {desc} at {_rel}:{line}",
                           file=_rel, line=line, source=desc)

            if path.endswith(".php"):
                analyzer = PhpAnalyzer(fw)
            elif path.endswith(".py"):
                analyzer = PythonAnalyzer(fw)
            else:
                analyzer = JsAnalyzer(fw)

            file_findings = analyzer.analyze(rel, source, on_source=on_source)
            template_flows += [(rel, fl) for fl in getattr(analyzer, "template_flows", [])]
            for f in file_findings:
                findings.append(f)
                self._report(f)

        if template_flows:
            self._step("file", f"Checking {len(template_flows)} template render(s) "
                               f"for unescaped EJS output ...")
            for f in _template_findings(base, template_flows):
                findings.append(f)
                self._report(f)

        findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9),
                                     f.file, f.line))
        counts = _counts(findings)
        self._step("summary",
                   f"Scan complete: {len(findings)} finding(s) across "
                   f"{len(files)} file(s).",
                   total_findings=len(findings), counts=counts,
                   frameworks=frameworks, files=len(files))

        return {
            "root": root,
            "frameworks": frameworks,
            "files_scanned": len(files),
            "findings": [f.to_dict() for f in findings],
            "counts": counts,
        }


def _template_findings(base: str, flows) -> List[Finding]:
    """XSS where a tainted value passed to ``res.render`` is printed unescaped.

    For each recorded render flow, open the EJS view and look for ``<%- expr %>``
    (raw output; ``<%= %>`` HTML-escapes) whose expression is one of the tainted
    object paths, e.g. ``res.render('products', {output: {term: req.query.q}})``
    + ``<%- output.term %>``. The finding is reported at the ``res.render`` line
    -- the handler that sends the page -- with the template location in the sink.
    """
    templates = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        templates += [os.path.relpath(os.path.join(dirpath, fn), base).replace("\\", "/")
                      for fn in filenames if fn.endswith(".ejs")]
    out: List[Finding] = []
    for js_rel, fl in flows:
        view = fl["view"].lstrip("/")
        view = view if view.endswith(".ejs") else view + ".ejs"
        matches = sorted((t for t in templates if t == view or t.endswith("/" + view)),
                         key=lambda t: ("views/" not in t, len(t)))
        if not matches:
            continue
        tpl = matches[0]
        try:
            with open(os.path.join(base, tpl), "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in re.finditer(r"<%-(.*?)%>", text, re.S):
            expr = m.group(1).strip()
            im = re.match(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*", expr)
            if not im or expr.startswith("include"):
                continue
            ident = re.sub(r"\s+", "", im.group(0))
            hit = next(((p, src, ep) for p, src, ep in fl["paths"]
                        if ident == p or ident.startswith(p + ".") or p.startswith(ident + ".")),
                       None)
            if not hit:
                continue
            tline = text[:m.start()].count("\n") + 1
            param, method = hit[2] or ("", "GET")
            sink = f"res.render -> {tpl}:{tline} <%- {ident} %> (unescaped EJS)"
            out.append(Finding(
                vuln="xss", file=js_rel, line=fl["line"], sink=sink, source=hit[1],
                framework=fl["framework"], code=fl["code"], param=param, method=method,
                function=fl["function"],
                message=f"Tainted value from {hit[1]} is rendered unescaped by {tpl}:{tline}."))
            break                                   # one finding per render call
    return out


def _counts(findings: List[Finding]) -> Dict:
    by_vuln, by_sev = {}, {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        by_vuln[f.vuln] = by_vuln.get(f.vuln, 0) + 1
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {"by_vuln": by_vuln, "by_severity": by_sev}


def scan_path(root: str, on_step: Optional[Callable[[Step], None]] = None) -> Dict:
    """Convenience wrapper: scan *root* and return the result dict."""
    return Scanner(on_step=on_step).scan(root)
