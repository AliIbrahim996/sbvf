"""Static Application Security Testing (SAST) engine for the SBVF framework.

While the rest of SBVF performs *dynamic*, black-box, search-based testing
against a running application, this sub-package performs *static* analysis of a
project's **source code**: it reads the files, detects the language and web
framework, and taint-tracks untrusted user input from sources to dangerous
sinks, reporting findings with ``file:line`` precision.

Supported stacks (in the scope order of the thesis):
  - PHP: native, Yii, Laravel
  - Python: native, FastAPI, Django

The public entry point is :func:`sbvf.sast.engine.scan_path`.
"""
from __future__ import annotations

from .model import Finding, VULN_INFO
from .engine import scan_path, Scanner
from .bridge import derive_endpoints
from .routes import extract_routes

__all__ = ["Finding", "VULN_INFO", "scan_path", "Scanner", "derive_endpoints",
           "extract_routes"]
