"""SBVF - Search-Based Vulnerability Framework.

A search-based framework for detecting XSS, SQLi and Clickjacking
vulnerabilities in local web applications.
"""
import sys

__version__ = "0.1.0"

# Minimum supported interpreter. Fail early with a clear message instead of an
# obscure error deep inside the framework when started with an older Python.
MIN_PYTHON = (3, 12)
if sys.version_info < MIN_PYTHON:
    raise RuntimeError(
        "SBVF requires Python %d.%d or newer (running %s). On Windows start it "
        "with `py -3.12 -m ...`." % (MIN_PYTHON + (sys.version.split()[0],)))
