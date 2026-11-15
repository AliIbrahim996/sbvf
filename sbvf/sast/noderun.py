"""Launch a Node.js application locally so the search can test it.

The static-guided flow (``scan_repo --from-sast``) needs the target application
running. For PHP/Python the tester passes ``--start``; this module lets a Node.js
project start with no ``--start`` by reading ``package.json`` and, when asked,
installing dependencies. Everything stays on ``127.0.0.1``.

Only used for a project the tester chose to scan; it runs ``npm``/``node`` the
same way the developer would, and never evaluates project code in-process.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Optional, Tuple


def _npm() -> Optional[str]:
    """Resolve the npm launcher (npm.cmd on Windows), or None if absent."""
    if os.name == "nt":
        return shutil.which("npm.cmd") or shutil.which("npm")
    return shutil.which("npm")

# Entry files tried, in order, when package.json gives no main/start script.
ENTRY_CANDIDATES = (
    "server.js", "app.js", "index.js", "main.js",
    "src/server.js", "src/app.js", "src/index.js", "src/main.js",
    "bin/www", "dist/main.js", "build/index.js",
)


def _package_json(app_dir: str) -> dict:
    try:
        with open(os.path.join(app_dir, "package.json"), encoding="utf-8") as fh:
            return json.load(fh) or {}
    except (OSError, ValueError):
        return {}


def detect_start(app_dir: str) -> Optional[str]:
    """Return a shell command that starts the Node app in *app_dir*, or None.

    Preference: an explicit ``scripts.start`` (run via ``npm start``), then the
    ``main`` entry, then a conventional entry file. TypeScript entries are run
    with the project's own tooling only if a start script invokes it; this does
    not transpile on its own.
    """
    pkg = _package_json(app_dir)
    scripts = pkg.get("scripts") or {}
    if isinstance(scripts, dict) and scripts.get("start"):
        return "npm start"
    main = pkg.get("main")
    if main and os.path.isfile(os.path.join(app_dir, main)) and str(main).endswith(".js"):
        return f'node "{main}"'
    for entry in ENTRY_CANDIDATES:
        if os.path.isfile(os.path.join(app_dir, entry)):
            return f'node "{entry}"'
    return None


def needs_install(app_dir: str) -> bool:
    """True if the project declares dependencies but has no node_modules yet."""
    pkg = _package_json(app_dir)
    has_deps = bool(pkg.get("dependencies") or pkg.get("devDependencies"))
    return has_deps and not os.path.isdir(os.path.join(app_dir, "node_modules"))


def install_deps(app_dir: str, timeout: int = 600) -> Tuple[bool, str]:
    """Run ``npm install`` in *app_dir*. Returns (ok, message)."""
    npm = _npm()
    if not npm:
        return False, "npm is not installed or not on PATH"
    args = ["install", "--no-audit", "--no-fund", "--loglevel", "error"]
    # On Windows npm is a .cmd launcher, which must go through the shell.
    win = os.name == "nt"
    cmd = subprocess.list2cmdline([npm] + args) if win else [npm] + args
    try:
        p = subprocess.run(cmd, cwd=app_dir, timeout=timeout, shell=win,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
    except OSError as exc:
        return False, f"could not run npm: {exc}"
    except subprocess.TimeoutExpired:
        return False, f"npm install timed out after {timeout}s"
    if p.returncode != 0:
        tail = "\n".join((p.stdout or "").splitlines()[-5:])
        return False, f"npm install failed:\n{tail}"
    return True, "dependencies installed"


def launch_env(base_port: int) -> dict:
    """Environment for the child: most Node apps honour PORT; pin HOST to local."""
    return dict(os.environ, PORT=str(base_port), HOST="127.0.0.1",
                NODE_ENV="development")
