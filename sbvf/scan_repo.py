"""Scan an open-source web application end to end:

    acquire (git clone / download) -> launch -> crawl + run the framework -> remove.

Intended for an authorized developer/tester who pastes an open-source project they
have the right to test. The application is launched with a START COMMAND that the
tester provides explicitly -- the tool never guesses how to run arbitrary code -- and
the framework only ever talks to a local address.

Example (DSVW, a single-file app):

    python -m sbvf.scan_repo \
        --repo https://github.com/stamparm/DSVW \
        --start "python dsvw.py" \
        --base http://127.0.0.1:65412 \
        --endpoints /:id:sqli /:v:xss \
        --runs 15 --budget 60

The cloned repository is deleted afterwards unless --keep is passed.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

from .external import ExternalEndpoint, light_crawl, run_external
from .oracles import LOCAL_HOSTS, Target
from .sast import scan_path, derive_endpoints, extract_routes
from .sast import noderun


def _is_node_project(rundir: str) -> bool:
    return os.path.isfile(os.path.join(rundir, "package.json"))


def _acquire(repo: str, workdir: str) -> str:
    """Put the project's source into workdir and return the directory to run from."""
    if os.path.isdir(repo):
        return repo  # local path: used in place, never deleted
    if repo.endswith(".py") or repo.endswith(".php"):
        name = os.path.basename(urllib.parse.urlparse(repo).path) or "app.py"
        dest = os.path.join(workdir, name)
        print(f"[*] downloading single file -> {dest}")
        urllib.request.urlretrieve(repo, dest)
        return workdir
    print(f"[*] git clone --depth 1 {repo}")
    subprocess.run(["git", "clone", "--depth", "1", repo, workdir], check=True)
    return workdir


def _wait_up(base: str, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(base, timeout=3)
            return True
        except urllib.error.HTTPError:
            return True  # any HTTP response means the server is up
        except Exception:
            time.sleep(1)
    return False


def _stop(proc: subprocess.Popen):
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        proc.kill()


def scan(repo, start, base, endpoints, runs, budget, keep=False, crawl=True,
         allow_remote=False, from_sast=False, web_root="", node_install=False):
    host = urllib.parse.urlparse(base).hostname or ""
    if host not in LOCAL_HOSTS and not allow_remote:
        sys.exit(f"[x] base host '{host}' is not local. Pass --allow-remote only for a "
                 f"target you are authorized to test.")

    print("=" * 70)
    print("  SBVF repository scan - authorized local testing only")
    print(f"  repo : {repo}")
    print(f"  start: {start or '(auto-detect)'}")
    print(f"  base : {base}")
    print("=" * 70)

    local_path = os.path.isdir(repo)
    workdir = repo if local_path else tempfile.mkdtemp(prefix="sbvf_scan_")
    proc = None
    env = None
    try:
        rundir = _acquire(repo, workdir)

        sast_eps = []
        if from_sast:
            sast_eps = _sast_endpoints(rundir, web_root)
            endpoints = list(endpoints) + sast_eps

        # Node.js: install deps (opt-in) and auto-detect the start command.
        if _is_node_project(rundir):
            if node_install and noderun.needs_install(rundir):
                print("[*] npm install ...")
                ok, msg = noderun.install_deps(rundir)
                print(f"    {msg}")
                if not ok:
                    sys.exit("[x] dependency install failed; pass --start to run it yourself.")
            if not start:
                start = noderun.detect_start(rundir)
                if not start:
                    sys.exit("[x] could not detect how to start the Node app; pass --start.")
                port = urllib.parse.urlparse(base).port or 3000
                env = noderun.launch_env(port)   # most Node apps honour PORT
        if not start:
            sys.exit("[x] no start command; pass --start.")

        print(f"[*] launching: {start}")
        proc = subprocess.Popen(start, shell=True, cwd=rundir, env=env)
        if not _wait_up(base):
            sys.exit("[x] the application did not come up at the base URL in time.")
        print("[+] application is up")

        target = Target(base, allow_remote=allow_remote)
        eps = list(endpoints)
        if crawl:
            for path, param in light_crawl(target):
                # crawled points have unknown vuln type; probe both xss and sqli
                for vuln in ("xss", "sqli"):
                    eps.append(ExternalEndpoint(path, param, vuln, "unknown", "crawled"))

        print(f"[*] testing {len(eps)} injection point(s)...\n")
        report = run_external(base, eps, runs, budget, allow_remote=allow_remote)
        _print_report(report)
        return report
    finally:
        if proc is not None:
            print("\n[*] stopping application")
            _stop(proc)
        if not keep and not local_path and os.path.isdir(workdir):
            print(f"[*] removing {workdir}")
            shutil.rmtree(workdir, ignore_errors=True)
        elif keep:
            print(f"[*] keeping {workdir}")


def _sast_endpoints(rundir, web_root=""):
    """Statically analyze *rundir* and return search-ready injection endpoints.

    This is the static->dynamic bridge: the taint analyzer discovers the request
    parameters, and the search algorithms (run later) decide which are actually
    exploitable. Only GET-reachable, file-routed findings become endpoints; the
    rest are reported as static-only so nothing is silently dropped.
    """
    print("[*] static pass: taint-analyzing the source to discover endpoints...")
    result = scan_path(rundir)
    findings = result["findings"]
    routes = extract_routes(rundir)       # Django urls.py / FastAPI decorators
    eps, skipped = derive_endpoints(findings, strip_prefix=web_root, routes=routes)
    print(f"    detected stack       : "
          + (", ".join(f"{k}={v}" for k, v in result["frameworks"].items() if v) or "none"))
    print(f"    recovered routes     : {sum(len(v) for v in routes.values())}")
    print(f"    static findings      : {len(findings)}")
    print(f"    search-ready endpoints: {len(eps)}")
    for e in eps:
        where = {"query": f"?{e.param}=", "body": f" [POST {e.param}]",
                 "path": f" [path {e.param}]"}.get(e.where, "")
        print(f"      -> {e.vuln:18} {e.path}{where}   [{e.note}]")
    if skipped:
        print(f"    static-only (not auto-confirmed): {len(skipped)}")
        for s in skipped[:12]:
            print(f"      .. {s['vuln']:4} {s['location']}  ({s['reason']})")
    return eps


def _print_report(report):
    found = 0
    for row in report:
        hits = {m: d for m, d in row["methods"].items() if d["detections"]}
        if not hits and row["label"] != "vulnerable":
            continue
        tag = row["label"] if row["label"] != "unknown" else "crawled"
        print(f"[{row['vuln']:4}] {row['path']}?{row['param']}=  ({tag}) {row['note']}")
        for m, d in row["methods"].items():
            mark = "FOUND" if d["detections"] else "  -  "
            med = d["median_evals"]
            print(f"     {mark} {m:7} {d['detections']}/{d['runs']}"
                  + (f"  median_evals={med}" if med is not None else ""))
        if any(d["detections"] for d in row["methods"].values()):
            found += 1
    print(f"\n[=] confirmed injection points: {found}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Scan an open-source web app with SBVF.")
    ap.add_argument("--repo", required=True, help="git URL, single-file URL, or local path")
    ap.add_argument("--start", default="", help="command to launch the app "
                    "(optional for Node.js projects: auto-detected from package.json)")
    ap.add_argument("--base", required=True, help="local base URL to test, e.g. http://127.0.0.1:8000")
    ap.add_argument("--node-install", action="store_true",
                    help="run `npm install` before launching a Node.js project")
    ap.add_argument("--endpoints", nargs="*", default=[],
                    help="known points as path:param:vuln, e.g. /:id:sqli /:q:xss")
    ap.add_argument("--runs", type=int, default=15)
    ap.add_argument("--budget", type=int, default=60)
    ap.add_argument("--no-crawl", action="store_true")
    ap.add_argument("--from-sast", action="store_true",
                    help="statically taint-analyze the source to auto-discover "
                         "injection endpoints, then confirm them with the search")
    ap.add_argument("--web-root", default="",
                    help="source subdirectory served as the web root (stripped "
                         "from file paths when mapping them to URLs, e.g. public)")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--allow-remote", action="store_true")
    args = ap.parse_args(argv)

    endpoints = []
    for spec in args.endpoints:
        parts = spec.split(":")
        if len(parts) != 3:
            sys.exit(f"[x] bad --endpoints spec '{spec}', expected path:param:vuln")
        endpoints.append(ExternalEndpoint(parts[0], parts[1], parts[2], "vulnerable"))

    scan(args.repo, args.start, args.base, endpoints, args.runs, args.budget,
         keep=args.keep, crawl=not args.no_crawl, allow_remote=args.allow_remote,
         from_sast=args.from_sast, web_root=args.web_root, node_install=args.node_install)


if __name__ == "__main__":
    main()
