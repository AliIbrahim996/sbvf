"""Real-time web UI for running the SBVF benchmark and watching results stream in.

Standard library only. On start it launches the three benchmark apps, then serves:
  GET  /                 -> the dashboard page
  GET  /api/run?...      -> Server-Sent Events stream, one event per completed run

Open http://127.0.0.1:8080 in a browser.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sbvf import datasets                    # noqa: E402
from sbvf.experiment import iter_runs, analyze, SPLITS  # noqa: E402
from sbvf.sast import scan_path              # noqa: E402
from sbvf.sast.repo import (                 # noqa: E402
    ALLOWED_HOSTS, RepoURLError, clone_repo, is_repo_url, normalize_repo_url,
    remove_tree)
from testbed.launcher import start_all       # noqa: E402

# Bundled intentionally-vulnerable sample projects for the static analyzer.
SAST_SAMPLES = {
    "php_native":   "PHP (native)",
    "php_yii":      "PHP (Yii)",
    "php_laravel":  "PHP (Laravel)",
    "python_native": "Python (native)",
    "python_fastapi": "Python (FastAPI)",
    "python_django": "Python (Django)",
    "node_express": "Node.js (Express)",
    "node_nestjs": "Node.js (NestJS)",
}
SAST_DIR = os.path.join(ROOT, "testbed", "sast_samples")

# Bind host is configurable so the UI can be exposed from inside a container
# (set SBVF_UI_HOST=0.0.0.0). The benchmark apps always stay on 127.0.0.1.
UI_HOST = os.environ.get("SBVF_UI_HOST", "127.0.0.1")
UI_PORT = int(os.environ.get("SBVF_UI_PORT", "8080"))
BASE_URLS = {}
# Arbitrary local folders may be scanned only while the dashboard is reachable
# from this machine alone; once exposed on a network interface, local scans are
# confined to the project tree (remote repos stay allowed via the host allowlist).
UI_IS_LOCAL = UI_HOST in ("127.0.0.1", "localhost", "::1")

HTML = open(os.path.join(os.path.dirname(__file__), "index.html"),
            encoding="utf-8").read()


class UIHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/api/run":
            return self._stream(urllib.parse.parse_qs(parsed.query))

        if parsed.path == "/api/scan":
            return self._scan_stream(urllib.parse.parse_qs(parsed.query))

        self.send_response(404)
        self.end_headers()

    def _sse(self, event, data):
        payload = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        self.wfile.write(payload.encode("utf-8"))
        self.wfile.flush()

    def _scan_stream(self, qs):
        """Server-Sent Events stream for a static (SAST) source-code scan.

        The ``path`` key is either a **local folder** or the URL of a **remote
        repository** on GitHub, GitLab or Bitbucket (shallow-cloned to a temp
        folder, scanned, then deleted). Without ``path``, ``sample`` selects a
        bundled vulnerable project.

        Any local folder is accepted while the dashboard is bound to localhost;
        if it is exposed on a network interface, local scans are confined to the
        project tree so it cannot be used to read arbitrary files.
        """
        sample = qs.get("sample", [""])[0]
        custom = qs.get("path", [""])[0].strip()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        def on_step(step):
            self._sse("scan_step", {"kind": step.kind, "text": step.text,
                                    "data": step.data})

        clone_dir = None
        try:
            if custom and is_repo_url(custom):
                try:
                    url = normalize_repo_url(custom)
                except RepoURLError as exc:
                    hosts = ", ".join(ALLOWED_HOSTS.values())
                    self._sse("scan_error", {"message": f"{exc}. Accepted: a local "
                                             f"folder or a {hosts} repository URL."})
                    return
                self._sse("scan_step", {"kind": "clone", "text":
                          f"Cloning {url} (shallow, depth 1) ...", "data": {"repo": url}})
                try:
                    clone_dir = clone_repo(url)
                except RuntimeError as exc:
                    self._sse("scan_error", {"message": str(exc)})
                    return
                self._sse("scan_step", {"kind": "clone", "text":
                          "Clone complete - starting static analysis "
                          "(the clone is deleted afterwards)", "data": {}})
                target = clone_dir
            elif custom:
                target = os.path.abspath(os.path.expanduser(custom))
                error = self._local_target_error(target)
                if error:
                    self._sse("scan_error", {"message": error})
                    return
            else:
                target = os.path.join(SAST_DIR, sample if sample in SAST_SAMPLES
                                      else "php_native")

            result = scan_path(target, on_step=on_step)
            if clone_dir:
                result["root"] = url
            self._sse("scan_done", result)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # surface analyzer errors to the dashboard
            try:
                self._sse("scan_error", {"message": str(exc)})
            except (BrokenPipeError, ConnectionResetError):
                pass
        finally:
            if clone_dir:
                remove_tree(clone_dir)

    def _local_target_error(self, target):
        """Return an error message if a local scan target is not acceptable."""
        if not os.path.exists(target):
            return f"local folder not found: {target}"
        if not UI_IS_LOCAL:
            root_real, target_real = os.path.realpath(ROOT), os.path.realpath(target)
            try:
                inside = os.path.commonpath([root_real, target_real]) == root_real
            except ValueError:
                inside = False   # different drive (Windows) -> outside the project
            if not inside:
                return ("the dashboard is exposed on the network, so local scans are "
                        "limited to the project folder; use a repository URL instead")
        return None

    def _stream(self, qs):
        split = qs.get("split", ["all"])[0]
        runs = int(qs.get("runs", ["10"])[0])
        budget = int(qs.get("budget", ["150"])[0])
        endpoints = SPLITS.get(split, SPLITS["all"])()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        total = len(endpoints) * 3 * runs
        self._sse("start", {"total": total, "split": split,
                            "runs": runs, "budget": budget,
                            "endpoints": len(endpoints)})
        rows = []
        try:
            for rec in iter_runs(endpoints, BASE_URLS, runs, budget):
                rows.append(rec)
                self._sse("run", {"i": len(rows), "total": total, "rec": rec})
            self._sse("done", analyze(rows))
        except (BrokenPipeError, ConnectionResetError):
            pass  # browser navigated away


def main():
    global BASE_URLS
    _servers, BASE_URLS = start_all()
    srv = ThreadingHTTPServer((UI_HOST, UI_PORT), UIHandler)
    print(f"SBVF UI on http://{UI_HOST}:{UI_PORT}")
    print("Benchmark apps:", ", ".join(f"{k}={v}" for k, v in BASE_URLS.items()))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
