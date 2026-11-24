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
import time
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
from sbvf import store                        # noqa: E402  (optional persistence)
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
    "idor_django": "IDOR (Django)",
    "crypto_py": "Crypto failures (Python)",
    "misconfig_py": "Security misconfig (Python)",
    "deser_py": "Insecure deserialization (Python)",
    "errors_py": "Mishandling exceptions (Python)",
    "supplychain": "Supply chain (manifests)",
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

        if parsed.path == "/api/scans":
            return self._list_scans(urllib.parse.parse_qs(parsed.query))

        if parsed.path == "/api/ai/status":
            return self._ai_status()

        if parsed.path.startswith("/api/scans/"):
            parts = parsed.path.rstrip("/")[len("/api/scans/"):].split("/")
            if len(parts) == 2 and parts[1] == "ai":
                return self._get_scan_ai(parts[0])
            if len(parts) == 1 and parts[0]:
                return self._get_scan(parts[0])
            self.send_response(404)
            self.end_headers()
            return

        if parsed.path == "/api/activity":
            return self._list_activity(urllib.parse.parse_qs(parsed.query))

        if parsed.path == "/api/chat":
            return self._list_chat(urllib.parse.parse_qs(parsed.query))

        self.send_response(404)
        self.end_headers()

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/scans/"):
            return self._delete_scan(parsed.path.rstrip("/").rsplit("/", 1)[-1])
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path == "/api/ask":
            return self._ask()
        if path.startswith("/api/scans/") and path.endswith("/agents"):
            scan_id = path[len("/api/scans/"):-len("/agents")]
            return self._run_agents(scan_id)
        self.send_response(404)
        self.end_headers()

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            return {}
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except Exception:
            return {}

    def _sse(self, event, data):
        payload = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        self.wfile.write(payload.encode("utf-8"))
        self.wfile.flush()

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- persistence-backed endpoints (no-op friendly when the DB is off) ----
    def _persistence_off(self):
        self._json({"enabled": False,
                    "message": "History requires the database service (set DATABASE_URL)."},
                   code=503)

    def _list_scans(self, qs):
        if not store.is_enabled():
            return self._persistence_off()
        limit = min(int(qs.get("limit", ["50"])[0] or 50), 200)
        offset = int(qs.get("offset", ["0"])[0] or 0)
        self._json({"enabled": True, "scans": store.repository.list_scans(limit, offset)})

    def _get_scan(self, raw_id):
        if not store.is_enabled():
            return self._persistence_off()
        try:
            scan_id = int(raw_id)
        except ValueError:
            return self._json({"message": "bad scan id"}, code=400)
        scan = store.repository.get_scan(scan_id)
        if scan is None:
            return self._json({"message": "scan not found"}, code=404)
        self._json(scan)

    def _delete_scan(self, raw_id):
        if not store.is_enabled():
            return self._persistence_off()
        try:
            scan_id = int(raw_id)
        except ValueError:
            return self._json({"message": "bad scan id"}, code=400)
        ok = store.repository.delete_scan(scan_id)
        self._json({"deleted": ok}, code=200 if ok else 404)

    def _list_activity(self, qs):
        if not store.is_enabled():
            return self._persistence_off()
        limit = min(int(qs.get("limit", ["100"])[0] or 100), 500)
        sid = qs.get("scan_id", [None])[0]
        scan_id = int(sid) if sid not in (None, "") else None
        self._json({"enabled": True,
                    "activity": store.repository.list_activity(limit, scan_id)})

    # ---- AI-agents layer (lazy import; degrades when no provider configured) ----
    def _ai_status(self):
        from sbvf import agents  # lazy: optional AI layer
        self._json({"enabled": agents.is_enabled(),
                    "providers": agents.available_providers()})

    def _get_scan_ai(self, raw_id):
        if not store.is_enabled():
            return self._persistence_off()
        try:
            scan_id = int(raw_id)
        except ValueError:
            return self._json({"message": "bad scan id"}, code=400)
        if store.repository.get_scan(scan_id) is None:
            return self._json({"message": "scan not found"}, code=404)
        self._json(store.repository.get_ai(scan_id))

    def _run_agents(self, raw_id):
        """Run the selected AI agents over a stored scan, streaming progress as SSE.

        Consumed by the frontend via a streaming fetch (not EventSource, since this
        is a POST). Each ``on_progress`` event is written as one SSE frame.
        """
        from sbvf import agents  # lazy: optional AI layer
        try:
            scan_id = int(raw_id)
        except ValueError:
            return self._json({"message": "bad scan id"}, code=400)
        body = self._read_json_body()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        try:
            if not store.is_enabled():
                self._sse("agents_error", {"message":
                          "AI analysis requires the database service (set DATABASE_URL)."})
                return
            if not agents.is_enabled():
                self._sse("agents_error", {"message":
                          "No AI provider is configured. Set ANTHROPIC_API_KEY, "
                          "OPENAI_API_KEY or OLLAMA_URL to enable AI analysis."})
                return
            agents.runner.run_finding_agents(
                scan_id,
                agents=body.get("agents") or None,
                provider_name=body.get("provider") or None,
                on_progress=lambda event, data: self._sse(event, data),
            )
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            try:
                self._sse("agents_error", {"message": str(exc)})
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _ask(self):
        """Answer a natural-language question over the stored scan history (JSON)."""
        from sbvf import agents  # lazy: optional AI layer
        body = self._read_json_body()
        question = (body.get("question") or "").strip()
        if not question:
            return self._json({"message": "question is required"}, code=400)
        if not store.is_enabled():
            return self._json({"enabled": False, "message":
                              "Q&A requires the database service (set DATABASE_URL)."},
                              code=503)
        if not agents.is_enabled():
            return self._json({"enabled": False, "message":
                              "No AI provider is configured. Set ANTHROPIC_API_KEY, "
                              "OPENAI_API_KEY or OLLAMA_URL to enable Q&A."}, code=503)
        try:
            sid = body.get("scan_id")
            scan_id = int(sid) if sid not in (None, "") else None
        except (TypeError, ValueError):
            scan_id = None
        if scan_id is not None and scan_id < 1:
            scan_id = None   # 0/negative is not a real scan id -> global thread
        result = agents.runner.answer_question(
            question, scan_id=scan_id, provider_name=(body.get("provider") or None))
        if not result.get("ok"):
            return self._json({"message": result.get("error", "Q&A failed")}, code=502)
        self._json(result)

    def _list_chat(self, qs):
        if not store.is_enabled():
            return self._persistence_off()
        limit = min(int(qs.get("limit", ["50"])[0] or 50), 200)
        sid = qs.get("scan_id", [None])[0]
        try:
            scan_id = int(sid) if sid not in (None, "") else None
        except (TypeError, ValueError):
            scan_id = None
        if scan_id is not None and scan_id < 1:
            scan_id = None   # 0/negative is not a real scan id -> global thread
        self._json({"enabled": True, "messages": store.repository.list_chat(limit, scan_id)})

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

            started = time.monotonic()
            result = scan_path(target, on_step=on_step)
            if clone_dir:
                result["root"] = url
            # Persist the scan (best-effort; a DB failure must not break the stream).
            try:
                scan_type = ("repo" if (custom and is_repo_url(custom))
                             else "local" if custom else "sample")
                scan_id = store.repository.save_scan(
                    result, target=(custom or sample),
                    scan_type=scan_type,
                    duration_ms=int((time.monotonic() - started) * 1000))
                if scan_id is not None:
                    result["scan_id"] = scan_id
            except Exception:
                pass
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
    if store.is_enabled():
        store.migrate.init()          # best-effort; prints status, never raises
    else:
        print("[sbvf.store] persistence disabled (no DATABASE_URL)")
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
