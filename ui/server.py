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
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Queue

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sbvf import datasets                    # noqa: E402
from sbvf.experiment import iter_runs, analyze, SPLITS  # noqa: E402
from sbvf.sast import scan_path, extract_routes, confirm_findings, TargetUnreachable  # noqa: E402
from sbvf.sast.repo import (                 # noqa: E402
    allowed_hosts, RepoURLError, checkout_branch, clone_repo, export_branch,
    is_git_repo, is_repo_url, list_branches, normalize_repo_url, remove_tree,
    uses_credentials)
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

# Interactive branch selection for a cloned repo: the scan stream clones all
# branch tips, emits a `branch_prompt`, then blocks until a `POST /api/scan/branch`
# (handled on another thread by the ThreadingHTTPServer) hands back the choice.
_PENDING_BRANCH: dict = {}
_PENDING_LOCK = threading.Lock()
BRANCH_SELECT_TIMEOUT = 300   # seconds to wait for the user's branch choice

# A scan is started by `POST /api/scans` (which registers the parameters and
# returns an opaque token) and then streamed by `GET /api/scans/<token>/events`.
# Routing the start through a POST (JSON body, same-origin) is what stops a
# cross-site `<img>`/`<script>` GET from driving the local API (see `_guard`).
_SCAN_JOBS: dict = {}
_SCAN_JOBS_LOCK = threading.Lock()
SCAN_JOB_TTL = 300   # seconds a registered-but-unstarted job stays valid

# Hostnames accepted in the `Host`/`Origin` headers. localhost forms always pass;
# SBVF_ALLOWED_HOSTS adds more (e.g. the compose service name "sbvf", which the
# Next.js proxy uses when it calls the backend as http://sbvf:8080).
_LOCAL_HOST_NAMES = {"127.0.0.1", "localhost", "[::1]", "::1", ""}


def _host_only(value: str) -> str:
    """The hostname part of a `Host`/`Origin` netloc, lower-cased, port removed."""
    h = (value or "").strip().lower()
    if h.startswith("["):                 # [::1] or [::1]:8080
        return h.split("]", 1)[0] + "]"
    return h.rsplit(":", 1)[0] if ":" in h else h


def allowed_host_names() -> set:
    """Effective set of accepted hostnames (localhost plus SBVF_ALLOWED_HOSTS)."""
    names = set(_LOCAL_HOST_NAMES)
    for tok in os.environ.get("SBVF_ALLOWED_HOSTS", "").split(","):
        name = _host_only(tok)
        if name:
            names.add(name)
    return names


class BadRequest(Exception):
    """A query/body parameter failed validation -> HTTP 400."""


def _int_param(qs, name, default, lo, hi):
    """Parse a bounded integer query param, raising :class:`BadRequest` if invalid."""
    raw = qs.get(name, [str(default)])[0]
    raw = raw if (raw is not None and raw != "") else str(default)
    try:
        val = int(raw)
    except (TypeError, ValueError):
        raise BadRequest(f"{name} must be an integer")
    if not lo <= val <= hi:
        raise BadRequest(f"{name} must be between {lo} and {hi}")
    return val


def _prune_scan_jobs():
    """Drop registered scan jobs that were never started (bounds memory). Call under lock."""
    now = time.monotonic()
    for tok in [t for t, p in _SCAN_JOBS.items() if now - p["created"] > SCAN_JOB_TTL]:
        _SCAN_JOBS.pop(tok, None)


class UIHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _guard(self, require_json: bool = False) -> bool:
        """Reject DNS-rebinding / cross-site requests. True = already responded.

        * ``Host`` must name localhost (or an SBVF_ALLOWED_HOSTS entry): a page on
          a rebound attacker domain carries that domain in ``Host`` -> 421.
        * ``Origin``, when present, must match -> a cross-site fetch is refused 403.
        * state-changing POSTs must be ``application/json`` -> a cross-site "simple"
          POST (text/plain or a form) cannot be forged without a CORS preflight.
        """
        allowed = allowed_host_names()
        if _host_only(self.headers.get("Host", "")) not in allowed:
            self._json({"message": "forbidden host"}, code=421)
            return True
        origin = self.headers.get("Origin")
        if origin:
            if _host_only(urllib.parse.urlparse(origin).netloc) not in allowed:
                self._json({"message": "cross-origin request refused"}, code=403)
                return True
        if require_json:
            ctype = self.headers.get("Content-Type", "").lower()
            if not ctype.startswith("application/json"):
                self._json({"message": "Content-Type must be application/json"}, code=415)
                return True
        return False

    def do_GET(self):
        if self._guard():
            return
        try:
            self._route_get(urllib.parse.urlparse(self.path))
        except BadRequest as exc:
            self._json({"message": str(exc)}, code=400)

    def _route_get(self, parsed):
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

        if parsed.path == "/api/scans":
            return self._list_scans(urllib.parse.parse_qs(parsed.query))

        if parsed.path == "/api/ai/status":
            return self._ai_status()

        if parsed.path.startswith("/api/scans/"):
            parts = parsed.path.rstrip("/")[len("/api/scans/"):].split("/")
            if len(parts) == 2 and parts[1] == "events":
                return self._scan_events(parts[0])
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
        if self._guard():
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/scans/"):
            return self._delete_scan(parsed.path.rstrip("/").rsplit("/", 1)[-1])
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self._guard(require_json=True):
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path == "/api/scans":
            return self._create_scan()
        if path == "/api/ask":
            return self._ask()
        if path == "/api/scan/branch":
            return self._pick_branch()
        if path.startswith("/api/scans/") and path.endswith("/agents"):
            scan_id = path[len("/api/scans/"):-len("/agents")]
            return self._run_agents(scan_id)
        self.send_response(404)
        self.end_headers()

    def _create_scan(self):
        """Register a scan job from a JSON body; return its streaming token.

        The actual scan runs on ``GET /api/scans/<token>/events``. Starting a scan
        requires this POST (JSON, same-origin), so a cross-site GET cannot."""
        body = self._read_json_body()
        params = {
            "sample": str(body.get("sample", "") or ""),
            "path": str(body.get("path", "") or "").strip(),
            "confirm": str(body.get("confirm", "") or "").strip(),
            "branch_select": bool(body.get("branch_select")),
            "branch": str(body.get("branch", "") or "").strip(),
            "created": time.monotonic(),
        }
        token = uuid.uuid4().hex
        with _SCAN_JOBS_LOCK:
            _prune_scan_jobs()
            _SCAN_JOBS[token] = params
        self._json({"scan_id": token, "events_url": f"/api/scans/{token}/events"})

    def _scan_events(self, token):
        """Stream a scan that ``_create_scan`` registered under *token* (one-shot)."""
        with _SCAN_JOBS_LOCK:
            _prune_scan_jobs()
            params = _SCAN_JOBS.pop(token, None)
        if params is None:
            return self._json({"message": "unknown or expired scan job"}, code=404)
        self._scan_stream(params)

    def _pick_branch(self):
        """Resume a scan that is waiting for a branch choice (see ``_resolve_branch``)."""
        body = self._read_json_body()
        token = str(body.get("token", "") or "")
        branch = str(body.get("branch", "") or "")
        with _PENDING_LOCK:
            entry = _PENDING_BRANCH.get(token)
        if entry is None:
            return self._json({"ok": False,
                               "message": "unknown or expired branch selection"}, code=404)
        if branch not in entry["branches"]:
            return self._json({"ok": False,
                               "message": "branch not offered for this scan"}, code=400)
        entry["queue"].put(branch)
        self._json({"ok": True, "branch": branch})

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
        limit = _int_param(qs, "limit", 50, 1, 200)
        offset = _int_param(qs, "offset", 0, 0, 1_000_000)
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
        limit = _int_param(qs, "limit", 100, 1, 500)
        sid = qs.get("scan_id", [None])[0]
        scan_id = _int_param(qs, "scan_id", 1, 1, 1_000_000) if sid not in (None, "") else None
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
        limit = _int_param(qs, "limit", 50, 1, 200)
        sid = qs.get("scan_id", [None])[0]
        try:
            scan_id = int(sid) if sid not in (None, "") else None
        except (TypeError, ValueError):
            scan_id = None
        if scan_id is not None and scan_id < 1:
            scan_id = None   # 0/negative is not a real scan id -> global thread
        self._json({"enabled": True, "messages": store.repository.list_chat(limit, scan_id)})

    def _scan_stream(self, params):
        """Server-Sent Events stream for a static (SAST) source-code scan.

        *params* is the dict registered by ``_create_scan``. The ``path`` key is
        either a **local folder** or the URL of a **remote repository** on GitHub,
        GitLab or Bitbucket (shallow-cloned to a temp folder, scanned, then
        deleted). Without ``path``, ``sample`` selects a bundled vulnerable project.

        Any local folder is accepted while the dashboard is bound to localhost;
        if it is exposed on a network interface, local scans are confined to the
        project tree so it cannot be used to read arbitrary files.
        """
        sample = params.get("sample", "")
        custom = (params.get("path", "") or "").strip()
        confirm = (params.get("confirm", "") or "").strip()  # optional live-confirm URL
        # Branch selection for a cloned repo: `branch_select` makes the stream
        # pause and prompt; `branch=<name>` checks that branch out directly.
        want_select = bool(params.get("branch_select"))
        want_branch = (params.get("branch", "") or "").strip()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        def on_step(step):
            self._sse("scan_step", {"kind": step.kind, "text": step.text,
                                    "data": step.data})

        clone_dir = None          # a clone to delete afterwards
        export_dir = None         # a local-branch export to delete afterwards
        branch_label = ""
        display_root = ""         # what to show as the report's root
        try:
            if custom and is_repo_url(custom):
                try:
                    url = normalize_repo_url(custom)
                except RepoURLError as exc:
                    hosts = ", ".join(allowed_hosts().values())
                    self._sse("scan_error", {"message": f"{exc}. Accepted: a local "
                                             f"folder or a {hosts} repository URL."})
                    return
                all_branches = want_select or bool(want_branch)
                if uses_credentials(url):
                    host = urllib.parse.urlparse(url).hostname or ""
                    self._sse("scan_step", {"kind": "clone", "text":
                              f"Using your machine's git credentials for {host}",
                              "data": {}})
                self._sse("scan_step", {"kind": "clone", "text":
                          f"Cloning {url} (shallow, depth 1"
                          f"{', all branches' if all_branches else ''}) ...",
                          "data": {"repo": url}})
                try:
                    clone_dir = clone_repo(url, all_branches=all_branches)
                except RuntimeError as exc:
                    self._sse("scan_error", {"message": str(exc)})
                    return
                self._sse("scan_step", {"kind": "clone", "text":
                          "Clone complete (the clone is deleted afterwards)", "data": {}})
                res = self._resolve_branch(clone_dir, want_select, want_branch, local=False)
                if res is None:                  # aborted; error already streamed
                    return
                branch_label, target, _ = res
                display_root = url
            elif custom:
                target = os.path.abspath(os.path.expanduser(custom))
                error = self._local_target_error(target)
                if error:
                    self._sse("scan_error", {"message": error})
                    return
                display_root = custom
                # A local git working tree can offer its branches too; the user's
                # checkout is never switched (other branches are exported read-only).
                if (want_select or want_branch) and is_git_repo(target):
                    res = self._resolve_branch(target, want_select, want_branch, local=True)
                    if res is None:
                        return
                    branch_label, target, export_dir = res
            else:
                target = os.path.join(SAST_DIR, sample if sample in SAST_SAMPLES
                                      else "php_native")

            started = time.monotonic()
            result = scan_path(target, on_step=on_step)
            if branch_label:
                result["root"] = f"{display_root} @ {branch_label}"
                result["branch"] = branch_label
            elif clone_dir:
                result["root"] = url

            # Optional live confirmation: drive the search against a running
            # instance of the app at a local base URL the user provides. This only
            # sends requests to that URL (it never launches code), and Target
            # refuses non-local hosts. Failure here must not lose the static result.
            if confirm:
                self._sse("scan_step", {"kind": "confirm", "text":
                          f"Confirming findings against {confirm} "
                          f"(connecting to your running app) ...", "data": {}})
                try:
                    summary = confirm_findings(
                        result["findings"], confirm,
                        routes=extract_routes(target), on_step=on_step)
                    self._sse("scan_step", {"kind": "confirm", "text":
                              f"Live confirmation: {summary['confirmed']} of "
                              f"{summary['attempted']} probe(s) reproduced, "
                              f"confirming {summary['findings']} finding(s) against "
                              f"the running app.", "data": summary})
                except (ValueError, TargetUnreachable) as exc:
                    self._sse("scan_step", {"kind": "confirm", "text":
                              f"Live confirmation skipped: {exc}", "data": {}})
                except Exception as exc:   # never lose the static result over confirm
                    self._sse("scan_step", {"kind": "confirm", "text":
                              f"Live confirmation failed (static results kept): {exc}",
                              "data": {}})

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
            if export_dir:
                remove_tree(export_dir)

    def _resolve_branch(self, repo_dir, want_select, want_branch, local):
        """Decide which branch of the git repo at *repo_dir* to scan.

        Returns ``(branch_label, scan_target, cleanup_dir)`` or ``None`` after
        streaming a ``scan_error`` so the caller stops. *branch_label* is ``""`` for
        "the default branch, no prompt". For a **clone** (*local* False) the branch
        is checked out in place and *scan_target* is *repo_dir*. For a **local**
        working tree the user's checkout is never switched: the current branch scans
        in place, any other branch is exported to a temp dir (returned as both
        *scan_target* and *cleanup_dir* for the caller to delete)."""
        def materialize(branch, is_current):
            """Produce the scan target for *branch* and stream the start step.

            *is_current* (local working tree on this branch) means scan in place."""
            try:
                if is_current:
                    tgt, cleanup = repo_dir, None          # scan the working tree
                elif local:
                    tgt = export_branch(repo_dir, branch)  # non-destructive snapshot
                    cleanup = tgt
                else:
                    checkout_branch(repo_dir, branch)      # we own the clone
                    tgt, cleanup = repo_dir, None
            except (RepoURLError, RuntimeError) as exc:
                self._sse("scan_error", {"message": str(exc)})
                return None
            verb = "On" if is_current else "Checked out"
            self._sse("scan_step", {"kind": "clone", "data": {"branch": branch},
                      "text": f"{verb} branch '{branch}' - starting static analysis"})
            return branch, tgt, cleanup

        if want_branch:
            # Only a local checkout needs the current branch (to scan in place).
            current = list_branches(repo_dir)[1] if local else ""
            return materialize(want_branch, local and want_branch == current)
        if not want_select:                      # legacy / CLI: default branch
            self._sse("scan_step", {"kind": "clone", "data": {},
                      "text": "Starting static analysis ..."})
            return "", repo_dir, None

        branches, current = list_branches(repo_dir)
        if len(branches) <= 1:                   # nothing to choose
            only = current or (branches[0] if branches else "")
            msg = (f"Branch '{only}' - starting static analysis" if only
                   else "Starting static analysis ...")
            self._sse("scan_step", {"kind": "clone", "data": {"branch": only},
                      "text": msg})
            return only, repo_dir, None

        token = uuid.uuid4().hex
        q: Queue = Queue()
        with _PENDING_LOCK:
            _PENDING_BRANCH[token] = {"queue": q, "branches": set(branches)}
        self._sse("branch_prompt", {"token": token, "branches": branches,
                                    "current": current})
        try:
            chosen = q.get(timeout=BRANCH_SELECT_TIMEOUT)
        except Empty:
            chosen = None
        finally:
            with _PENDING_LOCK:
                _PENDING_BRANCH.pop(token, None)
        if not chosen:
            self._sse("scan_error", {"message": "Branch selection timed out - "
                      "please scan again and choose a branch."})
            return None
        return materialize(chosen, local and chosen == current)

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
        runs = _int_param(qs, "runs", 10, 1, 100)
        budget = _int_param(qs, "budget", 150, 10, 2000)
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
