"""Tests for the SBVF dashboard server's request hardening (ui/server.py).

Covers the Host/Origin/Content-Type guard, the POST-to-start / SSE-to-stream scan
and benchmark flows (a cross-site GET can no longer start a scan or a benchmark),
bounded numeric parameters, and git-credential scrubbing.

Runnable with pytest or `python -m tests.test_ui_server`.
"""
import http.client
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json                                                   # noqa: E402

from ui import server                                         # noqa: E402
from sbvf.sast import repo                                    # noqa: E402


class _Server:
    """A UIHandler on an ephemeral loopback port, for black-box HTTP tests."""

    def __enter__(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.UIHandler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]
        # Slot counters and job registries are module-level (one server process in
        # production); reset them so each test starts from a clean, isolated slate.
        with server._JOBS_LOCK:
            server._active["scan"] = 0
            server._active["run"] = 0
            server._SCAN_JOBS.clear()
            server._RUN_JOBS.clear()
        time.sleep(0.1)
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()

    def request(self, method, path, *, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.read().decode("utf-8", "replace")
        finally:
            conn.close()

    def stream(self, path, *, until, timeout=30):
        """GET an SSE endpoint and read until *until* appears (event streams have
        no Content-Length, so a plain read() would block for EOF that never comes)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            buf = ""
            if resp.status == 200:
                while until not in buf:
                    chunk = resp.read(128)
                    if not chunk:
                        break
                    buf += chunk.decode("utf-8", "replace")
            return resp.status, buf
        finally:
            conn.close()


class TestRequestGuard(unittest.TestCase):
    def test_foreign_host_is_rejected(self):
        with _Server() as s:
            status, _ = s.request("GET", "/api/ai/status",
                                  headers={"Host": "attacker.example"})
            self.assertEqual(status, 421)

    def test_local_host_is_accepted(self):
        with _Server() as s:
            status, _ = s.request("GET", "/api/ai/status")   # Host defaults to 127.0.0.1
            self.assertEqual(status, 200)

    def test_cross_origin_is_rejected(self):
        with _Server() as s:
            status, _ = s.request("GET", "/api/ai/status",
                                  headers={"Origin": "https://attacker.example"})
            self.assertEqual(status, 403)

    def test_same_origin_is_accepted(self):
        with _Server() as s:
            status, _ = s.request(
                "GET", "/api/ai/status",
                headers={"Origin": f"http://127.0.0.1:{s.port}"})
            self.assertEqual(status, 200)

    def test_non_json_post_is_rejected(self):
        with _Server() as s:
            status, _ = s.request("POST", "/api/scans",
                                  headers={"Content-Type": "text/plain"},
                                  body='{"sample":"php_native"}')
            self.assertEqual(status, 415)

    def test_null_origin_is_rejected(self):
        with _Server() as s:
            status, _ = s.request("GET", "/api/ai/status", headers={"Origin": "null"})
            self.assertEqual(status, 403)

    def test_host_only_parses_ports_and_ipv6(self):
        self.assertEqual(server._host_only("127.0.0.1:8080"), "127.0.0.1")
        self.assertEqual(server._host_only("sbvf:8080"), "sbvf")
        self.assertEqual(server._host_only("[::1]:8080"), "[::1]")
        self.assertEqual(server._host_only("::1"), "::1")          # bare IPv6, no port
        self.assertEqual(server._host_only(""), "")

    def test_missing_host_is_not_implicitly_allowed(self):
        # "" must not be an accepted hostname, so a missing/empty Host is refused.
        self.assertNotIn("", server.allowed_host_names())

    def test_extra_allowed_host_via_env(self):
        os.environ["SBVF_ALLOWED_HOSTS"] = "sbvf"
        try:
            with _Server() as s:
                status, _ = s.request("GET", "/api/ai/status",
                                      headers={"Host": "sbvf:8080"})
                self.assertEqual(status, 200)
        finally:
            os.environ.pop("SBVF_ALLOWED_HOSTS", None)


class TestScanFlow(unittest.TestCase):
    def test_get_scan_no_longer_starts_a_scan(self):
        # The old GET /api/scan start route is gone, so an <img>/<script> GET
        # (which carries a valid Host and no Origin) cannot drive a scan.
        with _Server() as s:
            status, _ = s.request("GET", "/api/scan?sample=php_native")
            self.assertEqual(status, 404)

    def test_post_creates_job_then_sse_streams_it(self):
        with _Server() as s:
            status, body = s.request(
                "POST", "/api/scans",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"sample": "php_native"}))
            self.assertEqual(status, 200)
            token = json.loads(body)["scan_id"]
            self.assertTrue(token)
            status, stream = s.stream(f"/api/scans/{token}/events", until="event: scan_done")
            self.assertEqual(status, 200)
            self.assertIn("event: scan_done", stream)

    def test_unknown_scan_token_is_404(self):
        with _Server() as s:
            status, _ = s.request("GET", "/api/scans/deadbeef/events")
            self.assertEqual(status, 404)

    def test_scan_token_is_single_use(self):
        with _Server() as s:
            _, body = s.request("POST", "/api/scans",
                                headers={"Content-Type": "application/json"},
                                body=json.dumps({"sample": "php_native"}))
            token = json.loads(body)["scan_id"]
            s.stream(f"/api/scans/{token}/events", until="event: scan_done")  # consume
            status, _ = s.request("GET", f"/api/scans/{token}/events")        # again
            self.assertEqual(status, 404)


class TestRunFlow(unittest.TestCase):
    def test_get_run_no_longer_starts_a_benchmark(self):
        # The old GET /api/run start route is gone, so a forced cross-site GET
        # (an <img>/<script> with a valid Host and no Origin) cannot drive the load.
        with _Server() as s:
            status, _ = s.request("GET", "/api/run?split=all&runs=5")
            self.assertEqual(status, 404)

    def test_post_run_creates_job(self):
        with _Server() as s:
            status, body = s.request(
                "POST", "/api/runs",
                headers={"Content-Type": "application/json"},
                body=json.dumps({"split": "all", "runs": 3, "budget": 50}))
            self.assertEqual(status, 200)
            d = json.loads(body)
            self.assertTrue(d["run_id"])
            self.assertEqual(d["events_url"], f"/api/runs/{d['run_id']}/events")

    def test_post_run_then_sse_streams_it(self):
        # An empty split lets the benchmark complete offline (no target apps needed):
        # _stream emits `start` then `done` with no per-run events in between.
        server.SPLITS["_test_empty"] = lambda: []
        try:
            with _Server() as s:
                _, body = s.request(
                    "POST", "/api/runs",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"split": "_test_empty"}))
                token = json.loads(body)["run_id"]
                status, stream = s.stream(f"/api/runs/{token}/events", until="event: done")
                self.assertEqual(status, 200)
                self.assertIn("event: start", stream)
                self.assertIn("event: done", stream)
        finally:
            server.SPLITS.pop("_test_empty", None)

    def test_unknown_run_token_is_404(self):
        with _Server() as s:
            status, _ = s.request("GET", "/api/runs/deadbeef/events")
            self.assertEqual(status, 404)

    def test_non_object_json_body_is_treated_as_empty(self):
        # A valid-but-non-object body must not crash the handler; it falls back
        # to defaults and still registers a job.
        with _Server() as s:
            status, body = s.request("POST", "/api/runs",
                                     headers={"Content-Type": "application/json"},
                                     body=json.dumps([1, 2, 3]))
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body)["run_id"])

    def test_run_token_is_single_use(self):
        server.SPLITS["_test_empty"] = lambda: []
        try:
            with _Server() as s:
                _, body = s.request("POST", "/api/runs",
                                    headers={"Content-Type": "application/json"},
                                    body=json.dumps({"split": "_test_empty"}))
                token = json.loads(body)["run_id"]
                s.stream(f"/api/runs/{token}/events", until="event: done")   # consume
                status, _ = s.request("GET", f"/api/runs/{token}/events")    # again
                self.assertEqual(status, 404)
        finally:
            server.SPLITS.pop("_test_empty", None)


class TestBoundedParams(unittest.TestCase):
    def test_non_integer_run_param_is_400(self):
        with _Server() as s:
            status, _ = s.request("POST", "/api/runs",
                                  headers={"Content-Type": "application/json"},
                                  body=json.dumps({"runs": "abc"}))
            self.assertEqual(status, 400)

    def test_out_of_range_run_param_is_400(self):
        with _Server() as s:
            status, _ = s.request("POST", "/api/runs",
                                  headers={"Content-Type": "application/json"},
                                  body=json.dumps({"runs": 99999}))
            self.assertEqual(status, 400)

    def test_out_of_range_budget_is_400(self):
        with _Server() as s:
            status, _ = s.request("POST", "/api/runs",
                                  headers={"Content-Type": "application/json"},
                                  body=json.dumps({"budget": 1}))
            self.assertEqual(status, 400)


class TestConcurrencyLimit(unittest.TestCase):
    def test_scan_post_429_when_at_capacity(self):
        orig = server.MAX_ACTIVE["scan"]
        server.MAX_ACTIVE["scan"] = 1
        try:
            with _Server() as s:                # __enter__ zeroes the counters
                with server._JOBS_LOCK:
                    server._active["scan"] = 1  # pretend one scan is already running
                status, body = s.request(
                    "POST", "/api/scans",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"sample": "php_native"}))
                self.assertEqual(status, 429)
                self.assertIn("message", json.loads(body))
        finally:
            server.MAX_ACTIVE["scan"] = orig

    def test_run_post_429_when_at_capacity(self):
        orig = server.MAX_ACTIVE["run"]
        server.MAX_ACTIVE["run"] = 1
        try:
            with _Server() as s:
                with server._JOBS_LOCK:
                    server._active["run"] = 1
                status, _ = s.request(
                    "POST", "/api/runs",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"split": "all"}))
                self.assertEqual(status, 429)
        finally:
            server.MAX_ACTIVE["run"] = orig

    def _wait_slot_zero(self, kind, timeout=5.0):
        # The server frees the slot in a finally block just after it sends the final
        # event, which can land a hair after the client sees it and closes; poll.
        end = time.time() + timeout
        while time.time() < end and server._active[kind] != 0:
            time.sleep(0.02)
        self.assertEqual(server._active[kind], 0)

    def test_scan_slot_released_after_stream(self):
        with _Server() as s:
            _, body = s.request("POST", "/api/scans",
                                headers={"Content-Type": "application/json"},
                                body=json.dumps({"sample": "php_native"}))
            token = json.loads(body)["scan_id"]
            self.assertEqual(server._active["scan"], 1)        # held while registered
            s.stream(f"/api/scans/{token}/events", until="event: scan_done")
            self._wait_slot_zero("scan")                       # freed when the stream ends

    def test_abandoned_scan_slot_is_pruned(self):
        # A job that is POSTed but never streamed must not leak its slot: pruning
        # the expired job frees it.
        with _Server() as s:
            _, body = s.request("POST", "/api/scans",
                                headers={"Content-Type": "application/json"},
                                body=json.dumps({"sample": "php_native"}))
            token = json.loads(body)["scan_id"]
            self.assertEqual(server._active["scan"], 1)
            with server._JOBS_LOCK:
                server._SCAN_JOBS[token]["created"] -= server.JOB_TTL + 1
                server._prune_jobs(server._SCAN_JOBS, "scan")
            self.assertNotIn(token, server._SCAN_JOBS)
            self.assertEqual(server._active["scan"], 0)


class TestCloneSizeLimit(unittest.TestCase):
    def test_tree_size_over_detects_excess(self):
        d = tempfile.mkdtemp(prefix="sbvf_sizetest_")
        try:
            with open(os.path.join(d, "big.bin"), "wb") as fh:
                fh.write(b"\0" * 4096)
            self.assertTrue(repo._tree_size_over(d, 1024))    # 4 KiB > 1 KiB cap
            self.assertFalse(repo._tree_size_over(d, 8192))   # 4 KiB < 8 KiB cap
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_empty_tree_is_never_over(self):
        d = tempfile.mkdtemp(prefix="sbvf_sizetest_")
        try:
            self.assertFalse(repo._tree_size_over(d, 0))
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestCredentialScrubbing(unittest.TestCase):
    def test_scrub_removes_userinfo_from_urls(self):
        dirty = "fatal: could not read from https://alice:ghp_secret@git.example/x.git"
        clean = repo.scrub_credentials(dirty)
        self.assertNotIn("ghp_secret", clean)
        self.assertNotIn("alice", clean)
        self.assertIn("https://***@git.example/x.git", clean)

    def test_scrub_leaves_plain_urls_untouched(self):
        self.assertEqual(repo.scrub_credentials("clone of https://github.com/o/r.git"),
                         "clone of https://github.com/o/r.git")

    def test_uses_credentials_follows_extra_hosts_env(self):
        os.environ["SBVF_EXTRA_GIT_HOSTS"] = "git.internal.test"
        try:
            self.assertTrue(repo.uses_credentials("https://git.internal.test/g/r"))
            self.assertFalse(repo.uses_credentials("https://github.com/o/r"))
        finally:
            os.environ.pop("SBVF_EXTRA_GIT_HOSTS", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
