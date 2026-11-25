"""Tests for the SBVF dashboard server's request hardening (ui/server.py).

Covers the Host/Origin/Content-Type guard, the POST-to-start / SSE-to-stream scan
flow (a cross-site GET can no longer start a scan), bounded numeric parameters,
and git-credential scrubbing.

Runnable with pytest or `python -m tests.test_ui_server`.
"""
import http.client
import os
import sys
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


class TestBoundedParams(unittest.TestCase):
    def test_non_integer_run_param_is_400(self):
        with _Server() as s:
            status, _ = s.request("GET", "/api/run?runs=abc")
            self.assertEqual(status, 400)

    def test_out_of_range_run_param_is_400(self):
        with _Server() as s:
            status, _ = s.request("GET", "/api/run?runs=99999")
            self.assertEqual(status, 400)


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
