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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sbvf import datasets                    # noqa: E402
from sbvf.experiment import iter_runs, analyze, SPLITS  # noqa: E402
from testbed.launcher import start_all       # noqa: E402

# Bind host is configurable so the UI can be exposed from inside a container
# (set SBVF_UI_HOST=0.0.0.0). The benchmark apps always stay on 127.0.0.1.
UI_HOST = os.environ.get("SBVF_UI_HOST", "127.0.0.1")
UI_PORT = int(os.environ.get("SBVF_UI_PORT", "8080"))
BASE_URLS = {}

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

        self.send_response(404)
        self.end_headers()

    def _sse(self, event, data):
        payload = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        self.wfile.write(payload.encode("utf-8"))
        self.wfile.flush()

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
