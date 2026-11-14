"""Start all benchmark apps in background threads on their fixed localhost ports.

Used by both the experiment runner and the UI so a single call brings the whole
benchmark online without external processes.
"""
from __future__ import annotations

import importlib
import threading
import time
from http.server import ThreadingHTTPServer

# app module name -> (import path, port)
APPS = {
    "bank": ("testbed.app", 8013),
    "blog": ("testbed.apps.blog", 8014),
    "shop": ("testbed.apps.shop", 8015),
    "wafapp": ("testbed.apps.wafapp", 8016),
}


def start_all():
    """Return (servers, base_urls). Call stop_all(servers) when done."""
    servers = []
    base_urls = {}
    for name, (modpath, port) in APPS.items():
        mod = importlib.import_module(modpath)
        srv = ThreadingHTTPServer(("127.0.0.1", port), mod.H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        base_urls[name] = f"http://127.0.0.1:{port}"
    time.sleep(0.3)
    return servers, base_urls


def stop_all(servers):
    for s in servers:
        try:
            s.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    servers, urls = start_all()
    print("Apps running:")
    for n, u in urls.items():
        print(f"  {n}: {u}")
    print("Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_all(servers)
