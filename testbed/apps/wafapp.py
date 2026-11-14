"""Hard app 'wafapp' with WAF-style blacklist filters (standard library only).

Intentionally vulnerable; binds to 127.0.0.1 only; academic research use only.
These endpoints are the hard tier of the benchmark: trivial payloads are blocked, so
a payload that bypasses the filter is rare in the search space. This is where a
fitness-guided search is expected to show an advantage over random search.
"""
import html
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8016

# Blacklist of common XSS tokens; uncommon tags (<details>, <marquee>) slip through.
XSS_BLACKLIST = ["<script", "<img", "<svg", "<iframe", "<body", "<video",
                 "onerror", "onload", "javascript:"]
# Case-sensitive uppercase SQL keyword blacklist; mixed-case variants evade it.
SQL_BLACKLIST = ["OR", "UNION", "SELECT", "AND"]


def _db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE items(sku TEXT, price TEXT)")
    db.executemany("INSERT INTO items VALUES(?,?)", [("A1", "10"), ("B2", "20")])
    db.commit()
    return db


DB = _db()


def page(b):
    return f"<!doctype html><html><body>{b}</body></html>".encode()


def xss_filter(s):
    for bad in XSS_BLACKLIST:
        s = s.replace(bad, "")
    return s


def sql_filter(s):
    for bad in SQL_BLACKLIST:
        s = s.replace(bad, "")
    return s


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(p.query)

        def g(k):
            return qs.get(k, [""])[0]

        if p.path == "/xss_hard":          # body context, common tags blacklisted
            return self._send(page(f"<div>{xss_filter(g('q'))}</div>"))
        if p.path == "/sqli_hard":         # boolean-only (errors suppressed), uppercase keywords blocked
            sku = sql_filter(g("sku"))
            try:
                rows = DB.execute(
                    f"SELECT price FROM items WHERE sku='{sku}'").fetchall()
            except Exception:
                rows = []                  # suppress errors: no error-based shortcut
            return self._send(page(f"<p>rows: {len(rows)}</p>"))
        if p.path == "/xss_safe_hard":     # same filter but also entity-encodes: safe
            return self._send(page(f"<div>{html.escape(xss_filter(g('q')))}</div>"))
        return self._send(page("<p>404</p>"), 404)


def main():
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"wafapp on http://{HOST}:{PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
