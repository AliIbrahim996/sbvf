"""Extra app 'shop' with stronger-but-imperfect filters (standard library only).

Intentionally vulnerable; binds to 127.0.0.1 only; academic research use only.
Designed so trivial payloads fail and a guided search is rewarded: the XSS endpoint
blocks the word 'script' and parentheses pairs, but event-handler attribute breakout
still works; the SQLi endpoint blocks spaces but comment-based evasion works.
"""
import html
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8015


def _db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE items(sku TEXT, price TEXT)")
    db.executemany("INSERT INTO items VALUES(?,?)", [("A1", "10"), ("B2", "20")])
    db.commit()
    return db


DB = _db()


def page(b):
    return f"<!doctype html><html><body>{b}</body></html>".encode()


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

        if p.path == "/find":                    # blocks 'script' (case-insensitive) in an attribute context
            v = g("kw")
            filtered = v.replace("script", "").replace("SCRIPT", "")
            return self._send(page(f'<input value="{filtered}">'))
        if p.path == "/note":                    # safe
            return self._send(page(f"<p>{html.escape(g('msg'))}</p>"))
        if p.path == "/item":                    # blocks spaces -> needs /**/ or comment evasion
            sku = g("sku").replace(" ", "")
            try:
                rows = DB.execute(
                    f"SELECT price FROM items WHERE sku='{sku}'").fetchall()
                return self._send(page(f"<p>price rows: {len(rows)}</p>"))
            except Exception as e:
                return self._send(page(f"<p>SQL error: {html.escape(str(e))}</p>"), 500)
        if p.path == "/order_safe":              # parameterized (safe)
            rows = DB.execute("SELECT price FROM items WHERE sku=?",
                              (g("oid"),)).fetchall()
            return self._send(page(f"<p>rows: {len(rows)}</p>"))
        if p.path == "/panel":                   # protected (safe)
            return self._send(page("<h2>Admin</h2>"),
                              headers={"Content-Security-Policy": "frame-ancestors 'none'"})
        return self._send(page("<p>404</p>"), 404)


def main():
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"shop app on http://{HOST}:{PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
