"""Extra vulnerable app 'blog' for the benchmark (standard library only).

Intentionally vulnerable; binds to 127.0.0.1 only; academic research use only.
Endpoints are labelled in sbvf/datasets.py (the app itself never exposes labels).
"""
import html
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8014


def _db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE accounts(id INTEGER, user TEXT, pw TEXT)")
    db.executemany("INSERT INTO accounts VALUES(?,?,?)",
                   [(1, "root", "FLAG{blog}"), (2, "ali", "x")])
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

        if p.path == "/search":                     # raw reflection (vulnerable)
            return self._send(page(f"<h3>Results for {g('term')}</h3>"))
        if p.path == "/greet":                      # strips angle brackets only -> attr/js still work via quotes
            v = g("user")
            return self._send(page(f'<span title="{v}">hi</span>'))
        if p.path == "/comment_safe":               # safe
            return self._send(page(f"<p>{html.escape(g('text'))}</p>"))
        if p.path == "/login":                      # error-based sqli (vulnerable)
            try:
                rows = DB.execute(
                    f"SELECT user FROM accounts WHERE user='{g('user')}'").fetchall()
                return self._send(page(f"<p>rows: {len(rows)}</p>"))
            except Exception as e:
                return self._send(page(f"<p>SQL error: {html.escape(str(e))}</p>"), 500)
        if p.path == "/profile_safe":               # parameterized (safe)
            rows = DB.execute("SELECT user FROM accounts WHERE id=?",
                              (g("id"),)).fetchall()
            return self._send(page(f"<p>rows: {len(rows)}</p>"))
        if p.path == "/embed":                       # no frame header (clickjacking)
            return self._send(page("<h2>Post comment</h2><button>Send</button>"))
        return self._send(page("<p>404</p>"), 404)


def main():
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"blog app on http://{HOST}:{PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
