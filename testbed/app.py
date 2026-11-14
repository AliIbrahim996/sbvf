"""Local testbed with known, labelled vulnerabilities (ground truth) for evaluation.

A tiny web application using the standard library only (http.server + sqlite3), no
external dependencies. It exposes labelled endpoints: some vulnerable, some safe, so
Recall and False Positives can be measured precisely against the ground truth.

Security note: this application is intentionally vulnerable. It binds to 127.0.0.1
only and is for academic research use exclusively.
"""
import html
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8013


def build_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users(id INTEGER, name TEXT, secret TEXT)")
    db.executemany(
        "INSERT INTO users VALUES(?,?,?)",
        [(1, "admin", "FLAG{secret-admin}"), (2, "ali", "pw2"), (3, "guest", "pw3")],
    )
    db.commit()
    return db


DB = build_db()


# ---------------------------------------------------------------------------
# Ground truth: classification of every endpoint. The framework never sees this
# file; it is used only for evaluation.
# ---------------------------------------------------------------------------
GROUND_TRUTH = {
    "/xss/reflect_raw":   {"param": "q", "vuln": "xss",  "label": "vulnerable", "note": "no encoding at all"},
    "/xss/reflect_lt":    {"param": "q", "vuln": "xss",  "label": "vulnerable", "note": "weak filter: removes <script> tags only, bypassable via other tags/case"},
    "/xss/attr":          {"param": "q", "vuln": "xss",  "label": "vulnerable", "note": "attribute context, strips < > but not quotes"},
    "/xss/safe":          {"param": "q", "vuln": "xss",  "label": "safe",       "note": "full html.escape"},
    "/sqli/error":        {"param": "name", "vuln": "sqli", "label": "vulnerable", "note": "string concatenation, errors shown"},
    "/sqli/blind":        {"param": "name", "vuln": "sqli", "label": "vulnerable", "note": "boolean blind"},
    "/sqli/safe":         {"param": "name", "vuln": "sqli", "label": "safe",       "note": "parameterized query"},
    "/clickjacking/vuln": {"param": None, "vuln": "clickjacking", "label": "vulnerable", "note": "no frame header"},
    "/clickjacking/safe": {"param": None, "vuln": "clickjacking", "label": "safe",       "note": "X-Frame-Options: DENY"},
}


def page(body):
    return f"<!doctype html><html><body>{body}</body></html>".encode()


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
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        q = qs.get("q", [""])[0]
        name = qs.get("name", [""])[0]

        if path in ("/", "/index"):
            links = "".join(f'<li><a href="{p}">{p}</a> - {g["label"]}</li>'
                            for p, g in GROUND_TRUTH.items())
            return self._send(page(f"<h1>Testbed</h1><ul>{links}</ul>"))

        # ---- XSS ----
        if path == "/xss/reflect_raw":
            return self._send(page(f"<p>search result for: {q}</p>"))
        if path == "/xss/reflect_lt":
            # Weak blacklist filter: strips the exact "<script>"/"</script>" tags
            # (case-sensitive). Bypassable with other tags (<img>, <svg>) or mixed
            # case (<ScRiPt>), which is exactly what a guided search can discover.
            v = q.replace("<script>", "").replace("</script>", "")
            return self._send(page(f"<p>result: {v}</p>"))
        if path == "/xss/attr":
            v = q.replace("<", "").replace(">", "")
            return self._send(page(f'<input value="{v}"></p>'))
        if path == "/xss/safe":
            return self._send(page(f"<p>{html.escape(q)}</p>"))

        # ---- SQLi ----
        if path == "/sqli/error":
            try:
                rows = DB.execute(
                    f"SELECT name FROM users WHERE name='{name}'").fetchall()
                return self._send(page(f"<p>found: {len(rows)}</p>"))
            except Exception as e:
                return self._send(page(f"<p>SQL error: {html.escape(str(e))}</p>"), 500)
        if path == "/sqli/blind":
            try:
                rows = DB.execute(
                    f"SELECT name FROM users WHERE name='{name}'").fetchall()
            except Exception:
                rows = []
            # success/failure without revealing the error
            return self._send(page("<p>welcome</p>" if rows else "<p>no user</p>"))
        if path == "/sqli/safe":
            rows = DB.execute(
                "SELECT name FROM users WHERE name=?", (name,)).fetchall()
            return self._send(page(f"<p>found: {len(rows)}</p>"))

        # ---- Clickjacking ----
        if path == "/clickjacking/vuln":
            return self._send(page("<h2>Transfer money</h2><button>Confirm</button>"))
        if path == "/clickjacking/safe":
            return self._send(page("<h2>Transfer money</h2><button>Confirm</button>"),
                              headers={"X-Frame-Options": "DENY"})

        return self._send(page("<p>404</p>"), 404)


def main():
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"Testbed on http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
