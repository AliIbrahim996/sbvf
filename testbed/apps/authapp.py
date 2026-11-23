"""Access-control app 'authapp' for IDOR and RBAC testing (standard library only).

Intentionally vulnerable; binds to 127.0.0.1 only; academic research use only.

Identity model: a `token` query parameter stands in for a session. The framework acts
as a low-privilege user (token "u1", role "user"). Vulnerable endpoints leak other
users' objects (IDOR) or grant admin actions to non-admins (RBAC); safe endpoints
enforce ownership and role checks.
"""
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8017

# token -> (display name, role)
USERS = {
    "u1": ("alice", "user"),
    "u2": ("bob", "user"),
    "adm": ("carol", "admin"),
}

# account id -> (owner token, secret). Low ids are sequential; high ids are sparse
# (they require enumeration rather than a trivial +1 guess).
ACCOUNTS = {
    "1": ("u1", "s-alice-1"), "2": ("u1", "s-alice-2"),
    "3": ("u2", "s-bob-3"),   "4": ("u2", "s-bob-4"),
    "1001": ("u1", "s-alice-h"), "1002": ("u2", "FLAG-bob-secret"),
}

# A second object collection (documents) for an additional IDOR injection point.
DOCS = {
    "10": ("u1", "d-alice-10"), "11": ("u1", "d-alice-11"),
    "12": ("u2", "d-bob-12"), "20": ("u2", "FLAG-bob-doc"),
}


def _record_response(handler, store, id_, token, enforce_owner):
    rec = store.get(id_)
    if not rec:
        return handler._send(page("<p>not found</p>"), 404)
    owner, secret = rec
    if enforce_owner and owner != token:
        return handler._send(page("<p>forbidden</p>"), 403)
    return handler._send(page(f"<p>owner={owner} secret={secret}</p>"))


def page(b):
    return f"<!doctype html><html><body>{b}</body></html>".encode()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(p.query)

        def g(k):
            return qs.get(k, [""])[0]

        token = g("token")
        user = USERS.get(token)

        # ---------------- IDOR ----------------
        if p.path == "/idor/account":            # VULNERABLE: no ownership check
            return _record_response(self, ACCOUNTS, g("id"), token, enforce_owner=False)
        if p.path == "/idor/account_safe":       # SAFE: must own the record
            return _record_response(self, ACCOUNTS, g("id"), token, enforce_owner=True)
        if p.path == "/idor/doc":                # VULNERABLE: documents, no ownership check
            return _record_response(self, DOCS, g("id"), token, enforce_owner=False)
        if p.path == "/idor/doc_safe":           # SAFE
            return _record_response(self, DOCS, g("id"), token, enforce_owner=True)

        # ---------------- RBAC ----------------
        if p.path == "/rbac/admin":              # VULNERABLE: missing function-level check
            if user is None:
                return self._send(page("<p>login required</p>"), 401)
            # bug: grants admin content to ANY authenticated user, ignoring role
            return self._send(page("<p>ADMIN_ONLY dashboard: all-users FLAG</p>"))
        if p.path == "/rbac/dashboard":          # VULNERABLE: trusts a client-supplied role
            if user is None:
                return self._send(page("<p>login required</p>"), 401)
            if g("role") == "admin":             # mass-assignment / parameter tampering
                return self._send(page("<p>ADMIN_ONLY dashboard: tampered FLAG</p>"))
            return self._send(page("<p>user dashboard</p>"))
        if p.path == "/rbac/admin_safe":         # SAFE: real role check
            if user is None:
                return self._send(page("<p>login required</p>"), 401)
            if user[1] != "admin":
                return self._send(page("<p>forbidden</p>"), 403)
            return self._send(page("<p>ADMIN_ONLY dashboard</p>"))
        if p.path == "/rbac/report_safe":        # SAFE: role check, ignores client role param
            if user is None:
                return self._send(page("<p>login required</p>"), 401)
            if user[1] != "admin":
                return self._send(page("<p>forbidden</p>"), 403)
            return self._send(page("<p>ADMIN_ONLY report</p>"))

        return self._send(page("<p>404</p>"), 404)


def main():
    srv = ThreadingHTTPServer((HOST, PORT), H)
    print(f"authapp on http://{HOST}:{PORT}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
