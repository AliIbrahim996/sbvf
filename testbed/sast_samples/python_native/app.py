"""Intentionally vulnerable native-Python WSGI-style app (academic SAST target)."""
import os
import sqlite3


def handle(environ):
    user = environ['QUERY_STRING']                       # taint source (WSGI)
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + user + "'")  # VULN: SQL injection
    os.system("ping -c1 " + user)                        # VULN: command injection
    eval(user)                                           # VULN: code injection
    return [user.encode()]


def safe(environ):
    raw = environ['QUERY_STRING']
    uid = int(raw)                                       # cast -> safe
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))  # parameterized -> safe
    os.system("ping -c1 127.0.0.1")                      # constant -> safe
