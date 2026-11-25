"""Intentionally vulnerable Flask app (academic SAST target)."""
import os
import sqlite3

from flask import Flask, Markup, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")   # VULN: SQL injection
    return Markup("<h1>Hi " + name + "</h1>")                        # VULN: reflected XSS


@app.route("/item/<iid>")
def get_item(iid):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE id = '" + iid + "'")      # VULN: SQLi via path param
    return "ok"


@app.route("/run")
def run_cmd():
    os.system(request.args.get("cmd"))                              # VULN: command injection
    return "ok"


@app.route("/safe")
def safe():
    uid = request.args.get("uid")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))          # parameterized -> safe
    return "ok"
