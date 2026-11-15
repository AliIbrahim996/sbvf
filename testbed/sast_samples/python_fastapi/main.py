"""Intentionally vulnerable FastAPI app (academic SAST target)."""
import os
import sqlite3

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/user")
def get_user(name: str):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # VULN: SQL injection
    return HTMLResponse("<h1>Hi " + name + "</h1>")                 # VULN: reflected XSS


@app.get("/run")
def run_cmd(cmd: str = Query(...)):
    os.system(cmd)                                                 # VULN: command injection
    return {"ok": True}


@app.get("/safe")
def safe(uid: int):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))        # parameterized -> safe
    return {"ok": True}
