"""Hardened configuration counterparts (should produce no findings)."""
import os

from flask import Flask
from flask_cors import CORS

# ---- SAFE ------------------------------------------------------------------
DEBUG = os.environ.get("APP_DEBUG") == "1"     # off by default
ALLOWED_HOSTS = ["app.example.com"]            # explicit host list
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True

app = Flask(__name__)
CORS(app, origins=["https://app.example.com"])  # explicit origin allow-list


@app.route("/")
def index():
    resp = app.make_response("hi")
    resp.set_cookie("session", "abc", secure=True, httponly=True, samesite="Lax")
    return resp
