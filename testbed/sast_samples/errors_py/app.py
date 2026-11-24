"""Intentionally mishandled exceptions (academic SAST target, OWASP A10)."""
import traceback

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)


# ---- VULNERABLE -----------------------------------------------------------
@app.route("/divide")
def divide():
    try:
        return str(int(request.args["a"]) / int(request.args["b"]))
    except Exception as e:
        return jsonify(error=str(e))               # error_info_leak


@app.route("/debug")
def debug():
    try:
        return do_work(request.args["x"])
    except Exception:
        return make_response(traceback.format_exc(), 500)  # error_info_leak


@app.route("/silent")
def silent():
    try:
        risky(request.args["y"])
    except:                                        # swallowed_exception (bare except)
        pass
    return "ok"


@app.route("/ignore")
def ignore():
    try:
        risky(request.args["z"])
    except Exception: pass                         # swallowed_exception (one-liner)
    return "ok"
