"""Hardened counterpart: handle errors without leaking or swallowing them."""
import logging

from flask import jsonify, request

log = logging.getLogger(__name__)


def divide():
    try:
        return str(int(request.args["a"]) / int(request.args["b"]))
    except (ValueError, ZeroDivisionError):
        # specific exception, generic client message, detail logged server-side
        log.exception("divide failed")
        return jsonify(error="invalid input"), 400


def silent():
    try:
        risky(request.args["y"])
    except RuntimeError:
        log.exception("risky failed")      # logged, not swallowed
        raise
    return "ok"
