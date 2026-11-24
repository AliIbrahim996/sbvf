"""Intentionally insecure deserialization (academic SAST target, OWASP A08)."""
import marshal
import pickle

import yaml
from flask import Flask, request

app = Flask(__name__)


# ---- VULNERABLE -----------------------------------------------------------
@app.route("/load", methods=["POST"])
def load_session():
    blob = request.get_data()
    obj = pickle.loads(blob)                       # insecure_deserialization
    return str(obj)


@app.route("/code", methods=["POST"])
def load_code():
    return str(marshal.loads(request.get_data()))  # insecure_deserialization


@app.route("/config", methods=["POST"])
def load_config():
    doc = yaml.load(request.get_data())            # insecure_deserialization
    return str(doc)
