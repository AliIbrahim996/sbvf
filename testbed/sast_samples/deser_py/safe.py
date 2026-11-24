"""Hardened counterpart: the same features without deserialization risk."""
import json

import yaml
from flask import request


def load_session():
    # JSON cannot reconstruct arbitrary objects.
    return json.loads(request.get_data())


def load_config():
    # safe_load builds only plain scalars/dicts/lists, never Python objects.
    return yaml.safe_load(request.get_data())


def load_config_explicit():
    return yaml.load(request.get_data(), Loader=yaml.SafeLoader)
