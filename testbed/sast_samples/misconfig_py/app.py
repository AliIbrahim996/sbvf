"""Intentionally misconfigured settings (academic SAST target, OWASP A02)."""
from flask import Flask
from flask_cors import CORS

# ---- VULNERABLE -----------------------------------------------------------
DEBUG = True                                  # debug_enabled
ALLOWED_HOSTS = ["*"]                          # security_misconfig
SESSION_COOKIE_SECURE = False                  # insecure_cookie
SESSION_COOKIE_HTTPONLY = False                # insecure_cookie

app = Flask(__name__)
CORS(app)                                      # permissive_cors (wide open)


@app.route("/")
def index():
    resp = app.make_response("hi")
    resp.set_cookie("session", "abc", secure=False, httponly=False)  # insecure_cookie
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)        # debug_enabled
