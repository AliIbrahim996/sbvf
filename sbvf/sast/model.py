"""Shared data model for the static analyzer: vulnerability classes and findings.

Kept framework- and language-agnostic so the PHP and Python analyzers emit the
same ``Finding`` records and the dashboard/CLI can render them uniformly.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


# Canonical vulnerability classes. Besides CWE / severity / title / desc, each
# carries the three remediation panels the dashboard and PDF report render:
#   impact   -> business impact ("what you'd lose")
#   fix      -> ordered remediation steps ("how to close it")
#   owner    -> the team that usually owns the fix
#   exposure -> what an attacker reaches: Data / Accounts / Systems
# "How it got in" is composed per finding from its own source -> sink path.
VULN_INFO = {
    "sqli": {
        "cwe": "CWE-89", "severity": "high", "title": "SQL Injection",
        "desc": "User input reaches a SQL query without parameterization or escaping.",
        "owner": "Backend / data access", "exposure": ["Data", "Accounts", "Systems"],
        "impact": "An attacker can read or modify the whole database — user records, "
                  "password hashes, orders — bypass authentication, and in some setups "
                  "run commands on the database host. This is a direct data-breach path.",
        "fix": [
            "Use parameterized queries / prepared statements; never concatenate input into SQL.",
            "With an ORM or query builder, pass values as bound parameters, not raw fragments.",
            "Validate and type-cast identifiers (e.g. integer ids) before use.",
            "Apply least-privilege DB accounts so an injection cannot escalate.",
        ],
    },
    "xss": {
        "cwe": "CWE-79", "severity": "high", "title": "Cross-Site Scripting (XSS)",
        "desc": "User input is written to an HTML response without output encoding.",
        "owner": "Frontend / templating", "exposure": ["Accounts", "Data"],
        "impact": "An attacker can run script in victims' browsers: steal session cookies "
                  "and tokens, perform actions as the victim, deface pages, or deliver "
                  "phishing — leading to account takeover.",
        "fix": [
            "Output-encode untrusted data for the HTML context (escape < > \" ' &).",
            "Prefer auto-escaping template constructs; avoid raw/unescaped output.",
            "Sanitize rich HTML with an allow-list library (e.g. DOMPurify) when markup is needed.",
            "Add a Content-Security-Policy as defense in depth.",
        ],
    },
    "command_injection": {
        "cwe": "CWE-78", "severity": "high", "title": "OS Command Injection",
        "desc": "User input reaches an operating-system command interpreter.",
        "owner": "Backend / platform", "exposure": ["Systems", "Data", "Accounts"],
        "impact": "An attacker can run arbitrary commands on the server with the app's "
                  "privileges — full host compromise, data theft, lateral movement, and "
                  "persistence. Among the most severe outcomes possible.",
        "fix": [
            "Avoid shelling out; use native library APIs for the task instead.",
            "If a process must be spawned, pass arguments as a list and disable the shell.",
            "Never interpolate input into a command string; validate against a strict allow-list.",
            "Run the service as an unprivileged user and sandbox it.",
        ],
    },
    "code_injection": {
        "cwe": "CWE-94", "severity": "high", "title": "Code Injection",
        "desc": "User input reaches a dynamic code-evaluation sink (eval/exec).",
        "owner": "Backend", "exposure": ["Systems", "Data", "Accounts"],
        "impact": "An attacker can execute arbitrary application code, equivalent to full "
                  "server compromise — read secrets, alter logic, and pivot to the host.",
        "fix": [
            "Remove dynamic evaluation (eval/exec/new Function/deserialization of input).",
            "Replace with explicit parsing — e.g. a safe JSON/number parser or a dispatch map.",
            "If templating is needed, use a sandboxed engine with no code execution.",
        ],
    },
    "file_inclusion": {
        "cwe": "CWE-98", "severity": "high", "title": "File Inclusion",
        "desc": "User input controls an include/require path.",
        "owner": "Backend", "exposure": ["Systems", "Data"],
        "impact": "An attacker can include local or remote files — leaking source and "
                  "secrets, and often achieving code execution via a planted or remote file.",
        "fix": [
            "Never build an include/require path from input.",
            "Map a request value to an allow-list of known files instead of using it as a path.",
            "Disable remote includes; resolve and confine paths to an intended base directory.",
        ],
    },
    "path_traversal": {
        "cwe": "CWE-22", "severity": "medium", "title": "Path Traversal",
        "desc": "User input controls a filesystem path passed to a file operation.",
        "owner": "Backend", "exposure": ["Data"],
        "impact": "An attacker can read or write files outside the intended directory "
                  "(e.g. /etc/passwd, config, keys) using ../ sequences, exposing secrets "
                  "or corrupting files.",
        "fix": [
            "Resolve the final path and verify it stays within an allowed base directory.",
            "Use a safe basename / allow-list of filenames rather than the raw value.",
            "Reject path separators and traversal sequences in the input.",
        ],
    },
    "open_redirect": {
        "cwe": "CWE-601", "severity": "medium", "title": "Open Redirect",
        "desc": "User input controls a redirect target.",
        "owner": "Backend / auth", "exposure": ["Accounts"],
        "impact": "An attacker can send users to an attacker-controlled site from a "
                  "trusted link — enabling phishing and OAuth/token theft on login flows.",
        "fix": [
            "Redirect only to a server-side allow-list of paths or hosts.",
            "Accept a relative path or a short key that maps to a known URL, not a full URL.",
            "Reject absolute/scheme-relative targets (http(s):// and //host).",
        ],
    },
    "ssrf": {
        "cwe": "CWE-918", "severity": "medium", "title": "Server-Side Request Forgery",
        "desc": "User input controls the URL of an outbound server request.",
        "owner": "Backend / platform", "exposure": ["Systems", "Data"],
        "impact": "An attacker can make the server call internal services and cloud "
                  "metadata endpoints — reaching systems behind the firewall and stealing "
                  "credentials or internal data.",
        "fix": [
            "Allow-list the hosts/schemes the server may call; deny by default.",
            "Resolve the target and block private, loopback and link-local ranges.",
            "Disable unneeded protocols and do not follow redirects to blocked hosts.",
        ],
    },
    "idor": {
        "cwe": "CWE-639", "severity": "high", "title": "Insecure Direct Object Reference (IDOR)",
        "desc": "A request-supplied object id reaches a data lookup with no ownership or "
                "access-control check.",
        "owner": "Backend / auth", "exposure": ["Data", "Accounts"],
        "impact": "An attacker can read or change other users' records by changing an id "
                  "in the request — a broken-access-control breach of confidentiality and "
                  "integrity across accounts.",
        "fix": [
            "Enforce an ownership/authorization check on every object access.",
            "Scope queries to the authenticated user (e.g. WHERE user_id = current_user).",
            "Prefer unguessable identifiers, but treat them as defense in depth, not the control.",
        ],
    },
    "weak_crypto": {
        "cwe": "CWE-327", "severity": "medium", "title": "Weak or Broken Cryptography",
        "desc": "A weak hash (MD5/SHA-1) or a broken cipher/mode (DES, 3DES, RC4, ECB) is used.",
        "owner": "Backend / security engineering", "exposure": ["Data", "Accounts"],
        "impact": "Hashes can be cracked or forged with commodity hardware, and weak "
                  "ciphers or ECB mode leak plaintext — exposing stored passwords, "
                  "tokens and confidential data after a database or traffic leak.",
        "fix": [
            "Hash passwords with a slow adaptive function (bcrypt, scrypt, Argon2) and a per-user salt.",
            "Use SHA-256 or stronger (or HMAC-SHA-256) for integrity and signatures.",
            "Replace DES/3DES/RC4 and ECB with AES-GCM or ChaCha20-Poly1305 using a fresh random nonce.",
            "Prefer a vetted high-level library (e.g. libsodium, Fernet) over hand-assembled primitives.",
        ],
    },
    "broken_tls": {
        "cwe": "CWE-295", "severity": "high", "title": "Improper Certificate Validation",
        "desc": "TLS certificate or hostname verification is disabled for an outbound connection.",
        "owner": "Backend / platform", "exposure": ["Data", "Accounts", "Systems"],
        "impact": "Anyone on the network path can impersonate the remote service and read "
                  "or alter the traffic — stealing credentials, API tokens and data, or "
                  "injecting malicious responses.",
        "fix": [
            "Remove verify=False / rejectUnauthorized:false / VERIFYPEER=false and keep verification on.",
            "For private CAs or self-signed dev certificates, trust the specific CA bundle instead.",
            "Keep hostname verification enabled (CURLOPT_SSL_VERIFYHOST=2, check_hostname=True).",
            "Never set NODE_TLS_REJECT_UNAUTHORIZED=0 outside throwaway local tests.",
        ],
    },
    "hardcoded_secret": {
        "cwe": "CWE-798", "severity": "high", "title": "Hard-coded Credentials or Key",
        "desc": "A key, secret, password, token or IV is embedded as a literal in source code.",
        "owner": "Backend / DevOps", "exposure": ["Accounts", "Data", "Systems"],
        "impact": "Anyone with read access to the repository, a build artifact or a leaked "
                  "copy of the code gains the credential — enabling token forgery, "
                  "decryption of stored data and access to connected services. Rotation "
                  "requires a code release.",
        "fix": [
            "Move secrets to environment variables or a secrets manager (Vault, AWS/GCP Secrets Manager).",
            "Rotate every secret that was ever committed and purge it from history.",
            "Generate keys and IVs at runtime with a CSPRNG; never reuse a static IV.",
            "Add secret scanning (pre-commit / CI) to block new literals.",
        ],
    },
    "weak_random": {
        "cwe": "CWE-338", "severity": "medium", "title": "Insecure Randomness",
        "desc": "A non-cryptographic PRNG (random, Math.random, rand/mt_rand/uniqid) generates a secret value.",
        "owner": "Backend / security engineering", "exposure": ["Accounts", "Data"],
        "impact": "Tokens, reset links, session ids and keys can be predicted from a few "
                  "observed outputs, enabling account takeover and forged credentials.",
        "fix": [
            "Use a CSPRNG: secrets.token_urlsafe / os.urandom (Python), crypto.randomBytes (Node), random_bytes (PHP).",
            "Make tokens at least 128 bits long and single-use with an expiry.",
            "Never derive secrets from time, uniqid() or a seeded generator.",
        ],
    },
    # --- OWASP A02: Security Misconfiguration (sbvf/sast/rules.py) ------------
    "debug_enabled": {
        "cwe": "CWE-489", "severity": "high", "title": "Debug Mode Enabled",
        "desc": "A debug/development flag is turned on (DEBUG=True, app.debug, WP_DEBUG).",
        "owner": "Backend / DevOps", "exposure": ["Systems", "Data"],
        "impact": "Debug mode returns stack traces, source and configuration to users, "
                  "leaking secrets and internals; some debuggers (e.g. Werkzeug) allow "
                  "arbitrary code execution on the server.",
        "fix": [
            "Disable debug in production; drive it from an environment variable that defaults off.",
            "Return generic error pages and log details server-side only.",
            "Verify the deployed build has DEBUG/APP_DEBUG false.",
        ],
    },
    "permissive_cors": {
        "cwe": "CWE-942", "severity": "medium", "title": "Permissive CORS Policy",
        "desc": "Cross-Origin Resource Sharing allows any origin (wildcard or reflected).",
        "owner": "Backend / platform", "exposure": ["Data", "Accounts"],
        "impact": "Any website can make credentialed requests and read the responses, so "
                  "a malicious page can exfiltrate a logged-in user's data from this API.",
        "fix": [
            "Allow only an explicit list of trusted origins; never '*' with credentials.",
            "Echo an origin back only after checking it against the allow-list.",
            "Scope CORS to the routes that truly need it.",
        ],
    },
    "insecure_cookie": {
        "cwe": "CWE-614", "severity": "medium", "title": "Insecure Cookie Flags",
        "desc": "A session or security cookie is set without the Secure and/or HttpOnly flag.",
        "owner": "Backend / auth", "exposure": ["Accounts"],
        "impact": "Without Secure the cookie is sent over plain HTTP and can be sniffed; "
                  "without HttpOnly it is readable by JavaScript, so an XSS turns into "
                  "session theft and account takeover.",
        "fix": [
            "Set Secure, HttpOnly and SameSite on session/auth cookies.",
            "In Django set SESSION_COOKIE_SECURE / CSRF_COOKIE_SECURE / *_HTTPONLY to True.",
            "Serve the app over HTTPS only.",
        ],
    },
    "security_misconfig": {
        "cwe": "CWE-16", "severity": "medium", "title": "Security Misconfiguration",
        "desc": "An insecure setting (wildcard ALLOWED_HOSTS, verbose error display, "
                "server fingerprint exposure).",
        "owner": "Backend / DevOps", "exposure": ["Systems", "Data"],
        "impact": "Loose configuration widens the attack surface: wildcard hosts enable "
                  "host-header attacks, verbose errors leak internals, and exposed version "
                  "banners help attackers target known flaws.",
        "fix": [
            "Pin ALLOWED_HOSTS to the real domains; disable display_errors/expose_php in production.",
            "Harden defaults and remove sample/admin endpoints before deploy.",
            "Review the deployment against a security configuration checklist.",
        ],
    },
    # --- OWASP A08: Software and Data Integrity Failures (sbvf/sast/rules.py) -
    "insecure_deserialization": {
        "cwe": "CWE-502", "severity": "high", "title": "Insecure Deserialization",
        "desc": "Data is deserialized with a format that can reconstruct arbitrary objects "
                "(pickle, marshal, PHP unserialize, node-serialize, unsafe YAML).",
        "owner": "Backend / security engineering", "exposure": ["Systems", "Data", "Accounts"],
        "impact": "If the serialized bytes are attacker-controlled, decoding them can "
                  "instantiate arbitrary objects and trigger code execution (RCE) or object "
                  "injection — a software & data integrity failure (OWASP A08) that can "
                  "fully compromise the server.",
        "fix": [
            "Never deserialize untrusted data with code-bearing formats (pickle/marshal/unserialize).",
            "Exchange data as JSON and validate it against a strict schema.",
            "Load YAML with a safe loader (yaml.safe_load / Loader=SafeLoader); in PHP pass allowed_classes=>false.",
            "If a rich format is unavoidable, sign the payload (HMAC) and verify before decoding.",
        ],
    },
    # --- OWASP A10: Mishandling Exceptions (sbvf/sast/rules.py) ---------------
    "error_info_leak": {
        "cwe": "CWE-209", "severity": "medium", "title": "Sensitive Data in Error Message",
        "desc": "An exception message, stack trace or traceback is returned or echoed to the "
                "client instead of being logged server-side.",
        "owner": "Backend / security engineering", "exposure": ["Systems", "Data"],
        "impact": "Leaked exception text and stack traces reveal file paths, framework and "
                  "library versions, SQL, and internal logic — a reconnaissance aid that "
                  "lets an attacker fingerprint the stack and craft targeted exploits, and "
                  "can disclose secrets embedded in the error.",
        "fix": [
            "Return a generic error (and an opaque correlation id) to the client; never the exception text.",
            "Log the full exception and stack trace server-side only.",
            "Disable framework debug/verbose error pages in production.",
            "Add a catch-all error handler that maps unhandled exceptions to a 500 with no detail.",
        ],
    },
    "swallowed_exception": {
        "cwe": "CWE-390", "severity": "low", "title": "Swallowed or Overly Broad Exception",
        "desc": "An exception is caught and silently ignored (empty catch / except: pass) or a "
                "bare/overly broad handler hides the error condition.",
        "owner": "Backend / engineering", "exposure": ["Systems", "Data"],
        "impact": "Silently discarding an error lets the program continue in an unexpected "
                  "state — security checks that fail open, corrupted data written anyway, and "
                  "attacks that leave no trace because the failure was never logged or raised.",
        "fix": [
            "Catch the specific exception you can handle, not a bare except / catch (Throwable).",
            "At minimum log the exception; never leave the handler body empty.",
            "Re-raise or fail closed when the error means the operation cannot safely continue.",
        ],
    },
}

# Severity ordering for sorting the report (most serious first).
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# Breka-style remediation urgency ladder, by severity.
SEVERITY_ACTION = {
    "critical": "Fix before the next release",
    "high": "Fix this sprint",
    "medium": "Schedule it",
    "low": "Track it",
}
# How each input method is phrased in the "how it got in" narrative.
_METHOD_PHRASE = {
    "GET": "a GET query parameter", "POST": "a POST body field",
    "REQUEST": "a request parameter", "PATH": "a URL path segment",
    "COOKIE": "a cookie", "HEADER": "a request header",
}


@dataclass
class Finding:
    """One statically-detected vulnerability, anchored to a source location."""

    vuln: str                     # key into VULN_INFO, e.g. "sqli"
    file: str                     # path relative to the scanned root
    line: int                     # 1-based line number of the sink
    sink: str                     # the dangerous construct, e.g. "mysqli_query"
    source: str                   # where the taint originated, e.g. "$_GET['id']"
    framework: str                # "php-native" | "yii" | "laravel" | ...
    code: str = ""                # the offending source line (trimmed)
    message: str = ""             # human-readable explanation
    column: int = 0               # best-effort column of the sink
    param: str = ""               # the request parameter carrying the taint (e.g. "id")
    method: str = "GET"           # how the input arrives: GET | POST | REQUEST | COOKIE | PATH | ...
    function: str = ""            # enclosing function (the request handler), "" at module level
    rule: str = ""                # pattern-rule id (non-taint findings), "" for taint findings
    how: str = ""                 # explicit "how it got in" narrative (overrides the taint one)

    @property
    def cwe(self) -> str:
        return VULN_INFO.get(self.vuln, {}).get("cwe", "CWE-000")

    @property
    def severity(self) -> str:
        return VULN_INFO.get(self.vuln, {}).get("severity", "low")

    @property
    def title(self) -> str:
        return VULN_INFO.get(self.vuln, {}).get("title", self.vuln)

    @property
    def impact(self) -> str:
        return VULN_INFO.get(self.vuln, {}).get("impact", "")

    @property
    def fix(self) -> list:
        return list(VULN_INFO.get(self.vuln, {}).get("fix", []))

    @property
    def owner(self) -> str:
        return VULN_INFO.get(self.vuln, {}).get("owner", "Engineering")

    @property
    def exposure(self) -> list:
        return list(VULN_INFO.get(self.vuln, {}).get("exposure", []))

    @property
    def action(self) -> str:
        return SEVERITY_ACTION.get(self.severity, "Track it")

    @property
    def how_in(self) -> str:
        """Per-finding 'how it got in' narrative from this taint path."""
        if self.how:
            return self.how
        where = _METHOD_PHRASE.get(self.method, "an untrusted input")
        param = f" '{self.param}'" if self.param else ""
        loc = f" in {self.framework}" if self.framework else ""
        handler = f" (handler {self.function})" if self.function else ""
        return (f"Untrusted input from {self.source} — {where}{param} — flows "
                f"unsanitized into {self.sink} at {self.location()}{handler}{loc}. "
                f"Because nothing encodes, validates or parameterizes it on the way, "
                f"an attacker-controlled value reaches the {self.title} sink.")

    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(cwe=self.cwe, severity=self.severity, title=self.title,
                 location=self.location(), impact=self.impact, fix=self.fix,
                 owner=self.owner, exposure=self.exposure, action=self.action,
                 how_in=self.how_in)
        return d

    def __str__(self) -> str:
        return (f"[{self.severity.upper():6}] {self.title} ({self.cwe})  "
                f"{self.location()}\n"
                f"         source: {self.source}  ->  sink: {self.sink}\n"
                f"         {self.code.strip()[:120]}")


@dataclass
class Step:
    """A single progress event emitted while scanning (streamed to the UI)."""

    kind: str                     # "detect" | "file" | "source" | "finding" | "summary"
    text: str                     # one-line log message
    data: dict = field(default_factory=dict)
