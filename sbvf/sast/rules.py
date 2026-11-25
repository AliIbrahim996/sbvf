"""Line/regex PATTERN-rule engine for non-taint vulnerability classes.

Cryptographic failures (OWASP A04) are not source->sink flows: the weakness is
the mere *use* of a construct (``hashlib.md5``, ``verify=False``, a literal key).
This module is a small, extensible pattern engine for that kind of check.

To add rules for another OWASP item, define ``Rule`` objects, add a matching
``VULN_INFO`` entry in ``model.py`` and append them to ``RULES`` (or call
:func:`register`). ``scan_rules`` walks the project once and applies every
rule whose language matches the file.

Heuristic by design: rules are regexes over single lines, so obfuscated or
multi-line usage can be missed and some matches may be benign.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Pattern, Tuple

from .detect import iter_source_files, detect_frameworks, framework_for
from .model import Finding, Step


def _lang(path: str) -> str:
    if path.endswith(".php"):
        return "php"
    if path.endswith(".py"):
        return "py"
    return "js"      # .js/.jsx/.ts/.tsx/.mjs/.cjs ...


@dataclass
class Rule:
    """One pattern rule. ``patterns`` maps a language key ('php'|'py'|'js') to
    regexes; a rule fires at most once per line."""

    id: str                                   # e.g. "A04-weak-hash"
    vuln: str                                 # key into VULN_INFO
    patterns: Dict[str, List[str]]
    message: str
    # Optional: the line must ALSO match this (context filter), e.g. the line
    # must mention a secret-ish word for weak-randomness rules.
    require: Optional[str] = None
    # Optional: lines matching this are never reported (explicit safe forms).
    exclude: Optional[str] = None
    # Optional per-match veto: called with the regex match, True => skip.
    veto: Optional[Callable[["re.Match"], bool]] = None
    # Optional per-file veto: called with the file's relative path, True => skip
    # this rule for the whole file (e.g. test fixtures / i18n message catalogues).
    file_veto: Optional[Callable[[str], bool]] = None
    _compiled: Dict[str, List[Pattern]] = field(default_factory=dict, repr=False)
    _req: Optional[Pattern] = field(default=None, repr=False)
    _exc: Optional[Pattern] = field(default=None, repr=False)

    def __post_init__(self):
        self._compiled = {lang: [re.compile(p, re.I) for p in pats]
                          for lang, pats in self.patterns.items()}
        self._req = re.compile(self.require, re.I) if self.require else None
        self._exc = re.compile(self.exclude, re.I) if self.exclude else None

    def match(self, lang: str, line: str) -> Optional["re.Match"]:
        if self._exc and self._exc.search(line):
            return None
        if self._req and not self._req.search(line):
            return None
        for rx in self._compiled.get(lang, ()):
            for m in rx.finditer(line):
                if self.veto and self.veto(m):
                    continue
                return m
        return None


# --------------------------------------------------------------------------
# A04 - Cryptographic Failures
# --------------------------------------------------------------------------

# Candidate = any identifier assigned a string literal; precision is decided in
# _hardcoded_veto by analysing the identifier's *components* (so a secret word
# must be a real name part, not a substring of 'driver'/'archive'/'cache_key').
_SECRET_NAME = r"[\"']?\$?[A-Za-z_][\w.$\-]{0,64}[\"']?"
_LITERAL = r"(['\"])(?P<val>[^'\"\n]{6,})\1"
_HARDCODED = [_SECRET_NAME + r"\s*(?:=>|:|(?<![=!<>])=(?!=))\s*" + _LITERAL]

# Identifier components that are unambiguously a secret on their own.
_SECRET_COMPONENTS = {
    "secret", "secrets", "password", "passwd", "pwd", "pass", "passphrase",
    "token", "credential", "credentials", "apikey", "privatekey", "secretkey",
    "accesskey", "clientsecret", "passphrase",
}
# "key" only counts as a secret when qualified by one of these (api_key, private
# key, session key ...), so cache_key / sort_key / foreign_key are not secrets.
_KEY_QUALIFIERS = {
    "api", "private", "secret", "access", "encryption", "encrypt", "signing",
    "sign", "master", "session", "client", "consumer", "refresh", "aes", "rsa",
    "hmac", "jwt", "crypto", "app",
}
_NOT_SECRET_SUFFIX = re.compile(
    r"(?:url|uri|field|name|header|type|param|label|path|file|endpoint|"
    r"prompt|placeholder|regex|pattern|expiry|ttl|length|size|id|"
    r"cookie|claim|prefix)[\"']?$", re.I)
# Framework cast/transform directives (e.g. Laravel $casts / casts()): a
# secret-named attribute mapped to one of these is a cast instruction, not a
# stored secret — ['password' => 'hashed'], ['token' => 'encrypted'].
_CAST_DIRECTIVES = {
    "hashed", "encrypted", "encrypted:array", "encrypted:collection",
    "encrypted:json", "encrypted:object",
}
# Directories whose string literals are not real secrets: test fixtures and
# i18n message catalogues (both routinely hold fake tokens / human text).
_SECRET_SKIP_DIR = re.compile(
    r"(?:^|/)(?:tests?|__tests__|specs?|fixtures?|mocks?|stubs?|"
    r"messages|lang|langs|locale|locales|i18n|translations?|translation)(?:/|$)",
    re.I)
_SECRET_SKIP_FILE = re.compile(
    r"(?:^|/)(?:test_|spec_)|[._-](?:test|spec|fixture|mock|stub)s?\.\w+$", re.I)
# Obvious placeholder values ("your_api_key", "changeme", "<secret>", ...). The
# leading-word prefixes stay narrow ("your...") so real secrets like
# "my-super-secret" are not swallowed.
_PLACEHOLDER_VAL = re.compile(
    r"^(?:your|put[_\- ]?your|insert[_\- ]?your)[_\- ]|"
    r"(?:change[_\- ]?me|replace[_\- ]?me|placeholder|dummy[_\- ]?value|"
    r"todo|tbd|xxx+|secret[_\- ]?here|<[^>]+>|\*{3,})", re.I)


def _secret_path_veto(rel: str) -> bool:
    """Skip the hardcoded-secret rule for test fixtures and i18n catalogues."""
    return bool(_SECRET_SKIP_DIR.search(rel) or _SECRET_SKIP_FILE.search(rel))


def _components(name: str) -> set:
    """Lowercase name parts, split on snake/kebab/dot and camelCase boundaries."""
    out = []
    for part in re.split(r"[_\-.$]", name):
        out += re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", part) or [part]
    return {c.lower() for c in out if c}


def _name_is_secret(name: str) -> bool:
    comps = _components(name)
    if comps & _SECRET_COMPONENTS:
        return True
    if "key" in comps and (comps & _KEY_QUALIFIERS):
        return True
    # concatenated spellings a split may not separate (e.g. "mypassword")
    joined = "".join(comps)
    return any(w in joined for w in
               ("password", "passphrase", "apikey", "privatekey", "secretkey",
                "accesskey", "clientsecret"))


def _hardcoded_veto(m: "re.Match") -> bool:
    text = m.group(0)
    if text.lower().startswith("define"):                     # PHP define('NAME', 'val')
        dm = re.search(r"['\"]([\w]+)['\"]", text)
        name = dm.group(1) if dm else ""
    else:
        name = re.split(r"\s*(?:=>|:|=)", text, 1)[0].strip(" \"'$")
    val = m.group("val")
    if _NOT_SECRET_SUFFIX.search(name) or not _name_is_secret(name):
        return True
    low = val.lower()
    if low in _CAST_DIRECTIVES:                     # Laravel cast, not a secret value
        return True
    if low.startswith(("http://", "https://", "/", "./", "<", "{{", "${", "%(", "env:")):
        return True
    if re.search(r"\s", val):        # whitespace -> message/label/prose, not a token
        return True                  # e.g. "Enter password", i18n "كلمة السر غير صحيحة"
    if _PLACEHOLDER_VAL.search(val):                # 'apiKey' => 'your_api_key'
        return True
    # Value just echoes the key: an enum/scenario label, not a stored secret.
    # 'password' => 'password'; const SCENARIO_PASSWORD_CHANGE = 'passwordChange'.
    if re.fullmatch(r"[\w\-]+", val):
        vcomp, ncomp = _components(val), _components(name)
        if vcomp and vcomp <= ncomp:
            return True
    return False


_WEAK_HASH_CTX_SAFE = r"usedforsecurity\s*=\s*False"

RULES: List[Rule] = [
    Rule(
        id="A04-weak-hash", vuln="weak_crypto",
        patterns={
            "py": [r"\bhashlib\s*\.\s*(?:md5|sha1)\s*\(",
                   r"\bhashlib\s*\.\s*new\s*\(\s*['\"](?:md5|sha-?1)['\"]",
                   r"\b(?:MD5|SHA1|SHA)\s*\.\s*new\s*\("],
            "js": [r"\bcreateHash\s*\(\s*['\"](?:md5|sha-?1)['\"]",
                   r"\bCryptoJS\s*\.\s*(?:MD5|SHA1)\s*\(",
                   r"(?<![\w$])(?:md5|sha1)\s*\("],
            "php": [r"(?<![\w>:$])(?:md5|sha1)(?:_file)?\s*\(",
                    r"\bhash\s*\(\s*['\"](?:md5|sha-?1)['\"]",
                    r"\bcrypt\s*\([^)]*['\"]\$1\$"],
        },
        exclude=_WEAK_HASH_CTX_SAFE,
        message="Weak hash algorithm (MD5/SHA-1) is collision-prone and unsuitable for "
                "passwords, signatures or integrity protection."),
    Rule(
        id="A04-broken-cipher", vuln="weak_crypto",
        patterns={
            "py": [r"\b(?:DES|DES3|ARC4|ARC2|Blowfish|XOR)\s*\.\s*new\s*\(",
                   r"\bMODE_ECB\b", r"\bmodes\s*\.\s*ECB\s*\(",
                   r"\balgorithms\s*\.\s*(?:TripleDES|ARC4|Blowfish|IDEA|CAST5)\s*\("],
            "js": [r"\bcreate(?:De)?[Cc]ipher(?:iv)?\s*\(\s*['\"](?:des[\w-]*|rc4[\w-]*|bf[\w-]*|aes-\d+-ecb)['\"]",
                   r"['\"]aes-\d+-ecb['\"]",
                   r"\bCryptoJS\s*\.\s*(?:DES|TripleDES|RC4|RC4Drop)\b",
                   r"\bmode\s*:\s*CryptoJS\s*\.\s*mode\s*\.\s*ECB\b"],
            "php": [r"\bMCRYPT_(?:DES|3DES|TRIPLEDES|RC4|ARCFOUR|BLOWFISH)\w*",
                    r"\bMCRYPT_MODE_ECB\b",
                    r"\bopenssl_(?:en|de)crypt\s*\([^;]*?['\"](?:des[\w-]*|rc4[\w-]*|bf[\w-]*|aes-\d+-ecb)['\"]"],
        },
        message="Broken cipher or insecure mode (DES/3DES/RC4/ECB): weak keys, small blocks "
                "or deterministic output leak plaintext structure."),
    Rule(
        id="A04-tls-verify-disabled", vuln="broken_tls",
        patterns={
            "py": [r"\bverify\s*=\s*False\b",
                   r"\bssl\s*\.\s*_create_unverified_context\b",
                   r"\b_create_default_https_context\s*=\s*ssl\s*\.\s*_create_unverified",
                   r"\bcheck_hostname\s*=\s*False\b",
                   r"\bverify_mode\s*=\s*ssl\s*\.\s*CERT_NONE\b"],
            "js": [r"\brejectUnauthorized\s*:\s*false\b",
                   r"\bNODE_TLS_REJECT_UNAUTHORIZED\b[\"'\]]*\s*=\s*['\"]?0",
                   r"\bstrictSSL\s*:\s*false\b",
                   r"\bcheckServerIdentity\s*:\s*\(\s*\)\s*=>\s*(?:undefined|null)"],
            "php": [r"\bCURLOPT_SSL_VERIFYPEER\b['\"]?\s*(?:,|=>)\s*(?:false|0)\b",
                    r"\bCURLOPT_SSL_VERIFYHOST\b['\"]?\s*(?:,|=>)\s*(?:false|0)\b",
                    r"['\"]verify(?:_peer|_peer_name)?['\"]\s*=>\s*false\b",
                    r"\bcurl_setopt\s*\([^;]*VERIFY(?:PEER|HOST)[^;]*,\s*(?:false|0)\s*\)"],
        },
        message="TLS certificate/hostname verification is disabled, allowing "
                "man-in-the-middle interception of 'secure' connections."),
    Rule(
        id="A04-hardcoded-secret", vuln="hardcoded_secret",
        patterns={
            "py": _HARDCODED, "js": _HARDCODED,
            "php": _HARDCODED + [r"\bdefine\s*\(\s*['\"][\w]+['\"]\s*,\s*" + _LITERAL],
        },
        # reading the secret from the environment/config is the safe form
        exclude=r"(?:environ|getenv|process\s*\.\s*env|\$_ENV|\$_SERVER|config\s*\(|"
                r"settings\s*\.|secrets\s*\.)",
        veto=_hardcoded_veto,
        file_veto=_secret_path_veto,
        message="A key, secret, password, token or IV is embedded as a string literal "
                "in source code."),
    Rule(
        id="A04-weak-random", vuln="weak_random",
        patterns={
            "py": [r"\brandom\s*\.\s*(?:random|randint|randrange|choice|choices|getrandbits|"
                   r"sample|shuffle|randbytes)\s*\("],
            "js": [r"\bMath\s*\.\s*random\s*\("],
            "php": [r"(?<![\w>:$])(?:rand|mt_rand|uniqid|lcg_value|mt_srand|srand|"
                    r"str_shuffle|shuffle)\s*\("],
        },
        # only security-relevant uses: the line must deal with a secret-ish value
        require=r"(?:secret|passw(?:or)?d|token|otp|nonce|salt|session|csrf|api_?key|"
                r"reset|verification|\biv\b)",
        exclude=r"(?:\bsecrets\s*\.|SystemRandom|random_bytes|random_int|"
                r"crypto\s*\.\s*(?:randomBytes|randomUUID|getRandomValues)|openssl_random)",
        message="Predictable pseudo-random generator used to produce a token, key or "
                "other secret value."),

    # ----------------------------------------------------------------------
    # A02 - Security Misconfiguration
    # ----------------------------------------------------------------------
    Rule(
        id="A02-debug-enabled", vuln="debug_enabled",
        patterns={
            "py": [r"\bDEBUG\s*=\s*True\b",
                   r"\bapp\s*\.\s*debug\s*=\s*True\b",
                   r"\.run\s*\([^)]*\bdebug\s*=\s*True",
                   r"\bFLASK_DEBUG\b\s*=\s*['\"]?1"],
            "php": [r"\bdefine\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true",
                    r"\bAPP_DEBUG\b['\"]?\s*(?:,|=>|=)\s*true"],
            # No generic JS rule: a bare `debug: true` object key is far too
            # common in benign build/logger/test config to flag on its own.
            "js": [],
        },
        message="Debug mode is enabled. Debuggers and stack traces expose source, "
                "configuration and secrets, and some allow remote code execution."),
    Rule(
        id="A02-permissive-cors", vuln="permissive_cors",
        patterns={
            "py": [r"['\"]Access-Control-Allow-Origin['\"]\s*[:,]\s*['\"]\*['\"]",
                   r"\bCORS\s*\(\s*app\s*\)",
                   r"\borigins\s*=\s*\[\s*['\"]\*['\"]"],
            "js": [r"\bcors\s*\(\s*\)",
                   r"\borigin\s*:\s*['\"]\*['\"]",
                   r"\borigin\s*:\s*true\b",
                   r"['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]"],
            "php": [r"header\s*\(\s*['\"]Access-Control-Allow-Origin:\s*\*"],
        },
        message="Cross-Origin Resource Sharing allows any origin ('*' / reflected), "
                "letting any website read authenticated responses from this service."),
    Rule(
        id="A02-insecure-cookie", vuln="insecure_cookie",
        patterns={
            "py": [r"\bhttponly\s*=\s*False\b", r"\bsecure\s*=\s*False\b",
                   r"\bSESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False\b",
                   r"\bCSRF_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False\b"],
            "js": [r"\bhttpOnly\s*:\s*false\b", r"\bsecure\s*:\s*false\b"],
            "php": [r"['\"]http_?only['\"]\s*=>\s*false", r"['\"]secure['\"]\s*=>\s*false",
                    r"\bsession\.cookie_(?:httponly|secure)\b['\"]?\s*,\s*(?:0|false)"],
        },
        # Context filter: the line must actually be about a cookie/session, so an
        # unrelated `secure=False` / `httponly=False` kwarg (e.g. a DB driver
        # connect) is not misreported as an insecure cookie.
        require=r"(?i)cookie|session|csrf",
        message="A session/security cookie is set without the Secure and/or HttpOnly "
                "flag, exposing it to theft over plain HTTP or via JavaScript (XSS)."),
    Rule(
        id="A02-misconfig", vuln="security_misconfig",
        patterns={
            "py": [r"\bALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]"],
            "php": [r"\bini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(?:1|on|true)",
                    r"\bexpose_php\b['\"]?\s*,\s*['\"]?(?:1|on|true)",
                    r"\bdisplay_errors\b['\"]?\s*,\s*['\"]?(?:1|on|true)"],
            "js": [],
        },
        message="Insecure configuration (wildcard ALLOWED_HOSTS, verbose error "
                "display, or server fingerprint exposure) that eases attacks."),

    # ----------------------------------------------------------------------
    # A08 - Software and Data Integrity Failures
    # ----------------------------------------------------------------------
    Rule(
        id="A08-insecure-deserialization", vuln="insecure_deserialization",
        patterns={
            "py": [r"\b_?c?pickle\s*\.\s*loads?\s*\(",
                   r"\bmarshal\s*\.\s*loads?\s*\(",
                   r"\b(?:dill|jsonpickle)\s*\.\s*(?:loads?|decode)\s*\("],
            "php": [r"(?<![\w>:$])unserialize\s*\("],
            # node-serialize / funcster rebuild functions from the payload. Require
            # a serialize-named receiver (serialize.unserialize / serializer.unserialize)
            # so an unrelated in-house `foo.unserialize()` is not flagged.
            "js": [r"\b[\w$]*serial[\w$]*\s*\.\s*unserialize\s*\(",
                   r"\bfuncster\s*\.\s*deepDeserialize\s*\("],
        },
        # PHP 7+ unserialize($d, ['allowed_classes' => false]) blocks object
        # instantiation — that is the hardened form, not a finding.
        exclude=r"allowed_classes['\"]?\s*(?:=>|:)\s*(?:false|\[)",
        message="Untrusted data is deserialized with a code-bearing format "
                "(pickle/marshal/unserialize/node-serialize); a crafted payload can "
                "instantiate arbitrary objects and execute code while decoding."),
    Rule(
        id="A08-unsafe-yaml-load", vuln="insecure_deserialization",
        patterns={
            "py": [r"\byaml\s*\.\s*(?:unsafe_load|load_all|load)\s*\("],
            "php": [r"(?<![\w>:$])yaml_parse\s*\("],
            "js": [],
        },
        # yaml.load(x, Loader=SafeLoader/BaseLoader) and yaml.safe_load[_all] are
        # the safe forms (FullLoader is deliberately NOT excluded — it has had
        # object-construction holes). The (?<!un) guard keeps 'unsafe_load' — which
        # contains the substring 'safe_load' — from excluding itself.
        exclude=r"SafeLoader|BaseLoader|(?<!un)safe_load",
        message="YAML is parsed with a full (unsafe) loader; the document can construct "
                "arbitrary objects. Use yaml.safe_load / Loader=SafeLoader."),

    # ----------------------------------------------------------------------
    # A10 - Mishandling Exceptions
    # ----------------------------------------------------------------------
    Rule(
        id="A10-error-info-leak", vuln="error_info_leak",
        patterns={
            # returning / rendering the exception (str(e), .args, traceback) to the client.
            # return/except patterns are anchored to line start so the same words inside
            # a docstring or string literal are not misread as code.
            "py": [r"^\s*return\s+[^#]*\bstr\s*\(\s*(?:e|ex|exc|err|error|exception)\s*\)",
                   r"^\s*return\s+[^#]*traceback\s*\.\s*format_exc\s*\(",
                   r"\b(?:jsonify|JsonResponse|HttpResponse\w*|Response|make_response|abort)\s*\("
                   r"[^#]*(?:str\s*\(\s*(?:e|ex|exc|err|error|exception)\s*\)|"
                   r"traceback\s*\.\s*format_exc\s*\(|"
                   # an exception's .args — NOT Flask's request.args / form.args
                   r"\b(?:e|ex|exc|err|error|exception)\s*\.\s*args\b)"],
            # echoing / printing the exception message or trace to output. The
            # receiver is constrained to an exception-named var so a benign
            # $user->getMessage() (chat/notification) is not flagged.
            "php": [r"\b(?:echo|print|printf|vprintf|die|exit)\b[^;]*"
                    r"\$(?:exception|error|throwable|err|exc|ex|e)\b\s*->\s*getMessage\s*\(",
                    r"\b(?:echo|print|printf|die|exit)\b[^;]*"
                    r"\$(?:exception|error|throwable|err|exc|ex|e)\b\s*->\s*getTraceAsString\s*\(",
                    r"\b(?:print_r|var_dump|var_export)\s*\(\s*\$\w*(?:exception|error|err)\w*\b"],
            # writing the error object / its stack or message into the HTTP response
            "js": [r"\.\s*(?:send|json|write|end)\s*\([^;]*\b(?:err|error|exception|ex)\s*\.\s*(?:stack|message)\b",
                   r"\.\s*(?:send|json)\s*\(\s*(?:err|error|exception)\s*\)"],
        },
        # logging the exception server-side is the safe form, never a leak.
        exclude=r"console\s*\.\s*(?:log|error|warn|debug|info)|\blogger\b|\blogging\b|"
                r"error_log\s*\(|\bsyslog\b|->\s*log\s*\(|\bLog\s*::",
        message="An exception message, stack trace or traceback is sent to the client "
                "instead of being logged server-side, leaking internal details."),
    Rule(
        id="A10-swallowed-exception", vuln="swallowed_exception",
        patterns={
            # bare / overly broad catch, or a one-line handler that only passes.
            # Anchored to line start: real handlers are statements, so "except:"
            # mentioned in prose/strings is not flagged.
            "py": [r"^\s*except\s*:",
                   r"^\s*except\s+BaseException\b",
                   r"^\s*except\b[^:#]*:\s*pass\b"],
            # an empty catch body { } swallows the error
            "php": [r"\bcatch\s*\([^)]*\)\s*\{\s*\}"],
            "js": [r"\bcatch\s*(?:\(\s*[\w$]*\s*\))?\s*\{\s*\}",
                   r"\.\s*catch\s*\(\s*(?:\(\s*\)|[\w$]+)\s*=>\s*\{\s*\}\s*\)"],
        },
        message="An exception is caught and silently discarded (empty catch / except: pass) "
                "or a bare/overly broad handler hides the failure."),
]


def register(*rules: Rule) -> None:
    """Add rules to the shared engine (used by later OWASP items)."""
    RULES.extend(rules)


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

_COMMENT = re.compile(r"^\s*(?:#|//|\*|/\*|<!--)")


def scan_text(rel: str, source: str, framework: str = "",
              rules: Optional[List[Rule]] = None) -> List[Finding]:
    """Apply the rules to one file's text and return findings."""
    lang = _lang(rel)
    out: List[Finding] = []
    # Drop rules that veto this whole file (e.g. hardcoded-secret in test fixtures
    # or i18n catalogues) once up front, rather than per line.
    active = [r for r in (rules or RULES) if not (r.file_veto and r.file_veto(rel))]
    for ln, line in enumerate(source.splitlines(), 1):
        if len(line) > 600 or _COMMENT.match(line):
            continue                                   # minified / comment line
        for rule in active:
            m = rule.match(lang, line)
            if not m:
                continue
            matched = m.group(0).strip()
            code = line.strip()
            # Never store or surface the actual credential: for a hardcoded-secret
            # finding, redact the matched literal value everywhere it would appear
            # (code line, sink, and the "how it got in" narrative). The detection
            # already ran on the real value in rule.match above. Invariant: every
            # hardcoded_secret pattern must expose the value as a (?P<val>...) group
            # (see _LITERAL) so there is something to redact here.
            if rule.vuln == "hardcoded_secret":
                val = m.groupdict().get("val")
                if val:
                    matched = matched.replace(val, "***")
                    code = code.replace(val, "***")
            out.append(Finding(
                vuln=rule.vuln, file=rel, line=ln, sink=matched[:80],
                source=f"pattern rule {rule.id}", framework=framework,
                code=code[:200], message=rule.message, column=m.start() + 1,
                method="", rule=rule.id,
                how=f"Rule {rule.id} matched `{matched[:80]}` at "
                    f"{rel}:{ln}. {rule.message}"))
    return out


def scan_rules(root: str, on_step: Optional[Callable[[Step], None]] = None,
               files: Optional[List[str]] = None,
               frameworks: Optional[Dict[str, str]] = None) -> List[Finding]:
    """Walk *root* and return pattern-rule findings for every matching file."""
    root = os.path.abspath(root)
    base = root if os.path.isdir(root) else os.path.dirname(root)
    files = files if files is not None else iter_source_files(root)
    if frameworks is None:
        frameworks = detect_frameworks(root, files)
    findings: List[Finding] = []
    for path in files:
        rel = os.path.relpath(path, base).replace("\\", "/")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError:
            continue
        for f in scan_text(rel, source, framework_for(path, frameworks)):
            findings.append(f)
            if on_step:
                on_step(Step(
                    kind="finding",
                    text=f"   [{f.severity.upper()}] {f.title} ({f.cwe}) "
                         f"{f.location()} - {f.rule} -> {f.sink}",
                    data={"finding": f.to_dict()}))
    return findings
