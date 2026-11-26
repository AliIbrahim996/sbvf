"""Static taint analysis for PHP source (native, Yii, Laravel).

PHP has no parser in the Python standard library, so this module implements a
pragmatic, quote-aware lexer: it strips comments (preserving line numbers),
splits the source into statements while respecting string literals and heredocs,
and tracks tainted variables across assignments. A statement that pushes an
unsanitized tainted value into a dangerous sink (SQL query, echo, shell command,
include, eval) produces a :class:`Finding` at the statement's line.

Taint propagation is flow-insensitive (pass 1 over-approximates every variable
that is ever tainted), but the sink pass is flow-sensitive for *killing* taint:
a variable reassigned an unconditional clean value loses its taint for the
statements that follow (improvement 4.4). The analysis remains intra-file; these
limitations are noted in the thesis.
"""
from __future__ import annotations

import re
from typing import Callable, List, Optional, Tuple

from .model import INJECTION_CLASSES, Finding


# --- Sources (user input), scoped per framework -----------------------------

# Native PHP superglobals and raw input, always considered sources.
NATIVE_SOURCES = [
    (re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b"), "$_%s"),
    (re.compile(r"\$_SERVER\[\s*['\"](HTTP_[A-Z_]+|QUERY_STRING|REQUEST_URI|PHP_SELF|PATH_INFO)"),
     "$_SERVER"),
    (re.compile(r"php://input"), "php://input"),
]
# Yii 2 request helpers.
YII_SOURCES = [
    (re.compile(r"Yii::\$app->request->(get|post|getQueryParam|getBodyParam)"), "Yii request"),
    (re.compile(r"\$this->request->(get|post|getQueryParam|getBodyParam)"), "Yii request"),
    (re.compile(r"->getQueryParam\b|->getBodyParam\b"), "Yii request param"),
]
# Laravel request helpers.
LARAVEL_SOURCES = [
    (re.compile(r"\$request->(input|get|query|all|post|json|only|except|string|integer|boolean)\b"),
     "Laravel request"),
    (re.compile(r"request\(\)->(input|get|query|all|post|json)\b"), "Laravel request()"),
    (re.compile(r"Input::(get|all|only|post)\b"), "Laravel Input"),
    (re.compile(r"\$request\[\s*['\"]"), "Laravel request array"),
]

# Sanitizers, tied to the vulnerability class(es) each one actually neutralises
# (improvement 4.1). A sanitizer wrapping the tainted token makes the value safe
# *only* for its classes: htmlspecialchars stops XSS but not SQL injection, so
# ``mysqli_query("... " . htmlspecialchars($_GET['x']))`` is still reported.
# Function-style sanitizers wrap their argument in parentheses; the capture group
# names the function so its class set can be looked up.
SANITIZER_FUNCS = re.compile(
    r"\b(htmlspecialchars|htmlentities|intval|floatval|mysqli_real_escape_string|"
    r"real_escape_string|escapeshellarg|escapeshellcmd|basename|filter_var|"
    r"Html::encode|urlencode|ctype_digit|preg_quote|e)\s*\(")
# ... while a cast neutralises the value without parentheses: (int) $x
CAST_SAN = re.compile(r"\((?:int|integer|float|double|bool|boolean)\)")

# Which vulnerability classes each sanitizer neutralises. A value that is cast to
# a number or percent-encoded is safe across every injection sink (the full
# INJECTION_CLASSES set); an output/context encoder is safe only for its context.
# Access-control classes (IDOR) are never in a sanitizer set — see model.py.
SANITIZER_CLASSES = {
    "htmlspecialchars": frozenset({"xss"}),
    "htmlentities": frozenset({"xss"}),
    "html::encode": frozenset({"xss"}),
    "e": frozenset({"xss"}),                       # Blade/Laravel e() escaper
    "mysqli_real_escape_string": frozenset({"sqli"}),
    "real_escape_string": frozenset({"sqli"}),
    "escapeshellarg": frozenset({"command_injection"}),
    "escapeshellcmd": frozenset({"command_injection"}),
    "basename": frozenset({"file_inclusion", "path_traversal"}),
    "urlencode": INJECTION_CLASSES,                # percent-encoding: no raw metachars
    "intval": INJECTION_CLASSES,
    "floatval": INJECTION_CLASSES,
    "ctype_digit": INJECTION_CLASSES,              # numeric validation
    "filter_var": INJECTION_CLASSES,               # validating filter / FILTER_SANITIZE_*
    "preg_quote": frozenset(),                     # regex escaping: not a web-sink sanitizer
}
# A numeric/boolean cast neutralises every injection class.
_CAST_CLASSES = INJECTION_CLASSES

# --- Sinks ------------------------------------------------------------------
# Each entry: (vuln, compiled-regex that matches the sink keyword/call head).
SQLI_SINKS = re.compile(
    r"\b(mysqli_query|mysql_query|pg_query)\s*\(|->(query|exec|prepare)\s*\(|"
    r"->createCommand\s*\(|DB::(select|statement|insert|update|raw)\s*\(|"
    r"->(whereRaw|selectRaw|orderByRaw|havingRaw)\s*\("
)
CMD_SINKS = re.compile(
    r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(")
INCLUDE_SINKS = re.compile(r"\b(include|require)(_once)?\b")
CODE_SINKS = re.compile(r"\b(eval|assert|create_function)\s*\(")
ECHO_SINKS = re.compile(r"\b(echo|print|printf|print_r|vprintf)\b")
# IDOR (OWASP A01): an Eloquent fetch-by-id on tainted input. Static Model::find
# is Eloquent; of the arrow forms only the Eloquent-specific names are used, so a
# Laravel Collection's in-memory ->find() is not mistaken for a DB object fetch.
IDOR_SINKS = re.compile(r"::\s*(findOrFail|find)\s*\(|->\s*(findOrFail|firstWhere)\s*\(")
# A real ownership/authorization signal that suppresses IDOR, scoped to the
# enclosing function (see _guard_ranges) rather than the whole file.
_PHP_IDOR_GUARD = re.compile(
    r"auth\(\)\s*->|Auth::|\$request->user\(|->where\(\s*['\"](?:user_id|owner_id|owner|user)['\"]|"
    r"\bpolicy\b|->authorize\(|Gate::|->can\(|->middleware\(|->user_id\b")

# A concrete superglobal access, used to recover the request parameter + method
# (e.g. $_GET['id'] -> param "id", method "GET") so the dynamic search can target it.
SUPERGLOBAL_KEY = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([A-Za-z0-9_\-]+)['\"]")
# Laravel request accessors naming a parameter, so framework findings also carry a
# recoverable (param, method) and become dynamically confirmable (improvement 4.5):
#   $request->input('name') / ->query('q') / ->post('x') / request('y') / $request['z']
LARAVEL_METHOD_KEY = re.compile(
    r"(?:\$request|\$this->request|request\(\))\s*->\s*"
    r"(input|get|query|post|json|string|integer|boolean)\s*\(\s*['\"]([\w\-]+)['\"]")
LARAVEL_FACADE_KEY = re.compile(
    r"Input::\s*(get|input|post|query)\s*\(\s*['\"]([\w\-]+)['\"]")
LARAVEL_ARRAY_KEY = re.compile(r"\$request\s*\[\s*['\"]([\w\-]+)['\"]")


class PhpAnalyzer:
    def __init__(self, framework: str = "php-native"):
        self.framework = framework
        self.sources = list(NATIVE_SOURCES)
        if framework == "yii":
            self.sources += YII_SOURCES
        elif framework == "laravel":
            self.sources += LARAVEL_SOURCES
        else:  # native: still allow Yii/Laravel helpers to be recognised if present
            self.sources += YII_SOURCES + LARAVEL_SOURCES

    # --- public -------------------------------------------------------------

    def analyze(self, rel_path: str, source: str,
                on_source: Optional[Callable] = None,
                seed_params: Optional[List[str]] = None) -> List[Finding]:
        self._rel = rel_path
        self._lines = source.splitlines()
        self._on_source = on_source
        tainted = {}            # "$var" -> source description
        self._sanitized = {}    # "$var" -> frozenset of classes it is already safe for
        self._origin = {}       # "$var" -> (param, method) of its originating input
        findings: List[Finding] = []
        if not hasattr(self, "_summaries"):
            self._summaries = {}

        statements = list(self._statements(source))

        if seed_params is None:
            # Top-level file analysis: learn inter-procedural summaries first
            # (improvement 4.2) so call sites below can use them.
            self._summaries = {}
            self._build_summaries(source)
        else:
            # Summary sub-analysis: treat every parameter as a symbolic source so
            # we can see which ones reach a sink / flow to the return value.
            for p in seed_params:
                tainted[p] = f"parameter '{p}'"
                self._sanitized[p] = frozenset()
                self._origin[p] = (p, "PARAM")

        # Pass 1: propagate taint through assignments (fixpoint over statements).
        # Flow-insensitive over-approximation: it records every variable that is
        # ever tainted, independent of statement order, which pass 2 then refines.
        changed, guard = True, 0
        while changed and guard < 20:
            changed, guard = False, guard + 1
            for line, _depth, stmt in statements:
                # Match a real assignment ($var = ... or $var .= ...), but NOT a
                # comparison: the (?!=) lookahead rejects == / === / etc. so a
                # statement like `$x == $_GET['y'];` is not mistaken for `$x = ...`.
                m = re.match(r"\s*(\$\w+)\s*\.?=(?!=)\s*(.+)", stmt)
                if not m:
                    continue
                var, rhs = m.group(1), m.group(2)
                src, san = self._taint_rhs(rhs, tainted)
                if src and var not in tainted:
                    tainted[var] = src
                    self._sanitized[var] = san
                    self._remember_origin(var, rhs)
                    changed = True
                    if on_source:
                        on_source(src, line)

        # Ownership/authorization signal scoped per function (so one guarded
        # method does not suppress IDOR in a sibling method of the same file).
        self._guard_ranges = self._compute_guard_ranges(source)
        self._file_guarded = bool(_PHP_IDOR_GUARD.search(source))
        # Enclosing function/method name per line, so a finding can be tied to the
        # controller method that holds it (needed for Laravel route recovery, 4.5).
        self._func_ranges = self._compute_func_ranges(source)

        # Pass 2: flow-sensitive sink check (improvement 4.4). Walk the statements
        # in order with a *live* taint set seeded from pass 1; when a variable is
        # reassigned a clean value it is killed for the statements that follow, so
        # ``$x = $_GET['id']; $x = 5; mysqli_query($x);`` is no longer reported.
        # A block ({ ... }) is entered with a copy and its taint is unioned back on
        # exit, so a kill buried in a conditional/loop body does not leak out (no
        # false negatives) while an unconditional reassignment does.
        self._flow_check(statements, tainted, findings)

        # For a summary sub-analysis, record whether the function returns a value
        # tainted by a real input source (not merely one of its parameters).
        if seed_params is not None:
            self._returns_source = self._compute_returns_source(statements, tainted)

        # Blade raw-echo ({!! $x !!}) for Laravel template files.
        if rel_path.endswith(".blade.php"):
            self._check_blade(source, tainted, findings)

        return findings

    # --- inter-procedural summaries (improvement 4.2) -----------------------

    def _extract_functions(self, source: str):
        """{name: (params, body_text)} for each user-defined PHP function."""
        funcs = {}
        for m in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)[^{;]*\{", source):
            params = [pm.group(1) for pm in re.finditer(r"(\$\w+)", m.group(2))]
            depth, i, n = 1, m.end(), len(source)      # m.end() is just past '{'
            while i < n and depth:
                c = source[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                i += 1
            body = source[m.end():i - 1] if depth == 0 else source[m.end():i]
            funcs[m.group(1)] = (params, body)
        return funcs

    def _build_summaries(self, source: str):
        """Fixpoint over every function: record returns_source (hands back user
        input) and sink_params (a parameter reaches a sink). Iterated so one
        helper calling another converges."""
        funcs = self._extract_functions(source)
        for name, (params, _body) in funcs.items():
            self._summaries[name] = {"params": params, "returns_source": False,
                                     "sink_params": set()}
        for _ in range(8):
            changed = False
            for name, (params, body) in funcs.items():
                rs, sp = self._summarize_func(params, body)
                cur = self._summaries[name]
                if rs != cur["returns_source"] or sp != cur["sink_params"]:
                    cur["returns_source"], cur["sink_params"] = rs, sp
                    changed = True
            if not changed:
                break

    def _summarize_func(self, params, body):
        """Analyze a function body with its parameters seeded as taint, using the
        shared summaries for any helper it calls."""
        sub = PhpAnalyzer(self.framework)
        sub._summaries = self._summaries               # share for transitive calls
        found = sub.analyze("<summary>", "<?php\n" + body, seed_params=params)
        pset = set(params)
        sink_params = {(f.param, f.vuln) for f in found
                       if f.method == "PARAM" and f.param in pset}
        return getattr(sub, "_returns_source", False), sink_params

    def _compute_returns_source(self, statements, tainted) -> bool:
        for _line, _depth, stmt in statements:
            rm = re.match(r"return\b\s*(.+)", stmt)
            if not rm:
                continue
            expr = rm.group(1)
            if self._taint_in(expr, tainted, None) and self._endpoint_for(expr)[1] != "PARAM":
                return True
        return False

    def _call_returns_source(self, text: str) -> Optional[str]:
        """Source description if *text* calls a local helper that returns user
        input (improvement 4.2)."""
        for m in re.finditer(r"(?<![\w>$:])(\w+)\s*\(", text):
            s = getattr(self, "_summaries", {}).get(m.group(1))
            if s and s["returns_source"]:
                return f"user input (returned by {m.group(1)}())"
        return None

    @staticmethod
    def _split_args(s: str):
        """Split a call's argument list on top-level commas (quote/paren aware)."""
        args, depth, buf, quote = [], 0, [], None
        for ch in s:
            if quote:
                buf.append(ch)
                if ch == quote:
                    quote = None
                continue
            if ch in "'\"":
                quote = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == "," and depth == 0:
                args.append("".join(buf).strip())
                buf = []
                continue
            buf.append(ch)
        if "".join(buf).strip():
            args.append("".join(buf).strip())
        return args

    def _check_helper_sinks(self, line, stmt, live, findings):
        """4.2: a call to a local helper that funnels a parameter into a sink."""
        if stmt.lstrip().startswith("function"):
            return
        for m in re.finditer(r"(?<![\w>$:])(\w+)\s*\(", stmt):
            s = getattr(self, "_summaries", {}).get(m.group(1))
            if not s or not s["sink_params"]:
                continue
            open_idx = stmt.find("(", m.start())
            if open_idx == -1:
                continue
            args = self._split_args(self._arg_region(stmt, open_idx)[1:-1])
            for pname, vuln in s["sink_params"]:
                try:
                    idx = s["params"].index(pname)
                except ValueError:
                    continue
                if idx < len(args):
                    src = self._taint_in(args[idx], live, vuln)
                    if src:
                        self._emit(findings, vuln, line,
                                   f"{m.group(1)}() -> {vuln} sink", src, args[idx])
                        return

    def _flow_check(self, statements, tainted, findings):
        """Ordered, block-scoped sink pass that kills taint on clean reassignment."""
        live = dict(tainted)
        live_san = dict(self._sanitized)
        saved_san = self._sanitized
        self._sanitized = live_san          # _taint_in / _taint_rhs read live now
        stack = []                          # snapshots of (live, live_san) per open brace
        cur_depth = 0
        try:
            for line, depth, stmt in statements:
                while depth > cur_depth:    # entering a block: snapshot, keep working copy
                    stack.append((dict(live), dict(live_san)))
                    cur_depth += 1
                while depth < cur_depth and stack:   # leaving: union gens back, drop kills
                    parent, parent_san = stack.pop()
                    parent.update(live)
                    parent_san.update(live_san)
                    live, live_san = parent, parent_san
                    self._sanitized = live_san
                    cur_depth -= 1
                # sinks see the live state BEFORE this statement's own reassignment
                self._check_stmt(line, stmt, live, findings)
                self._apply_assign_live(stmt, live, live_san)
            while stack:                    # close any unbalanced blocks
                parent, parent_san = stack.pop()
                parent.update(live)
                parent_san.update(live_san)
                live, live_san = parent, parent_san
        finally:
            self._sanitized = saved_san

    def _apply_assign_live(self, stmt, live, live_san):
        """Update the live taint set for an assignment statement: (re)taint the
        target from a tainted RHS, or kill it on a clean plain assignment."""
        m = re.match(r"\s*(\$\w+)\s*(\.)?=(?!=)\s*(.+)", stmt)
        if not m:
            return
        var, concat, rhs = m.group(1), m.group(2), m.group(3)
        src, san = self._taint_rhs(rhs, live)
        if src:
            live[var] = src
            live_san[var] = san
        elif not concat:            # $x = <clean>  -> taint-kill; $x .= <clean> appends, keep
            live.pop(var, None)
            live_san.pop(var, None)

    # --- IDOR guard scoping -------------------------------------------------

    def _compute_guard_ranges(self, source: str):
        """[(start_line, end_line, guarded_bool)] for each PHP function body, so an
        ownership/authz check in one method does not suppress IDOR in another."""
        ranges = []
        for m in re.finditer(r"function\s+\w+\s*\([^)]*\)[^{;]*\{", source):
            depth, i, n = 0, m.end() - 1, len(source)
            while i < n:
                c = source[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            body = source[m.start():i + 1]
            start = source.count("\n", 0, m.start()) + 1
            end = source.count("\n", 0, min(i, n - 1)) + 1
            ranges.append((start, end, bool(_PHP_IDOR_GUARD.search(body))))
        return ranges

    def _compute_func_ranges(self, source: str):
        """[(name, start_line, end_line)] for each PHP function/method body."""
        ranges = []
        for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)[^{;]*\{", source):
            depth, i, n = 0, m.end() - 1, len(source)
            while i < n:
                c = source[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            start = source.count("\n", 0, m.start()) + 1
            end = source.count("\n", 0, min(i, n - 1)) + 1
            ranges.append((m.group(1), start, end))
        return ranges

    def _line_function(self, line: int) -> str:
        """Name of the innermost function/method enclosing *line* ("" at top level)."""
        best = None
        for name, start, end in getattr(self, "_func_ranges", []):
            if start <= line <= end and (best is None or start > best[1]):
                best = (name, start)
        return best[0] if best else ""

    def _line_guarded(self, line: int) -> bool:
        """Whether *line* sits in a guarded function; top-level code falls back to
        a file-wide signal."""
        inner = None
        for start, end, guarded in getattr(self, "_guard_ranges", []):
            if start <= line <= end and (inner is None or start > inner[0]):
                inner = (start, guarded)
        if inner is not None:
            return inner[1]
        return getattr(self, "_file_guarded", False)

    # --- request-parameter recovery (for the SAST-guided dynamic search) ----

    def _remember_origin(self, var: str, rhs: str) -> None:
        """Record which request parameter/method a tainted var ultimately came from."""
        if var in self._origin:
            return
        ep = self._superglobal_in(rhs)
        if ep:
            self._origin[var] = ep
            return
        for v2, ep2 in self._origin.items():      # inherit through $a = $b . '...'
            if re.search(re.escape(v2) + r"\b", rhs):
                self._origin[var] = ep2
                return

    def _superglobal_in(self, text: str):
        """(param, method) for the first concrete request access in *text*, else None.

        Recognises native superglobals ($_GET['id']) and Laravel request accessors
        ($request->input('name'), request('q'), Input::get('x'), $request['z'])."""
        m = SUPERGLOBAL_KEY.search(text)
        if m:
            return (m.group(2), m.group(1))
        m = LARAVEL_METHOD_KEY.search(text)
        if m:
            return (m.group(2), "POST" if m.group(1) == "post" else "GET")
        m = LARAVEL_FACADE_KEY.search(text)
        if m:
            return (m.group(2), "POST" if m.group(1) == "post" else "GET")
        m = LARAVEL_ARRAY_KEY.search(text)
        if m:
            return (m.group(1), "REQUEST")
        return None

    def _endpoint_for(self, region: str):
        """Best-effort (param, method) for a tainted sink region: a direct
        superglobal access, or the recorded origin of a tainted variable."""
        ep = self._superglobal_in(region)
        if ep:
            return ep
        for var, ep2 in self._origin.items():
            if re.search(re.escape(var) + r"\b", region):
                return ep2
        return ("", "GET")

    # --- taint helpers ------------------------------------------------------

    def _source_desc(self, text: str) -> Optional[str]:
        for rx, label in self.sources:
            m = rx.search(text)
            if m:
                if "%s" in label and m.groups():
                    try:
                        return label % m.group(1)
                    except Exception:
                        return label.replace("%s", "")
                return label
        return None

    def _taint_in(self, text: str, tainted: dict, vuln: Optional[str] = None) -> Optional[str]:
        """Return a source description if *text* carries taint that is NOT
        sanitized for vulnerability class *vuln* (improvement 4.1).

        When *vuln* is None any sanitizer suppresses the taint (the pre-4.1
        behaviour, used by the access-control sinks that content sanitizers do
        not address, e.g. IDOR)."""
        # A direct source reference.
        src = self._source_desc(text)
        if src:
            tok = self._source_token(text)
            if not self._token_safe(text, tok, frozenset(), vuln):
                return src
        # A previously-tainted variable used in concatenation / interpolation.
        for var, desc in tainted.items():
            if re.search(re.escape(var) + r"\b", text):
                base = self._sanitized.get(var, frozenset())
                if not self._token_safe(text, var, base, vuln):
                    return desc
        # A call to a local helper that returns user input (improvement 4.2).
        return self._call_returns_source(text)

    def _taint_rhs(self, rhs: str, tainted: dict) -> Tuple[Optional[str], frozenset]:
        """For an assignment RHS, return (source description, classes it is safe
        for). A value neutralised for *every* injection class is treated as
        clean (returns (None, ...)), so it never taints the target."""
        src = self._source_desc(rhs)
        if src:
            san = self._wrap_classes(rhs, self._source_token(rhs))
            if INJECTION_CLASSES <= san:
                return None, frozenset()
            return src, san
        for var, desc in tainted.items():
            if re.search(re.escape(var) + r"\b", rhs):
                san = self._sanitized.get(var, frozenset()) | self._wrap_classes(rhs, var)
                if INJECTION_CLASSES <= san:
                    continue
                return desc, san
        cs = self._call_returns_source(rhs)            # 4.2: source-returning helper
        if cs:
            return cs, frozenset()
        return None, frozenset()

    def _source_token(self, text: str) -> str:
        """The literal text of the first direct input source in *text* (used as
        the token a wrapping sanitizer must cover)."""
        for rx, _ in self.sources:
            m = rx.search(text)
            if m:
                return m.group(0)
        return ""

    def _wrap_classes(self, text: str, token: str) -> frozenset:
        """The set of vulnerability classes neutralised for *token* by a cast or
        wrapping sanitizer call in *text*. The cast/sanitizer must apply to this
        token, not merely appear in the statement: ``(int)$id . $_GET['x']``
        sanitizes ``$id`` but leaves ``$_GET['x']`` tainted."""
        if not token:
            return frozenset()
        classes: set = set()
        # A numeric/boolean cast directly applied to the token, e.g. (int) $x.
        for cm in CAST_SAN.finditer(text):
            if re.match(r"\s*" + re.escape(token) + r"\b", text[cm.end():]):
                classes |= _CAST_CLASSES
        # A function-style sanitizer whose balanced-paren region covers the token.
        for sm in SANITIZER_FUNCS.finditer(text):
            open_idx = text.find("(", sm.start())
            if open_idx == -1:
                continue
            region = self._arg_region(text, open_idx)
            if token in region or self._source_desc(region):
                classes |= SANITIZER_CLASSES.get(sm.group(1).lower(), frozenset())
        return frozenset(classes)

    def _token_safe(self, text: str, token: str, base: frozenset,
                    vuln: Optional[str]) -> bool:
        """True if *token* is sanitized (for class *vuln*, or by any sanitizer
        when *vuln* is None) given classes *base* it already carries."""
        san = base | self._wrap_classes(text, token)
        if vuln is None:
            return bool(san)
        return vuln in san

    # --- sink checks --------------------------------------------------------

    def _arg_region(self, stmt: str, open_idx: int) -> str:
        """Return the text inside the balanced parentheses starting at *open_idx*."""
        depth, out = 0, []
        for ch in stmt[open_idx:]:
            out.append(ch)
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
        return "".join(out)

    def _check_stmt(self, line, stmt, tainted, findings):
        # SQL injection
        m = SQLI_SINKS.search(stmt)
        if m:
            region = self._region_after(stmt, m)
            src = self._taint_in(region, tainted, "sqli")
            if src and self._is_dynamic(region):
                return self._emit(findings, "sqli", line, m.group(0).strip("("),
                                  src, region)

        # Command injection
        m = CMD_SINKS.search(stmt)
        if m:
            region = self._region_after(stmt, m)
            src = self._taint_in(region, tainted, "command_injection")
            if src:
                return self._emit(findings, "command_injection", line,
                                  m.group(1), src, region)

        # Code injection
        m = CODE_SINKS.search(stmt)
        if m:
            region = self._region_after(stmt, m)
            src = self._taint_in(region, tainted, "code_injection")
            if src:
                return self._emit(findings, "code_injection", line, m.group(1),
                                  src, region)

        # File inclusion
        m = INCLUDE_SINKS.search(stmt)
        if m:
            region = stmt[m.end():]
            src = self._taint_in(region, tainted, "file_inclusion")
            if src and self._is_dynamic(region):
                return self._emit(findings, "file_inclusion", line,
                                  m.group(0).strip(), src, region)

        # IDOR: Eloquent fetch-by-id on tainted input, no ownership check in the
        # enclosing function (falls back to file scope for top-level code). A
        # content sanitizer (even an int cast) does not make an id non-IDOR, so
        # this sink keeps the pre-4.1 "any sanitizer suppresses" semantics.
        if not self._line_guarded(line):
            m = IDOR_SINKS.search(stmt)
            if m:
                region = self._region_after(stmt, m)
                src = self._taint_in(region, tainted, None)
                if src:
                    return self._emit(findings, "idor", line,
                                      (m.group(1) or m.group(2)), src, region)

        # XSS (echo/print of tainted output)
        m = ECHO_SINKS.search(stmt)
        if m:
            region = stmt[m.end():]
            src = self._taint_in(region, tainted, "xss")
            if src:
                return self._emit(findings, "xss", line, m.group(1), src, region)

        # Backtick shell execution: `... $var ...`
        if "`" in stmt:
            bt = re.search(r"`([^`]*)`", stmt)
            if bt:
                src = self._taint_in(bt.group(1), tainted, "command_injection")
                if src:
                    return self._emit(findings, "command_injection", line,
                                      "backticks", src, bt.group(1))

        # Inter-procedural (4.2): a call to a local helper that funnels a tainted
        # argument into an internal sink.
        self._check_helper_sinks(line, stmt, tainted, findings)

    def _region_after(self, stmt, match):
        """Argument region for a call-style sink (balanced parens) or rest of line."""
        open_idx = stmt.find("(", match.start())
        if open_idx != -1 and open_idx - match.start() < 40:
            return self._arg_region(stmt, open_idx)
        return stmt[match.end():]

    def _is_dynamic(self, region: str) -> bool:
        """True if the SQL/path is built dynamically (concatenation or interpolation),
        i.e. not a static constant string — the hallmark of an injectable sink."""
        if "." in region and re.search(r"['\"]\s*\.|\.\s*\$", region):
            return True
        # interpolation of a variable inside a double-quoted string
        if re.search(r'"[^"]*\$\w+[^"]*"', region):
            return True
        # a bare tainted variable or superglobal passed directly
        if re.search(r"\$_(GET|POST|REQUEST|COOKIE)\b", region):
            return True
        if re.search(r"\$\w+", region) and '"' not in region and "'" not in region:
            return True
        return False

    def _check_blade(self, source, tainted, findings):
        for mo in re.finditer(r"\{!!(.+?)!!\}", source, re.DOTALL):
            region = mo.group(1)
            src = self._taint_in(region, tainted, "xss") or self._source_desc(region)
            if src:
                line = source[:mo.start()].count("\n") + 1
                self._emit(findings, "xss", line, "{!! !!} raw echo", src, region)

    def _emit(self, findings, vuln, line, sink, source, region=""):
        code = self._lines[line - 1] if 0 < line <= len(self._lines) else ""
        param, method = self._endpoint_for(region) if region else ("", "GET")
        f = Finding(vuln=vuln, file=self._rel, line=line, sink=sink.strip(),
                    source=source, framework=self.framework, code=code,
                    param=param, method=method, function=self._line_function(line),
                    message=f"Tainted value from {source} reaches {sink.strip()}.")
        findings.append(f)
        if self._on_source:
            self._on_source(source, line)

    # --- lexer: statement splitter -----------------------------------------

    def _statements(self, src: str) -> List[Tuple[int, int, str]]:
        """Yield (start_line, brace_depth, statement_text) tuples.

        Strips comments, respects single/double quotes and heredocs, treats
        ``<?=`` as an echo, and splits on ``;`` ``{`` ``}`` and ``?>``. The
        brace depth (0 at top level, +1 inside each ``{ }``) lets the
        flow-sensitive pass tell an unconditional reassignment from one buried
        in a conditional/loop body (improvement 4.4)."""
        out: List[Tuple[int, int, str]] = []
        i, n = 0, len(src)
        line = 1
        depth = 0            # current brace-nesting depth
        buf = []
        start_line = 1
        start_depth = 0
        started = False      # True once the current statement has a non-space char
        in_php = False

        def flush():
            nonlocal started
            text = "".join(buf).strip()
            if text:
                out.append((start_line, start_depth, text))
            buf.clear()
            started = False

        def mark():
            # Anchor the statement's line to its first meaningful character,
            # so the number is not left on the previous statement's terminator.
            nonlocal start_line, start_depth, started
            if not started:
                start_line = line
                start_depth = depth
                started = True

        while i < n:
            ch = src[i]
            two = src[i:i + 2]
            three = src[i:i + 3]

            if not in_php:
                # scan for a PHP open tag; everything else is inert HTML
                if three == "<?=":
                    in_php = True
                    flush()
                    buf.append("echo ")
                    mark()
                    i += 3
                    continue
                if src[i:i + 5].lower() == "<?php":
                    in_php = True
                    flush()
                    i += 5
                    continue
                if two == "<?":
                    in_php = True
                    flush()
                    i += 2
                    continue
                if ch == "\n":
                    line += 1
                i += 1
                continue

            # inside PHP
            if two == "?>":
                flush()
                in_php = False
                i += 2
                continue
            if two == "//" or ch == "#":
                while i < n and src[i] != "\n":
                    i += 1
                continue
            if two == "/*":
                i += 2
                while i < n and src[i:i + 2] != "*/":
                    if src[i] == "\n":
                        line += 1
                    i += 1
                i += 2
                continue
            if ch in "'\"":
                quote = ch
                mark()
                buf.append(ch)
                i += 1
                while i < n and src[i] != quote:
                    if src[i] == "\\":
                        buf.append(src[i:i + 2])
                        i += 2
                        continue
                    if src[i] == "\n":
                        line += 1
                    buf.append(src[i])
                    i += 1
                if i < n:
                    buf.append(src[i])
                    i += 1
                continue
            if three == "<<<":
                # heredoc/nowdoc: capture label, then skip to a line starting with it
                m = re.match(r"<<<\s*(['\"]?)(\w+)\1", src[i:])
                if m:
                    label = m.group(2)
                    mark()
                    buf.append(src[i:i + m.end()])
                    i += m.end()
                    end_rx = re.compile(r"^\s*" + re.escape(label) + r"\b", re.M)
                    em = end_rx.search(src, i)
                    stop = em.end() if em else n
                    chunk = src[i:stop]
                    buf.append(chunk)
                    line += chunk.count("\n")
                    i = stop
                    continue
            if ch == "{":
                flush()
                depth += 1
                i += 1
                continue
            if ch == "}":
                flush()
                depth = max(0, depth - 1)
                i += 1
                continue
            if ch == ";":
                flush()
                i += 1
                continue
            if ch == "\n":
                line += 1
            if not ch.isspace():
                mark()
            buf.append(ch)
            i += 1

        flush()
        return out
