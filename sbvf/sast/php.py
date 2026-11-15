"""Static taint analysis for PHP source (native, Yii, Laravel).

PHP has no parser in the Python standard library, so this module implements a
pragmatic, quote-aware lexer: it strips comments (preserving line numbers),
splits the source into statements while respecting string literals and heredocs,
and tracks tainted variables across assignments. A statement that pushes an
unsanitized tainted value into a dangerous sink (SQL query, echo, shell command,
include, eval) produces a :class:`Finding` at the statement's line.

The analysis is flow-insensitive (once a ``$var`` is tainted it stays tainted)
and intra-file; these limitations are noted in the thesis.
"""
from __future__ import annotations

import re
from typing import Callable, List, Optional, Tuple

from .model import Finding


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

# Sanitizers: if one wraps the tainted token, the statement is considered safe.
# Function-style sanitizers wrap their argument in parentheses ...
SANITIZER_FUNCS = re.compile(
    r"\b(htmlspecialchars|htmlentities|intval|floatval|mysqli_real_escape_string|"
    r"real_escape_string|escapeshellarg|escapeshellcmd|basename|filter_var|"
    r"Html::encode|urlencode|ctype_digit|preg_quote|e)\s*\(")
# ... while a cast neutralises the value without parentheses: (int) $x
CAST_SAN = re.compile(r"\((?:int|integer|float|double|bool|boolean)\)")

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
                on_source: Optional[Callable] = None) -> List[Finding]:
        self._rel = rel_path
        self._lines = source.splitlines()
        self._on_source = on_source
        tainted = {}            # "$var" -> source description
        findings: List[Finding] = []

        statements = list(self._statements(source))

        # Pass 1: propagate taint through assignments (fixpoint over statements).
        changed, guard = True, 0
        while changed and guard < 20:
            changed, guard = False, guard + 1
            for line, stmt in statements:
                m = re.match(r"\s*(\$\w+)\s*(?:\.?=)\s*(.+)", stmt)
                if not m or stmt.lstrip().startswith("=="):
                    continue
                var, rhs = m.group(1), m.group(2)
                if "==" in stmt.split("=", 1)[0]:
                    continue
                src = self._taint_in(rhs, tainted)
                if src and var not in tainted:
                    tainted[var] = src
                    changed = True
                    if on_source:
                        on_source(src, line)

        # Pass 2: check every statement for sink usage of tainted data.
        for line, stmt in statements:
            self._check_stmt(line, stmt, tainted, findings)

        # Blade raw-echo ({!! $x !!}) for Laravel template files.
        if rel_path.endswith(".blade.php"):
            self._check_blade(source, tainted, findings)

        return findings

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

    def _taint_in(self, text: str, tainted: dict) -> Optional[str]:
        """Return a source description if *text* carries unsanitized taint."""
        # A direct source reference.
        src = self._source_desc(text)
        if src and not self._is_sanitized(text, src):
            return src
        # A previously-tainted variable used in concatenation / interpolation.
        for var, desc in tainted.items():
            if re.search(re.escape(var) + r"\b", text):
                if not self._is_sanitized(text, var):
                    return desc
        return None

    def _is_sanitized(self, text: str, token: str) -> bool:
        """True if a sanitizer (cast or wrapping call) neutralises the taint."""
        # A numeric/boolean cast anywhere in the expression sanitizes it.
        if CAST_SAN.search(text):
            return True
        # A function-style sanitizer whose balanced-paren region covers the token.
        for sm in SANITIZER_FUNCS.finditer(text):
            open_idx = text.find("(", sm.start())
            if open_idx == -1:
                continue
            region = self._arg_region(text, open_idx)
            if token in region or self._source_desc(region):
                return True
        return False

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
            src = self._taint_in(region, tainted)
            if src and self._is_dynamic(region):
                return self._emit(findings, "sqli", line, m.group(0).strip("("), src)

        # Command injection
        m = CMD_SINKS.search(stmt)
        if m:
            region = self._region_after(stmt, m)
            src = self._taint_in(region, tainted)
            if src:
                return self._emit(findings, "command_injection", line,
                                  m.group(1), src)

        # Code injection
        m = CODE_SINKS.search(stmt)
        if m:
            region = self._region_after(stmt, m)
            src = self._taint_in(region, tainted)
            if src:
                return self._emit(findings, "code_injection", line, m.group(1), src)

        # File inclusion
        m = INCLUDE_SINKS.search(stmt)
        if m:
            region = stmt[m.end():]
            src = self._taint_in(region, tainted)
            if src and self._is_dynamic(region):
                return self._emit(findings, "file_inclusion", line,
                                  m.group(0).strip(), src)

        # XSS (echo/print of tainted output)
        m = ECHO_SINKS.search(stmt)
        if m:
            region = stmt[m.end():]
            src = self._taint_in(region, tainted)
            if src:
                return self._emit(findings, "xss", line, m.group(1), src)

        # Backtick shell execution: `... $var ...`
        if "`" in stmt:
            bt = re.search(r"`([^`]*)`", stmt)
            if bt:
                src = self._taint_in(bt.group(1), tainted)
                if src:
                    return self._emit(findings, "command_injection", line,
                                      "backticks", src)

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
            src = self._taint_in(region, tainted) or self._source_desc(region)
            if src:
                line = source[:mo.start()].count("\n") + 1
                self._emit(findings, "xss", line, "{!! !!} raw echo", src)

    def _emit(self, findings, vuln, line, sink, source):
        code = self._lines[line - 1] if 0 < line <= len(self._lines) else ""
        f = Finding(vuln=vuln, file=self._rel, line=line, sink=sink.strip(),
                    source=source, framework=self.framework, code=code,
                    message=f"Tainted value from {source} reaches {sink.strip()}.")
        findings.append(f)
        if self._on_source:
            self._on_source(source, line)

    # --- lexer: statement splitter -----------------------------------------

    def _statements(self, src: str) -> List[Tuple[int, str]]:
        """Yield (start_line, statement_text) tuples.

        Strips comments, respects single/double quotes and heredocs, treats
        ``<?=`` as an echo, and splits on ``;`` ``{`` ``}`` and ``?>``.
        """
        out: List[Tuple[int, str]] = []
        i, n = 0, len(src)
        line = 1
        buf = []
        start_line = 1
        started = False      # True once the current statement has a non-space char
        in_php = False

        def flush():
            nonlocal started
            text = "".join(buf).strip()
            if text:
                out.append((start_line, text))
            buf.clear()
            started = False

        def mark():
            # Anchor the statement's line to its first meaningful character,
            # so the number is not left on the previous statement's terminator.
            nonlocal start_line, started
            if not started:
                start_line = line
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
            if ch in ";{}":
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
