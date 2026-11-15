"""Static taint analysis for Python source, built on the standard-library ``ast``.

Approach (intra-procedural, flow-insensitive taint tracking):

1. Parse the file into an AST.
2. For every function (and for module-level code) collect *sources* of
   untrusted input: web-request attributes, route-handler parameters, ``input()``,
   ``sys.argv``, CGI/WSGI fields, etc. The set of taint sources depends on the
   detected framework (native / FastAPI / Django).
3. Propagate taint to any variable assigned from a tainted expression
   (concatenation, f-strings, ``.format``, ``%`` formatting, slicing, casts that
   are *not* sanitizers), iterating to a fixpoint.
4. Walk the body for *sinks* (SQL execution, command execution, ``eval``/``exec``,
   HTML responses, file/redirect/HTTP operations). When a sink receives a tainted
   argument that is not neutralised by a sanitizer, emit a :class:`Finding` at the
   sink's ``file:line``.

This is deliberately a lightweight prototype analyzer: it is intra-procedural
(it does not follow taint across function-call boundaries) and flow-insensitive
(a variable that becomes tainted stays tainted). These limitations are discussed
in the thesis as threats to validity.
"""
from __future__ import annotations

import ast
from typing import Callable, List, Optional

from .model import Finding


# --- Source recognition -----------------------------------------------------

# Request attributes that carry user input (Django / Flask / FastAPI Request).
REQUEST_ATTRS = {
    "GET", "POST", "QUERY", "query_params", "path_params", "data", "body",
    "args", "values", "form", "files", "cookies", "headers", "json", "content",
    "query", "params", "get_json",
}
# Base identifiers commonly bound to the incoming request object.
REQUEST_BASES = {"request", "req", "self.request"}

# Callables that *remove* taint (validation / encoding / casting).
SANITIZERS = {
    "int", "float", "bool", "escape", "quote", "clean", "mark_safe_off",
    "escape_html", "json_dumps", "quote_plus", "escapeshellarg", "b64encode",
    "shlex_quote",
}
# Attribute-style sanitizers matched by their final attribute name.
SANITIZER_ATTRS = {"escape", "quote", "clean", "quote_plus", "sanitize"}

# FastAPI parameter markers whose presence means "this parameter is user input".
FASTAPI_PARAM_MARKERS = {"Query", "Path", "Body", "Form", "Cookie", "Header", "File"}
# FastAPI route-decorator method names.
ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "options",
                 "head", "api_route", "route", "websocket"}
# Parameter names never treated as user input.
PARAM_SKIP = {"self", "cls", "request", "req", "db", "session", "background_tasks",
              "response", "websocket", "current_user", "settings"}


def _name_of(node) -> str:
    """Return the dotted call/attribute name, e.g. ``os.system`` or ``cursor.execute``."""
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        return (base + "." if base else "") + node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _name_of(node.func)
    return ""


class _FuncScope:
    """Taint state for a single function (or the synthetic module scope)."""

    def __init__(self, framework: str):
        self.framework = framework
        self.tainted = {}   # var name -> human-readable source description

    def is_source_expr(self, node) -> Optional[str]:
        """Return a source description if *node* reads untrusted input directly."""
        # input(...) builtin
        if isinstance(node, ast.Call):
            fname = _name_of(node.func)
            if fname == "input":
                return "input()"
            if fname.split(".")[-1] in ("getvalue", "getfirst", "getlist") and \
                    "FieldStorage" in fname or fname.endswith("FieldStorage"):
                return "cgi.FieldStorage"
            # request.GET.get('x'), request.query_params.get(...), await request.json()
            tgt = node.func
            if isinstance(tgt, ast.Attribute):
                desc = self._req_attr_desc(tgt.value)
                if desc:
                    return desc
            # parse_qs(environ['QUERY_STRING']) etc. -> taint flows via its argument
        # request.GET  /  request.query_params  /  request.data ...
        if isinstance(node, ast.Attribute):
            desc = self._req_attr_desc(node)
            if desc:
                return desc
        # request.GET['id'] / request.POST['x'] / sys.argv[1] / environ['QUERY_STRING']
        if isinstance(node, ast.Subscript):
            base = node.value
            desc = self._req_attr_desc(base)
            if desc:
                return desc
            bn = _name_of(base)
            if bn in ("sys.argv", "argv"):
                return "sys.argv"
            if bn in ("environ", "os.environ") or bn.endswith(".environ"):
                return "WSGI environ"
        if isinstance(node, ast.Await):
            return self.is_source_expr(node.value)
        return None

    def _req_attr_desc(self, node) -> Optional[str]:
        """If *node* is a request-input attribute chain, describe it; else None."""
        if isinstance(node, ast.Attribute) and node.attr in REQUEST_ATTRS:
            base = _name_of(node.value)
            if base in REQUEST_BASES or base.endswith("request") or base.endswith("req"):
                return f"{base}.{node.attr}"
        return None

    def is_sanitized(self, node) -> bool:
        """True if *node* is a call to a known sanitizer/validator."""
        if isinstance(node, ast.Call):
            fname = _name_of(node.func)
            last = fname.split(".")[-1]
            if last in SANITIZERS or last in SANITIZER_ATTRS:
                return True
            if fname in ("html.escape", "markupsafe.escape", "shlex.quote",
                         "urllib.parse.quote", "bleach.clean", "cgi.escape"):
                return True
        return False

    def taint_of(self, node) -> Optional[str]:
        """Return a source description if *node* evaluates to tainted data."""
        if node is None:
            return None
        if self.is_sanitized(node):
            return None
        direct = self.is_source_expr(node)
        if direct:
            return direct
        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)
        if isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return self.taint_of(node.left) or self.taint_of(node.right)
        if isinstance(node, ast.JoinedStr):           # f"...{x}..."
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t = self.taint_of(v.value)
                    if t:
                        return t
            return None
        if isinstance(node, ast.Call):
            fname = _name_of(node.func)
            last = fname.split(".")[-1]
            # "...".format(x) / tmpl.format(x) / "".join(parts) / str(x) / x.upper()
            if last in ("format", "join", "str", "format_map", "replace",
                        "strip", "lower", "upper", "decode", "encode", "title"):
                # the value the method is called on
                if isinstance(node.func, ast.Attribute):
                    if self.taint_of(node.func.value):
                        return self.taint_of(node.func.value)
                for a in node.args:
                    t = self.taint_of(a)
                    if t:
                        return t
            return None
        if isinstance(node, ast.Subscript):           # tainted[...] , dict.get handled above
            return self.taint_of(node.value)
        if isinstance(node, ast.Attribute):           # tainted.attr
            return self.taint_of(node.value)
        if isinstance(node, ast.Await):
            return self.taint_of(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for e in node.elts:
                t = self.taint_of(e)
                if t:
                    return t
        if isinstance(node, ast.IfExp):
            return self.taint_of(node.body) or self.taint_of(node.orelse)
        return None


class PythonAnalyzer:
    """Analyze a single Python source file for a given framework."""

    def __init__(self, framework: str = "python-native"):
        self.framework = framework

    def analyze(self, rel_path: str, source: str,
                on_source: Optional[Callable] = None) -> List[Finding]:
        try:
            tree = ast.parse(source, filename=rel_path)
        except SyntaxError:
            return []
        self._lines = source.splitlines()
        self._rel = rel_path
        self._on_source = on_source
        findings: List[Finding] = []

        # Module-level (native scripts with no functions) plus each function body.
        module_scope = _FuncScope(self.framework)
        self._seed_module(tree, module_scope)
        self._fixpoint(tree.body, module_scope)
        self._collect_sinks(tree.body, module_scope, findings)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = _FuncScope(self.framework)
                self._seed_params(node, scope)
                self._fixpoint(node.body, scope)
                self._collect_sinks(node.body, scope, findings)
        return findings

    # --- taint seeding ------------------------------------------------------

    def _seed_module(self, tree, scope):
        pass  # module scope relies on direct sources (input/argv/environ)

    def _seed_params(self, func, scope):
        """Mark route-handler parameters as tainted per framework conventions."""
        is_route = self._is_route_handler(func)
        args = func.args
        all_args = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
        defaults_map = self._default_markers(args)
        has_request = any(a.arg in ("request", "req") for a in all_args)
        for a in all_args:
            name = a.arg
            if name in PARAM_SKIP:
                continue
            marker = defaults_map.get(name)
            if self.framework == "fastapi":
                # Tainted if it carries a Query/Path/Body/... marker, or is a plain
                # str/int path or query parameter on a route handler.
                if marker in FASTAPI_PARAM_MARKERS or (is_route and self._simple_type(a.annotation)):
                    scope.tainted[name] = f"request parameter '{name}'"
            elif self.framework == "django":
                # Django view: positional URL kwargs after `request` are user-controlled.
                if has_request and name not in ("request", "req"):
                    scope.tainted[name] = f"URL parameter '{name}'"
            # native: parameters are not assumed to be user input.
            if name in scope.tainted and self._on_source:
                self._on_source(scope.tainted[name], func.lineno)

    def _default_markers(self, args) -> dict:
        """Map param name -> marker call name (Query/Path/...) from its default."""
        out = {}
        names = list(args.posonlyargs) + list(args.args)
        defaults = list(args.defaults)
        if defaults:
            for a, d in zip(names[-len(defaults):], defaults):
                if isinstance(d, ast.Call):
                    out[a.arg] = _name_of(d.func).split(".")[-1]
        for a, d in zip(args.kwonlyargs, args.kw_defaults):
            if isinstance(d, ast.Call):
                out[a.arg] = _name_of(d.func).split(".")[-1]
        return out

    def _simple_type(self, ann) -> bool:
        if ann is None:
            return True
        return _name_of(ann) in ("str", "int", "float", "bool", "")

    def _is_route_handler(self, func) -> bool:
        for d in func.decorator_list:
            name = _name_of(d)
            last = name.split(".")[-1]
            if last in ROUTE_METHODS:
                return True
        return False

    # --- taint propagation --------------------------------------------------

    def _scope_nodes(self, stmts):
        """Yield every node in *stmts* without descending into nested function,
        class or lambda bodies (those are analyzed in their own scope).

        A function/class/lambda node is still yielded, but its body is not
        traversed here, so module scope never re-analyzes a function's body."""
        stack = list(stmts)
        while stack:
            node = stack.pop()
            yield node
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef, ast.Lambda)):
                continue
            for child in ast.iter_child_nodes(node):
                stack.append(child)

    def _fixpoint(self, body, scope):
        """Iterate assignments until the tainted set stops growing."""
        assigns = []
        for node in self._scope_nodes(body):
            if isinstance(node, ast.Assign):
                assigns.append((node.targets, node.value))
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                assigns.append(([node.target], node.value))
            elif isinstance(node, ast.AugAssign):
                assigns.append(([node.target], node.value))
        changed = True
        guard = 0
        while changed and guard < 50:
            changed = False
            guard += 1
            for targets, value in assigns:
                src = scope.taint_of(value)
                if not src:
                    continue
                for t in targets:
                    for name in self._target_names(t):
                        if name not in scope.tainted:
                            scope.tainted[name] = src
                            changed = True
                            if self._on_source:
                                self._on_source(src, getattr(value, "lineno", 0))

    def _target_names(self, target):
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            out = []
            for e in target.elts:
                out += self._target_names(e)
            return out
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            n = _name_of(target)
            return [n] if n else []
        return []

    # --- sink detection -----------------------------------------------------

    def _collect_sinks(self, body, scope, findings):
        for node in self._scope_nodes(body):
            if isinstance(node, ast.Call):
                self._check_call(node, scope, findings)

    def _check_call(self, node, scope, findings):
        fname = _name_of(node.func)
        last = fname.split(".")[-1]
        pos = node.args

        def first_tainted(args):
            for a in args:
                t = scope.taint_of(a)
                if t:
                    return t
            return None

        def dyn_tainted(args):
            """Tainted AND dynamically built (not a bare constant) -> injectable."""
            for a in args:
                t = scope.taint_of(a)
                if t and not isinstance(a, ast.Constant):
                    return t
            return None

        # SQL injection
        if last in ("execute", "executemany", "executescript", "raw", "extra",
                    "annotate_raw") or fname in ("connection.execute",):
            src = dyn_tainted(pos[:1])
            if src:
                return self._emit(findings, "sqli", node, fname, src, scope)
        if last == "RawSQL" or fname.endswith("RawSQL"):
            src = dyn_tainted(pos[:1])
            if src:
                return self._emit(findings, "sqli", node, fname, src, scope)
        if last == "text":   # sqlalchemy text()
            src = dyn_tainted(pos[:1])
            if src:
                return self._emit(findings, "sqli", node, fname, src, scope)

        # OS command injection
        if fname in ("os.system", "os.popen") or last in ("getoutput", "getstatusoutput"):
            src = first_tainted(pos[:1])
            if src:
                return self._emit(findings, "command_injection", node, fname, src, scope)
        if last in ("call", "run", "Popen", "check_output", "check_call") and \
                ("subprocess" in fname or last == "Popen"):
            shell_true = any(isinstance(k.value, ast.Constant) and k.value.value is True
                             for k in node.keywords if k.arg == "shell")
            if shell_true:
                src = first_tainted(pos)
                if src:
                    return self._emit(findings, "command_injection", node, fname, src, scope)

        # Code injection
        if fname in ("eval", "exec") or last in ("eval", "exec"):
            src = first_tainted(pos[:1])
            if src:
                return self._emit(findings, "code_injection", node, fname, src, scope)
        if fname in ("pickle.loads", "yaml.load", "cPickle.loads"):
            src = first_tainted(pos[:1])
            if src:
                return self._emit(findings, "code_injection", node, fname, src, scope)

        # XSS / HTML response
        if last in ("HttpResponse", "HttpResponseBadRequest", "HTMLResponse",
                    "mark_safe", "Markup", "format_html"):
            src = first_tainted(pos[:1])
            if src:
                return self._emit(findings, "xss", node, fname, src, scope)

        # Open redirect
        if last in ("redirect", "HttpResponseRedirect", "RedirectResponse"):
            src = first_tainted(pos[:1])
            if src:
                return self._emit(findings, "open_redirect", node, fname, src, scope)

        # Path traversal / file ops
        if fname == "open" or last in ("send_file", "send_from_directory"):
            src = first_tainted(pos[:1])
            if src:
                return self._emit(findings, "path_traversal", node, fname, src, scope)
        if fname in ("os.remove", "os.unlink"):
            src = first_tainted(pos[:1])
            if src:
                return self._emit(findings, "path_traversal", node, fname, src, scope)

        # SSRF
        if fname in ("requests.get", "requests.post", "requests.put", "requests.delete",
                     "urllib.request.urlopen", "httpx.get", "httpx.post") or \
                (last == "urlopen"):
            src = first_tainted(pos[:1])
            if src:
                return self._emit(findings, "ssrf", node, fname, src, scope)

    def _emit(self, findings, vuln, node, sink, source, scope):
        line = getattr(node, "lineno", 0)
        code = self._lines[line - 1] if 0 < line <= len(self._lines) else ""
        f = Finding(vuln=vuln, file=self._rel, line=line, sink=sink,
                    source=source, framework=self.framework, code=code,
                    column=getattr(node, "col_offset", 0),
                    message=f"Tainted value from {source} reaches {sink}().")
        findings.append(f)
        if self._on_source:
            self._on_source(source, line)
