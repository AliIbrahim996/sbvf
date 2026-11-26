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
(it does not follow taint across function-call boundaries). Taint propagation is
flow-insensitive (a variable that becomes tainted stays tainted), but the sink
pass is flow-sensitive for *killing* taint: a variable reassigned an
unconditional clean value loses its taint downstream (improvement 4.4). These
limitations are discussed in the thesis as threats to validity.
"""
from __future__ import annotations

import ast
import re
from typing import Callable, List, Optional, Tuple

from .model import INJECTION_CLASSES, Finding


# --- Source recognition -----------------------------------------------------

# Request attributes that carry user input (Django / Flask / FastAPI Request).
REQUEST_ATTRS = {
    "GET", "POST", "QUERY", "query_params", "path_params", "data", "body",
    "args", "values", "form", "files", "cookies", "headers", "json", "content",
    "query", "params", "get_json",
}
# Base identifiers commonly bound to the incoming request object.
REQUEST_BASES = {"request", "req", "self.request"}

# Callables that remove taint, each tied to the vulnerability class(es) it
# actually neutralises (improvement 4.1). A sanitizer makes its value safe only
# for its classes, so html.escape(x) stops XSS but NOT SQL injection:
# cursor.execute("... " + html.escape(x)) is still reported. Numeric casts and
# content-free encoders (base64/percent/JSON) are safe across every injection
# class (INJECTION_CLASSES) but never neutralise an access-control class (IDOR).
# Keyed by the call's final name (e.g. "escape" for markupsafe.escape).
SANITIZER_NAMES = {
    # numeric cast / boolean / encoding -> safe for every injection sink
    "int": INJECTION_CLASSES, "float": INJECTION_CLASSES, "bool": INJECTION_CLASSES,
    "b64encode": INJECTION_CLASSES, "json_dumps": INJECTION_CLASSES,
    "quote": INJECTION_CLASSES, "quote_plus": INJECTION_CLASSES,   # percent-encoding
    "mark_safe_off": INJECTION_CLASSES, "sanitize": INJECTION_CLASSES,
    # HTML/markup escaping -> XSS only
    "escape": frozenset({"xss"}), "escape_html": frozenset({"xss"}),
    "clean": frozenset({"xss"}),                                   # bleach.clean
    # shell quoting -> command injection only
    "escapeshellarg": frozenset({"command_injection"}),
    "shlex_quote": frozenset({"command_injection"}),
}
# Fully-qualified sanitizers whose dotted name pins the class precisely.
SANITIZER_FULL = {
    "html.escape": frozenset({"xss"}), "markupsafe.escape": frozenset({"xss"}),
    "cgi.escape": frozenset({"xss"}), "bleach.clean": frozenset({"xss"}),
    "shlex.quote": frozenset({"command_injection"}),
    "urllib.parse.quote": INJECTION_CLASSES,                       # percent-encoding
}

# Standard-library http.server: inside a *RequestHandler subclass these `self`
# attributes carry the raw request (path + query string, headers, body).
HTTP_HANDLER_ATTRS = {"path", "headers", "rfile", "requestline"}

# Calls whose result does NOT carry their arguments' taint. Every other call
# propagates taint from its receiver/arguments (unless it is a sanitizer), which
# is what lets taint survive helpers such as split/unquote/re.findall/dict(...).
NON_PROPAGATING = {
    "len", "isinstance", "issubclass", "hasattr", "callable", "type", "id", "hash",
    "range", "execute", "executemany", "executescript", "connect", "cursor",
    "commit", "close", "flush", "time", "ctime", "now",
}

# FastAPI parameter markers whose presence means "this parameter is user input".
FASTAPI_PARAM_MARKERS = {"Query", "Path", "Body", "Form", "Cookie", "Header", "File"}
# FastAPI route-decorator method names.
ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "options",
                 "head", "api_route", "route", "websocket"}
# Parameter names never treated as user input.
PARAM_SKIP = {"self", "cls", "request", "req", "db", "session", "background_tasks",
              "response", "websocket", "current_user", "settings"}

# How a request attribute delivers its input (used to tell the dynamic search
# whether a parameter is reachable with a GET query string).
_ATTR_METHOD = {
    "GET": "GET", "QUERY": "GET", "query_params": "GET", "args": "GET",
    "query": "GET", "params": "GET",
    "POST": "POST", "form": "POST", "data": "POST", "body": "POST",
    "json": "POST", "get_json": "POST", "files": "POST", "content": "POST",
    "values": "REQUEST", "cookies": "COOKIE", "headers": "HEADER",
    "path_params": "PATH",
}
# FastAPI parameter marker -> input method.
_MARKER_METHOD = {"Query": "GET", "Path": "PATH", "Body": "POST", "Form": "POST",
                  "File": "POST", "Cookie": "COOKIE", "Header": "HEADER"}
# Flask route path segment: <name> or <converter:name> (e.g. <int:uid>).
_FLASK_PATH_PARAM = re.compile(r"<(?:[^:>]+:)?(\w+)>")

# --- IDOR (broken object-level access control, OWASP A01) --------------------
# A request-controlled id reaching a by-id data fetch, in a handler that performs
# no ownership / authorization check. Decorators that imply an access check:
IDOR_GUARD_DECORATORS = {"login_required", "permission_required", "user_passes_test",
                         "staff_member_required", "permission_classes",
                         "has_permissions", "authenticated"}
# A real authorization *action* in the handler suppresses its IDOR findings.
# Only explicit permission calls/exceptions count -- NOT the mere presence of a
# variable named user/owner/account (those over-suppressed real IDOR before).
_IDOR_AUTHZ_RE = re.compile(
    r"\bhas_perm\s*\(|\bhas_object_permission\b|PermissionDenied|self\.get_object\s*\(|"
    r"\bauthorize\s*\(|\bcheck_object_permissions\b|\bcheck_owner\s*\(|\brequire_\w+\s*\(")
# Keyword names that scope a query to an owner; when one of these is passed on the
# fetch itself with a current-user value, the fetch is authorized (not IDOR).
IDOR_OWNER_KEYS = {"user", "owner", "created_by", "account", "tenant", "author",
                   "user_id", "owner_id", "created_by_id", "account_id",
                   "tenant_id", "author_id", "owner_user"}
_CUR_USER_RE = re.compile(r"\brequest\.user\b|\bcurrent_user\b|self\.request\.user")


def _const_str(node) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _subscript_key(node: ast.Subscript):
    """The subscript expression (Python 3.9+ stores it directly in ``slice``)."""
    return node.slice


def route_path_params(template: str) -> List[str]:
    """Names of ``{param}`` placeholders in a FastAPI route template."""
    return re.findall(r"\{(\w+)(?::[^}]*)?\}", template or "")


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

    def __init__(self, framework: str, func_name: str = "", http_handler: bool = False,
                 summaries: Optional[dict] = None):
        self.framework = framework
        self.func_name = func_name
        self.http_handler = http_handler   # method of an http.server RequestHandler
        self.guarded = False               # handler has an ownership/authz check (IDOR)
        self.tainted = {}   # var name -> human-readable source description
        self.sanitized = {} # var name -> frozenset of classes it is already safe for
        self.origin = {}    # var name -> (request param, input method)
        # Inter-procedural summaries (improvement 4.2): name -> {params,
        # returns_source, sink_params}. Shared ref so fixpoint updates are visible.
        self.summaries = summaries if summaries is not None else {}

    def _returns_source_call(self, node) -> bool:
        """True if *node* calls a local helper that hands back user input."""
        if not isinstance(node, ast.Call):
            return False
        fname = _name_of(node.func)
        s = self.summaries.get(fname) or self.summaries.get(fname.split(".")[-1])
        return bool(s and s["returns_source"])

    # --- request-parameter recovery (for the SAST-guided dynamic search) ----

    def _direct_param(self, node) -> Optional[Tuple[str, str]]:
        """(param, method) if *node* reads one named request parameter, e.g.
        ``request.GET.get('q')`` or ``request.GET['q']``."""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("get", "getlist", "getone") and node.args:
            key = _const_str(node.args[0])
            if key and self._req_attr_desc(node.func.value):
                return key, _ATTR_METHOD.get(node.func.value.attr, "GET")
        if isinstance(node, ast.Subscript):
            key = _const_str(_subscript_key(node))
            if key and self._req_attr_desc(node.value):
                return key, _ATTR_METHOD.get(node.value.attr, "GET")
        return None

    def origin_of(self, node) -> Optional[Tuple[str, str]]:
        """Best-effort (param, method) behind the taint in expression *node*."""
        for sub in ast.walk(node):
            ep = self._direct_param(sub)
            if ep:
                return ep
            if isinstance(sub, ast.Name) and sub.id in self.origin:
                return self.origin[sub.id]
        return None

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
            # http.server: self.path / self.headers / self.rfile in a RequestHandler
            if self.http_handler and isinstance(node.value, ast.Name) \
                    and node.value.id == "self" and node.attr in HTTP_HANDLER_ATTRS:
                return f"http.server request (self.{node.attr})"
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

    def sanitizer_classes(self, node) -> Optional[frozenset]:
        """The classes a sanitizer call neutralises, or None if *node* is not a
        known sanitizer."""
        if isinstance(node, ast.Call):
            fname = _name_of(node.func)
            if fname in SANITIZER_FULL:
                return SANITIZER_FULL[fname]
            last = fname.split(".")[-1]
            if last in SANITIZER_NAMES:
                return SANITIZER_NAMES[last]
        return None

    def _taint_children(self, node) -> list:
        """The sub-expressions through which taint propagates for *node* (the same
        structure taint_of and taint_san both walk)."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return [node.left, node.right]
        if isinstance(node, ast.JoinedStr):           # f"...{x}..."
            return [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        if isinstance(node, ast.Call):
            # A call's result carries the taint of its receiver or any argument
            # ("...".format(x), x.split('?'), unquote(x), dict(gen), helper(x) ...),
            # except for NON_PROPAGATING calls (sanitizers are handled separately).
            if _name_of(node.func).split(".")[-1] in NON_PROPAGATING:
                return []
            out = []
            if isinstance(node.func, ast.Attribute):
                out.append(node.func.value)
            for a in list(node.args) + [k.value for k in node.keywords]:
                out.append(a.value if isinstance(a, ast.Starred) else a)
            return out
        if isinstance(node, ast.Lambda):              # re.sub(..., lambda m: x, ...)
            return [node.body]
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            return parts + [g.iter for g in node.generators]
        if isinstance(node, ast.Dict):
            return [v for v in node.values if v is not None]
        if isinstance(node, ast.Starred):
            return [node.value]
        if isinstance(node, ast.Subscript):           # tainted[...] , dict.get handled above
            return [node.value]
        if isinstance(node, ast.Attribute):           # tainted.attr
            return [node.value]
        if isinstance(node, ast.Await):
            return [node.value]
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return list(node.elts)
        if isinstance(node, ast.IfExp):
            return [node.body, node.orelse]
        return []

    def taint_of(self, node, vuln: Optional[str] = None) -> Optional[str]:
        """Return a source description if *node* carries taint that is NOT
        sanitized for vulnerability class *vuln* (improvement 4.1).

        With *vuln* None, any sanitizer suppresses the taint (the pre-4.1
        behaviour, kept for the access-control sinks a content sanitizer does not
        address, e.g. IDOR)."""
        if node is None:
            return None
        sc = self.sanitizer_classes(node)
        if sc is not None:
            if vuln is None or vuln in sc:
                return None
            # Sanitized for another class only: taint still flows for *vuln*
            # through the wrapped argument(s) -> fall through to the children.
        if self._returns_source_call(node):           # 4.2: source-returning helper
            return f"user input (returned by {_name_of(node.func)}())"
        direct = self.is_source_expr(node)
        if direct:
            return direct
        if isinstance(node, ast.Name):
            src = self.tainted.get(node.id)
            if src is None:
                return None
            if vuln is not None and vuln in self.sanitized.get(node.id, frozenset()):
                return None
            return src
        if isinstance(node, ast.Constant):
            return None
        for child in self._taint_children(node):
            t = self.taint_of(child, vuln)
            if t:
                return t
        return None

    def taint_san(self, node) -> Tuple[Optional[str], frozenset]:
        """For a value expression during propagation, return (source description,
        classes it is safe for). A value neutralised for every injection class is
        treated as clean (returns (None, ...)) so it never taints the target."""
        if node is None:
            return None, frozenset()
        sc = self.sanitizer_classes(node)
        if sc is not None:
            if INJECTION_CLASSES <= sc:
                return None, frozenset()           # universal sanitizer -> clean
            src, inner = self._children_taint_san(node)
            if src is None:
                return None, frozenset()
            return src, inner | sc                 # safe for this class downstream
        if self._returns_source_call(node):           # 4.2: source-returning helper
            return f"user input (returned by {_name_of(node.func)}())", frozenset()
        direct = self.is_source_expr(node)
        if direct:
            return direct, frozenset()
        if isinstance(node, ast.Name):
            return self.tainted.get(node.id), self.sanitized.get(node.id, frozenset())
        if isinstance(node, ast.Constant):
            return None, frozenset()
        return self._children_taint_san(node)

    def _children_taint_san(self, node) -> Tuple[Optional[str], frozenset]:
        """Combine taint/san across a composite node's tainted children: the
        source is the first tainted child's; a class is safe only if *every*
        tainted part is safe for it (intersection)."""
        found = []
        for child in self._taint_children(node):
            s, sn = self.taint_san(child)
            if s is not None:
                found.append((s, sn))
        if not found:
            return None, frozenset()
        san = set(found[0][1])
        for _, sn in found[1:]:
            san &= sn
        return found[0][0], frozenset(san)


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

        # Inter-procedural summaries (improvement 4.2): learn, for every function
        # in the file, whether it RETURNS user input (a source-returning helper)
        # and which of its parameters flow to a dangerous SINK. Built before the
        # main pass so call sites can use them. (Taint flowing *through* an
        # argument to the call's result is already handled by call propagation.)
        self._summaries = {}
        self._build_summaries(tree)

        # Module-level (native scripts with no functions) plus each function body.
        module_scope = _FuncScope(self.framework, summaries=self._summaries)
        self._seed_module(tree, module_scope)
        self._fixpoint(tree.body, module_scope)
        self._collect_sinks(tree.body, module_scope, findings)

        # Methods of http.server request-handler classes read the raw request
        # from self.path / self.headers / self.rfile (stdlib web apps).
        handler_methods = set()
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef) and any(
                    _name_of(b).split(".")[-1].endswith("RequestHandler") for b in cls.bases):
                handler_methods.update(id(n) for n in cls.body
                                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = _FuncScope(self.framework, node.name,
                                   http_handler=id(node) in handler_methods,
                                   summaries=self._summaries)
                scope.guarded = self._has_ownership_guard(node)
                self._seed_params(node, scope)
                self._fixpoint(node.body, scope)
                self._collect_sinks(node.body, scope, findings)
        return findings

    # --- inter-procedural summaries (improvement 4.2) -----------------------

    def _param_names(self, func) -> List[str]:
        """Positional-then-keyword parameter names of *func*, minus framework
        objects (self/request/db/...) that are never a caller-supplied value."""
        a = func.args
        names = [p.arg for p in (list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs))]
        return [n for n in names if n not in PARAM_SKIP]

    def _build_summaries(self, tree):
        """Fixpoint over every function: record returns_source (the function hands
        back user input) and sink_params (a parameter reaches a sink inside it).
        Iterated because one helper may call another."""
        funcs = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs[node.name] = node        # last definition of a name wins
        for name, f in funcs.items():
            self._summaries[name] = {"params": self._param_names(f),
                                     "returns_source": False, "sink_params": set()}
        for _ in range(8):
            changed = False
            for name, f in funcs.items():
                rs, sp = self._summarize_func(f)
                cur = self._summaries[name]
                if rs != cur["returns_source"] or sp != cur["sink_params"]:
                    cur["returns_source"], cur["sink_params"] = rs, sp
                    changed = True
            if not changed:
                break

    def _summarize_func(self, func):
        """Analyze *func* with every parameter treated as tainted, and report
        (returns_source, {(param, vuln)}). Uses the current summaries for any
        helper it calls, so the enclosing fixpoint converges."""
        scope = _FuncScope(self.framework, func.name, summaries=self._summaries)
        for p in self._param_names(func):
            scope.tainted[p] = f"parameter '{p}'"
            scope.origin[p] = (p, "PARAM")
        self._fixpoint(func.body, scope)

        # sink_params: run the (flow-sensitive) sink pass into a throwaway list;
        # a finding whose recovered origin is a parameter is a parameter->sink flow.
        tmp: List[Finding] = []
        self._collect_sinks(func.body, scope, tmp)
        params = set(self._param_names(func))
        sink_params = {(f.param, f.vuln) for f in tmp
                       if f.method == "PARAM" and f.param in params}

        # returns_source: a return value tainted by a real input source (not just
        # a parameter, whose through-flow the caller already models).
        returns_source = False
        for node in self._scope_nodes(func.body):
            if isinstance(node, ast.Return) and node.value is not None:
                if scope.taint_of(node.value):
                    ep = scope.origin_of(node.value)
                    if ep is None or ep[1] != "PARAM":
                        returns_source = True
                        break
        return returns_source, sink_params

    def _call_summary(self, node):
        """The summary for a call to a locally-defined function, or None."""
        if not isinstance(node, ast.Call):
            return None
        fname = _name_of(node.func)
        return self._summaries.get(fname) or self._summaries.get(fname.split(".")[-1])

    def _arg_for_param(self, call, params, pname):
        """The argument expression a call passes for parameter *pname*, or None."""
        for kw in call.keywords:
            if kw.arg == pname:
                return kw.value
        try:
            idx = params.index(pname)
        except ValueError:
            return None
        return call.args[idx] if idx < len(call.args) else None

    def _func_source(self, func) -> str:
        start = max(0, getattr(func, "lineno", 1) - 1)
        end = getattr(func, "end_lineno", None) or (start + 60)
        return "\n".join(self._lines[start:end])

    def _has_ownership_guard(self, func) -> bool:
        """True if the handler performs a real authorization action (a guard
        decorator or an explicit permission call), so a by-id fetch inside it is
        not reported as IDOR. Variable *names* no longer count as a guard."""
        for d in func.decorator_list:
            if _name_of(d).split(".")[-1] in IDOR_GUARD_DECORATORS:
                return True
        return bool(_IDOR_AUTHZ_RE.search(self._func_source(func)))

    @staticmethod
    def _call_owner_scoped(node) -> bool:
        """True if this fetch is scoped to the current user, e.g.
        ``Order.objects.get(pk=id, user=request.user)`` -- then it is authorized."""
        for kw in node.keywords:
            if kw.arg in IDOR_OWNER_KEYS:
                try:
                    val = ast.unparse(kw.value)
                except Exception:
                    val = ""
                if _CUR_USER_RE.search(val):
                    return True
        return False

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
        path_params = set(self._route_path_params(func))
        flask_params = set(self._flask_route_params(func)) if self.framework == "flask" else set()
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
                    if name in path_params:
                        method = "PATH"
                    else:
                        method = _MARKER_METHOD.get(marker, "GET")
                    scope.origin[name] = (name, method)
            elif self.framework == "django":
                # Django view: positional URL kwargs after `request` are user-controlled.
                if has_request and name not in ("request", "req"):
                    scope.tainted[name] = f"URL parameter '{name}'"
                    scope.origin[name] = (name, "PATH")
            elif self.framework == "flask":
                # Flask view: a parameter named by a <converter:name> segment of the
                # route is a user-controlled URL path value. (request.args/form are
                # recognised as sources directly, independent of the parameters.)
                if is_route and name in flask_params:
                    scope.tainted[name] = f"URL parameter '{name}'"
                    scope.origin[name] = (name, "PATH")
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

    def _route_path_params(self, func) -> List[str]:
        """``{param}`` names in the handler's route decorator template, if any."""
        out = []
        for d in func.decorator_list:
            if isinstance(d, ast.Call) and _name_of(d.func).split(".")[-1] in ROUTE_METHODS:
                tmpl = _const_str(d.args[0]) if d.args else None
                for k in d.keywords:
                    if k.arg == "path":
                        tmpl = _const_str(k.value)
                out += route_path_params(tmpl)
        return out

    def _flask_route_params(self, func) -> List[str]:
        """``<converter:name>`` segment names in the handler's Flask route(s)."""
        out = []
        for d in func.decorator_list:
            if isinstance(d, ast.Call) and _name_of(d.func).split(".")[-1] in ROUTE_METHODS:
                tmpl = _const_str(d.args[0]) if d.args else None
                if tmpl:
                    out += _FLASK_PATH_PARAM.findall(tmpl)
        return out

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
                for t in node.targets:
                    assigns.extend(self._pair(t, node.value))
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                assigns.append(([node.target], node.value))
            elif isinstance(node, ast.AugAssign):
                assigns.append(([node.target], node.value))
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                assigns.append(([node.target], node.iter))   # for x in tainted: ...
        changed = True
        guard = 0
        while changed and guard < 50:
            changed = False
            guard += 1
            for targets, value in assigns:
                src, san = scope.taint_san(value)
                if not src:
                    continue
                for t in targets:
                    for name in self._target_names(t):
                        if name not in scope.tainted:
                            scope.tainted[name] = src
                            scope.sanitized[name] = san
                            changed = True
                            if self._on_source:
                                self._on_source(src, getattr(value, "lineno", 0))
                        if name not in scope.origin:
                            ep = scope.origin_of(value)
                            if ep:
                                scope.origin[name] = ep
                                changed = True

    def _pair(self, target, value):
        """Split ``a, b = x, y`` into element-wise assignments so only the
        variables that actually receive tainted values become tainted."""
        if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (ast.Tuple, ast.List)) \
                and len(target.elts) == len(value.elts) \
                and not any(isinstance(e, ast.Starred) for e in target.elts + value.elts):
            out = []
            for t, v in zip(target.elts, value.elts):
                out.extend(self._pair(t, v))
            return out
        return [([target], value)]

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
        """Flow-sensitive sink pass (improvement 4.4). Walk the statements in
        order with a *live* taint set seeded from the fixpoint; a variable
        reassigned a clean value is killed for the statements that follow, so
        ``x = request.GET['q']; x = '5'; cur.execute(x)`` is no longer reported.
        Nested blocks are entered with a copy and their taint is unioned back on
        exit, so a kill buried in a conditional/loop body never leaks out (no
        false negatives) while an unconditional reassignment does."""
        saved_t, saved_s = scope.tainted, scope.sanitized
        scope.tainted = dict(saved_t)
        scope.sanitized = dict(saved_s)
        try:
            self._flow_block(body, scope, findings)
        finally:
            scope.tainted, scope.sanitized = saved_t, saved_s

    def _flow_block(self, stmts, scope, findings):
        for node in stmts:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue                                  # separate scope
            # 1) sinks in this statement's own expressions (not nested blocks),
            #    evaluated before the statement's own reassignment takes effect.
            for call in self._stmt_calls(node):
                self._check_call(call, scope, findings)
            # 2) apply this statement's taint gen/kill to the live state.
            self._apply_flow_assign(node, scope)
            # 3) recurse into nested blocks with copies; union gens back on exit.
            subs = self._sub_blocks(node)
            if subs:
                base_t, base_s = scope.tainted, scope.sanitized
                for block in subs:
                    scope.tainted, scope.sanitized = dict(base_t), dict(base_s)
                    self._flow_block(block, scope, findings)
                    base_t.update(scope.tainted)          # keep gens, drop kills
                    base_s.update(scope.sanitized)
                scope.tainted, scope.sanitized = base_t, base_s

    def _stmt_calls(self, node):
        """Every Call in *node*'s own expressions, not descending into the nested
        statement blocks (those are walked separately by _flow_block)."""
        calls = []
        for field, value in ast.iter_fields(node):
            if field in ("body", "orelse", "finalbody", "handlers"):
                continue
            for item in (value if isinstance(value, list) else [value]):
                if isinstance(item, ast.AST):
                    calls.extend(n for n in ast.walk(item) if isinstance(n, ast.Call))
        return calls

    def _sub_blocks(self, node):
        """The nested statement lists of *node* (if/for/while/with/try bodies)."""
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return []
        blocks = []
        for field in ("body", "orelse", "finalbody"):
            v = getattr(node, field, None)
            if isinstance(v, list) and v and all(isinstance(x, ast.stmt) for x in v):
                blocks.append(v)
        for h in getattr(node, "handlers", []) or []:
            if getattr(h, "body", None):
                blocks.append(h.body)
        return blocks

    def _apply_flow_assign(self, node, scope):
        """Update the live taint set for an assignment: (re)taint a target from a
        tainted value, or kill it on a clean (re)assignment."""
        def gen_kill(targets, value, allow_kill=True):
            src, san = scope.taint_san(value)
            for t in targets:
                for name in self._target_names(t):
                    if src:
                        scope.tainted[name] = src
                        scope.sanitized[name] = san
                    elif allow_kill:
                        scope.tainted.pop(name, None)
                        scope.sanitized.pop(name, None)

        if isinstance(node, ast.Assign):
            for t in node.targets:
                for targets, value in self._pair(t, node.value):
                    gen_kill(targets, value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            gen_kill([node.target], node.value)
        elif isinstance(node, ast.AugAssign):
            # x += value accumulates; a tainted RHS taints x but a clean RHS does
            # not wipe the existing value, so never kill here.
            gen_kill([node.target], node.value, allow_kill=False)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            gen_kill([node.target], node.iter)

    def _check_call(self, node, scope, findings):
        fname = _name_of(node.func)
        last = fname.split(".")[-1]
        pos = node.args

        def first_tainted(args, vuln):
            for a in args:
                t = scope.taint_of(a, vuln)
                if t:
                    return t
            return None

        def dyn_tainted(args, vuln):
            """Tainted AND dynamically built (not a bare constant) -> injectable."""
            for a in args:
                t = scope.taint_of(a, vuln)
                if t and not isinstance(a, ast.Constant):
                    return t
            return None

        # SQL injection
        if last in ("execute", "executemany", "executescript", "raw", "extra",
                    "annotate_raw") or fname in ("connection.execute",):
            src = dyn_tainted(pos[:1], "sqli")
            if src:
                return self._emit(findings, "sqli", node, fname, src, scope)
        if last == "RawSQL" or fname.endswith("RawSQL"):
            src = dyn_tainted(pos[:1], "sqli")
            if src:
                return self._emit(findings, "sqli", node, fname, src, scope)
        if last == "text":   # sqlalchemy text()
            src = dyn_tainted(pos[:1], "sqli")
            if src:
                return self._emit(findings, "sqli", node, fname, src, scope)

        # OS command injection
        if fname in ("os.system", "os.popen") or last in ("getoutput", "getstatusoutput"):
            src = first_tainted(pos[:1], "command_injection")
            if src:
                return self._emit(findings, "command_injection", node, fname, src, scope)
        if last in ("call", "run", "Popen", "check_output", "check_call") and \
                ("subprocess" in fname or last == "Popen"):
            shell_true = any(isinstance(k.value, ast.Constant) and k.value.value is True
                             for k in node.keywords if k.arg == "shell")
            if shell_true:
                src = first_tainted(pos, "command_injection")
                if src:
                    return self._emit(findings, "command_injection", node, fname, src, scope)

        # IDOR: a request-controlled id reaches a by-id object fetch, and the
        # handler has no ownership/authorization check. These ORM fetches are
        # parameterized (not SQLi) but return an object chosen by the caller.
        if not scope.guarded:
            recv = fname.rsplit(".", 1)[0] if "." in fname else ""
            orm_fetch = (
                last in ("get_object_or_404", "get_list_or_404")
                or (last in ("get", "filter", "get_or_create", "aget", "afilter",
                             "aget_or_create") and recv.endswith(".objects"))
                or last in ("filter_by",)
                or (last == "get" and recv.endswith(".query")))
            if orm_fetch and not self._call_owner_scoped(node):
                # A content sanitizer (even int()) does not make an id non-IDOR,
                # so this access-control sink keeps the pre-4.1 semantics.
                src = first_tainted(list(node.args) + [k.value for k in node.keywords], None)
                if src:
                    return self._emit(findings, "idor", node, fname, src, scope)

        # Code injection
        if fname in ("eval", "exec") or last in ("eval", "exec"):
            src = first_tainted(pos[:1], "code_injection")
            if src:
                return self._emit(findings, "code_injection", node, fname, src, scope)
        if fname in ("pickle.loads", "yaml.load", "cPickle.loads"):
            src = first_tainted(pos[:1], "code_injection")
            if src:
                return self._emit(findings, "code_injection", node, fname, src, scope)

        # XSS / HTML response
        if last in ("HttpResponse", "HttpResponseBadRequest", "HTMLResponse",
                    "mark_safe", "Markup", "format_html"):
            src = first_tainted(pos[:1], "xss")
            if src:
                return self._emit(findings, "xss", node, fname, src, scope)

        # http.server handlers: the response body and the Location header
        if scope.http_handler and fname == "self.wfile.write":
            src = first_tainted(pos[:1], "xss")
            if src:
                return self._emit(findings, "xss", node, fname, src, scope)
        if scope.http_handler and fname == "self.send_header" and len(pos) >= 2 \
                and isinstance(pos[0], ast.Constant) \
                and str(pos[0].value).lower() == "location":
            src = first_tainted(pos[1:2], "open_redirect")
            if src:
                return self._emit(findings, "open_redirect", node, fname, src, scope)

        # Open redirect
        if last in ("redirect", "HttpResponseRedirect", "RedirectResponse"):
            src = first_tainted(pos[:1], "open_redirect")
            if src:
                return self._emit(findings, "open_redirect", node, fname, src, scope)

        # Path traversal / file ops
        if fname == "open" or last in ("send_file", "send_from_directory"):
            src = first_tainted(pos[:1], "path_traversal")
            if src:
                return self._emit(findings, "path_traversal", node, fname, src, scope)
        if fname in ("os.remove", "os.unlink"):
            src = first_tainted(pos[:1], "path_traversal")
            if src:
                return self._emit(findings, "path_traversal", node, fname, src, scope)

        # SSRF
        if fname in ("requests.get", "requests.post", "requests.put", "requests.delete",
                     "urllib.request.urlopen", "httpx.get", "httpx.post") or \
                (last == "urlopen"):
            src = first_tainted(pos[:1], "ssrf")
            if src:
                return self._emit(findings, "ssrf", node, fname, src, scope)

        # Inter-procedural (4.2): a call to a local helper that funnels one of its
        # parameters into a sink -> flag if the matching argument is tainted.
        summ = self._call_summary(node)
        if summ and summ["sink_params"]:
            for pname, vuln in summ["sink_params"]:
                arg = self._arg_for_param(node, summ["params"], pname)
                if arg is None:
                    continue
                src = scope.taint_of(arg, vuln)
                if src:
                    return self._emit(findings, vuln, node,
                                      f"{fname}() -> {vuln} sink", src, scope)

    def _emit(self, findings, vuln, node, sink, source, scope):
        line = getattr(node, "lineno", 0)
        code = self._lines[line - 1] if 0 < line <= len(self._lines) else ""
        ep = None
        for arg in list(node.args) + [k.value for k in node.keywords]:
            ep = scope.origin_of(arg)
            if ep:
                break
        param, method = ep or ("", "GET")
        f = Finding(vuln=vuln, file=self._rel, line=line, sink=sink,
                    source=source, framework=self.framework, code=code,
                    column=getattr(node, "col_offset", 0),
                    param=param, method=method, function=scope.func_name,
                    message=f"Tainted value from {source} reaches {sink}().")
        findings.append(f)
        if self._on_source:
            self._on_source(source, line)
