"""Static URL-route recovery for Python and Node.js web frameworks.

Native PHP is file-routed (the URL path *is* the file path), but Django,
FastAPI, Express and NestJS map URLs to handler functions through routing code.
To let the search algorithms test such a project automatically, this module
reads that routing code -- with the standard-library ``ast`` for Python and the
:mod:`sbvf.sast.js` lexer for JavaScript/TypeScript, without importing or
running the project -- and returns, for each handler, the URL path(s) that
reach it.

Supported:

* **Django** -- ``urlpatterns`` built with ``path()``, including nested
  ``include('app.urls')`` prefixes, and views referenced as ``views.fn`` or as a
  name imported with ``from .views import fn``. Converters such as
  ``<int:uid>`` are filled with a placeholder value so the path is requestable.
* **FastAPI** -- ``@app.get('/x')`` / ``@router.post(...)`` / ``api_route``
  decorators, ``APIRouter(prefix=...)`` and ``include_router(..., prefix=...)``.
  ``{param}`` placeholders are filled the same way.

* **Express** -- ``app.get('/x', ...)`` / ``router.post(...)`` /
  ``router.route('/x').get(...)``; inline callbacks (keyed by the line of the
  registration, ``@L<line>``) and named handlers (``handlers.search``); mount
  prefixes from ``app.use('/api', router)`` followed across require/import.
* **NestJS** -- ``@Controller('users')`` + ``@Get(':id')`` method decorators and
  ``app.setGlobalPrefix('api')``.

Not supported (documented as a limitation): regex routes (``re_path``/``url``,
Express regex paths), class-based views, routes assembled dynamically at run
time.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .detect import iter_source_files
from .js import JS_EXT, NEST_ROUTE_DECOS, lex, route_of, split_args

# (module path without extension, e.g. "shop/views", function name).
# A module of "" means the view could not be tied to a file; matched by name only.
RouteKey = Tuple[str, str]

HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options"}
_UUID = "00000000-0000-0000-0000-000000000001"
_DJ_PARAM = re.compile(r"<(?:(\w+):)?(\w+)>")
_FA_PARAM = re.compile(r"\{(\w+)(?::[^}]*)?\}")


@dataclass
class Route:
    path: str                       # concrete, requestable path (placeholders filled)
    template: str                   # the route as written, e.g. /profile/<int:uid>/
    methods: Tuple[str, ...]        # allowed HTTP methods; ("*",) = any
    path_params: Tuple[str, ...]    # names bound from the URL path itself
    framework: str                  # "django" | "fastapi" | "express" | "nestjs"
    source: str                     # where the route is declared, e.g. urls.py:7


def extract_routes(root: str) -> Dict[RouteKey, List[Route]]:
    """Return ``{(module, function): [Route, ...]}`` for the project at *root*."""
    base = root if os.path.isdir(root) else os.path.dirname(root)
    trees: Dict[str, ast.Module] = {}
    js_sources: Dict[str, str] = {}
    for path in iter_source_files(root):
        rel = _noext(os.path.relpath(path, base))
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            if path.endswith(".py"):
                trees[rel] = ast.parse(text)
            elif path.endswith(JS_EXT):
                js_sources[rel] = text
        except (SyntaxError, ValueError, OSError):
            continue
    routes: Dict[RouteKey, List[Route]] = {}
    _django_routes(trees, routes)
    _fastapi_routes(trees, routes)
    if js_sources:
        _js_routes(js_sources, routes)
    return routes


def lookup(routes: Dict[RouteKey, List[Route]], file: str, function: str) -> List[Route]:
    """Routes that reach *function* defined in *file* (falls back to name only)."""
    return routes.get((_noext(file), function)) or routes.get(("", function)) or []


# --- helpers ------------------------------------------------------------------

def _noext(rel: str) -> str:
    return os.path.splitext(rel.replace("\\", "/"))[0]


def _const_str(node) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _find_module(dotted: str, trees, near: str = "") -> str:
    """Resolve a dotted module name to a key of *trees* ('' if not found).

    *near* is the importing module; a sibling module with the same name wins,
    which is how ``from . import views`` resolves in a multi-app project.
    """
    want = dotted.replace(".", "/")
    if near:
        sib = (os.path.dirname(near) + "/" + want).lstrip("/")
        if sib in trees:
            return sib
    if want in trees:
        return want
    hits = [k for k in trees if k.endswith("/" + want)]
    return hits[0] if len(hits) == 1 else ""


def _import_map(tree: ast.Module, mod: str, trees) -> Dict[str, str]:
    """name -> module key, from ``import x`` / ``from y import x`` statements."""
    out: Dict[str, str] = {}
    pkg = os.path.dirname(mod)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:   # relative: anchor at the importing package
                parts = pkg.split("/") if pkg else []
                parts = parts[:len(parts) - (node.level - 1)] if node.level > 1 else parts
                anchor = "/".join(parts)
                base = "/".join(p for p in (anchor, (node.module or "").replace(".", "/")) if p)
            else:
                base = (node.module or "").replace(".", "/")
            for a in node.names:
                name = a.asname or a.name
                # `from pkg import views` -> the module pkg/views itself
                as_module = "/".join(p for p in (base, a.name) if p)
                if as_module in trees:
                    out[name] = as_module
                elif base in trees:
                    out[name] = base          # `from .views import profile`
                else:
                    found = _find_module(base.replace("/", "."), trees, mod)
                    if found:
                        out[name] = found
        elif isinstance(node, ast.Import):
            for a in node.names:
                found = _find_module(a.name, trees, mod)
                if found:
                    out[a.asname or a.name.split(".")[0]] = found
    return out


def _fill(template: str, pattern, uuid_types=("uuid",)) -> Tuple[str, Tuple[str, ...]]:
    """Replace path placeholders with requestable values; return (path, names)."""
    names = []

    def sub(m):
        conv, name = (m.group(1), m.group(2)) if m.re is _DJ_PARAM else (None, m.group(1))
        names.append(name)
        return _UUID if conv in uuid_types else "1"

    return pattern.sub(sub, template), tuple(names)


def _add(routes, key: RouteKey, route: Route):
    lst = routes.setdefault(key, [])
    if all(r.path != route.path or r.methods != route.methods for r in lst):
        lst.append(route)


# --- Django -------------------------------------------------------------------

def _django_entries(tree: ast.Module, mod: str, trees):
    """[(kind, template, target, lineno)] from path(...) calls in a urls module."""
    imports = _import_map(tree, mod, trees)
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and len(node.args) >= 2):
            continue
        fname = node.func.attr if isinstance(node.func, ast.Attribute) else \
            node.func.id if isinstance(node.func, ast.Name) else ""
        if fname != "path":
            continue
        tmpl = _const_str(node.args[0])
        if tmpl is None:
            continue
        target = node.args[1]
        if isinstance(target, ast.Call) and isinstance(target.func, ast.Name) \
                and target.func.id == "include" and target.args:
            inc = target.args[0]
            if isinstance(inc, ast.Tuple) and inc.elts:
                inc = inc.elts[0]
            dotted = _const_str(inc)
            if dotted:
                out.append(("include", tmpl, _find_module(dotted, trees, mod), node.lineno))
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            # views.profile -> resolve "views" through imports / sibling module
            modname = target.value.id
            vmod = imports.get(modname) or _find_module(modname, trees, mod)
            out.append(("view", tmpl, (vmod, target.attr), node.lineno))
        elif isinstance(target, ast.Name):
            out.append(("view", tmpl, (imports.get(target.id, ""), target.id), node.lineno))
    return out


def _django_routes(trees, routes):
    urls = {m: t for m, t in trees.items() if os.path.basename(m) == "urls"}
    entries = {m: _django_entries(t, m, trees) for m, t in urls.items()}
    included = {tgt for ents in entries.values()
                for kind, _, tgt, _ in ents if kind == "include" and tgt}
    roots = [m for m in entries if m not in included] or list(entries)

    def walk(mod, prefix, depth):
        if depth > 6 or mod not in entries:
            return
        for kind, tmpl, target, line in entries[mod]:
            full = prefix + tmpl
            if kind == "include":
                walk(target, full, depth + 1)
                continue
            path, names = _fill("/" + full.lstrip("/"), _DJ_PARAM)
            _add(routes, target, Route(path=path, template="/" + full.lstrip("/"),
                                       methods=("*",), path_params=names,
                                       framework="django", source=f"{mod}.py:{line}"))

    for r in roots:
        walk(r, "", 0)


# --- FastAPI ------------------------------------------------------------------

def _fastapi_routes(trees, routes):
    var_prefix: Dict[Tuple[str, str], str] = {}     # (module, var) -> APIRouter prefix
    mounts: List[Tuple[str, str, str]] = []         # (prefix, module, var)

    for mod, tree in trees.items():
        imports = _import_map(tree, mod, trees)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name) \
                    and isinstance(node.value, ast.Call):
                ctor = node.value.func
                cname = ctor.attr if isinstance(ctor, ast.Attribute) else \
                    ctor.id if isinstance(ctor, ast.Name) else ""
                if cname in ("APIRouter", "FastAPI"):
                    var_prefix[(mod, node.targets[0].id)] = \
                        _const_str(_kw(node.value, "prefix")) or ""
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "include_router" and node.args:
                pfx = _const_str(_kw(node, "prefix")) or ""
                a = node.args[0]
                if isinstance(a, ast.Name):
                    # either a local router, or `from .users import router`
                    mounts.append((pfx, imports.get(a.id, mod), a.id))
                elif isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name):
                    target_mod = imports.get(a.value.id) or _find_module(a.value.id, trees, mod)
                    mounts.append((pfx, target_mod, a.attr))

    for mod, tree in trees.items():
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for d in fn.decorator_list:
                if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                        and isinstance(d.func.value, ast.Name)):
                    continue
                verb, var = d.func.attr, d.func.value.id
                if verb in HTTP_VERBS:
                    methods = (verb.upper(),)
                elif verb == "api_route":
                    m = _kw(d, "methods")
                    methods = tuple(s.upper() for s in (
                        _const_str(e) for e in getattr(m, "elts", [])) if s) or ("GET",)
                else:
                    continue
                tmpl = _const_str(d.args[0]) if d.args else _const_str(_kw(d, "path"))
                if tmpl is None:
                    continue
                own = var_prefix.get((mod, var), "")
                outer = [p for p, m, v in mounts if m == mod and v == var] or [""]
                for op in outer:
                    full = op + own + tmpl
                    path, names = _fill(full, _FA_PARAM)
                    _add(routes, (mod, fn.name), Route(
                        path=path, template=full, methods=methods, path_params=names,
                        framework="fastapi", source=f"{mod}.py:{d.lineno}"))


# --- Express / NestJS -------------------------------------------------------------

_EXPRESS_PARAM = re.compile(r":(\w+)(?:\([^)]*\))?\??")
_REQUIRE = re.compile(r"""require\(\s*(['"`])([^'"`]+)\1\s*\)""")
_VERB_CALL = re.compile(r"\.\s*(?:get|post|put|delete|patch|all|options|head)\s*\(")
_IDENT = r"[A-Za-z_$][\w$]*"


def _join_url(*parts: str) -> str:
    return "/" + "/".join(p.strip("/") for p in parts if p and p.strip("/"))


def _fill_express(template: str) -> Tuple[str, Tuple[str, ...]]:
    """Fill ``:param`` placeholders (and ``*``) so the path is requestable."""
    names = []

    def sub(m):
        names.append(m.group(1))
        return "1"
    return _EXPRESS_PARAM.sub(sub, template).replace("*", "x"), tuple(names)


def _resolve_js(spec: str, mod: str, mods) -> str:
    """Module key for a relative require/import specifier ('' for packages)."""
    if not spec.startswith("."):
        return ""
    p = os.path.normpath(os.path.join(os.path.dirname(mod), spec)).replace("\\", "/")
    p = re.sub(r"\.(?:js|mjs|cjs|ts)$", "", p)
    for cand in (p, p + "/index"):
        if cand in mods:
            return cand
    return ""


def _js_imports(stmts, mod: str, mods) -> Dict[str, Tuple[str, Optional[str]]]:
    """local name -> (module key, exported name, or None for a default export)."""
    out: Dict[str, Tuple[str, Optional[str]]] = {}
    for s in stmts:
        t = s.text
        m = re.match(rf"(?:const|let|var)\s+({_IDENT})\s*=\s*" + _REQUIRE.pattern, t)
        if m:
            out[m.group(1)] = (_resolve_js(m.group(3), mod, mods), None)
            continue
        m = re.match(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*" + _REQUIRE.pattern, t)
        if m:
            target = _resolve_js(m.group(3), mod, mods)
            for part in m.group(1).split(","):
                mm = re.match(rf"\s*({_IDENT})\s*(?::\s*({_IDENT}))?", part)
                if mm:
                    out[mm.group(2) or mm.group(1)] = (target, mm.group(1))
            continue
        m = re.match(r"""import\s+(.+?)\s+from\s*(['"`])([^'"`]+)\2""", t, re.S)
        if not m:
            continue
        target, clause = _resolve_js(m.group(3), mod, mods), m.group(1)
        star = re.search(rf"\*\s*as\s+({_IDENT})", clause)
        if star:
            out[star.group(1)] = (target, None)
        default = re.match(rf"\s*({_IDENT})\s*(?:,|$)", clause)
        if default:
            out[default.group(1)] = (target, None)
        named = re.search(r"\{([^}]*)\}", clause)
        if named:
            for part in named.group(1).split(","):
                mm = re.match(rf"\s*({_IDENT})(?:\s+as\s+({_IDENT}))?", part)
                if mm:
                    out[mm.group(2) or mm.group(1)] = (target, mm.group(1))
    return out


def _js_routes(sources: Dict[str, str], routes) -> None:
    lexed = {mod: lex(src) for mod, src in sources.items()}
    mods = set(lexed)
    imports = {mod: _js_imports(stmts, mod, mods) for mod, (stmts, _) in lexed.items()}
    apps = set()                    # {(module, var)} created with express()
    mounts = []                     # (prefix, parent module, parent var, target module, target var)
    global_prefix = ""

    for mod, (stmts, _) in lexed.items():
        imp = imports[mod]
        for s in stmts:
            t = s.text
            m = re.match(rf"(?:const|let|var)\s+({_IDENT})\s*=\s*(?:express|polka|connect)\s*\(\s*\)", t)
            if m:
                apps.add((mod, m.group(1)))
            m = re.search(r"""\.\s*setGlobalPrefix\s*\(\s*(['"`])([^'"`]*)\1""", t)
            if m:
                global_prefix = m.group(2)
            for um in re.finditer(rf"""\b({_IDENT})\s*\.\s*use\s*\(\s*(['"`])([^'"`]*)\2\s*,""", t):
                _, spans = split_args(t, t.index("(", um.start()))
                for a, b in spans[1:]:                  # middlewares..., router
                    arg = t[a:b].strip()
                    rq = _REQUIRE.fullmatch(arg)
                    if rq:
                        target = (_resolve_js(rq.group(2), mod, mods), None)
                    elif re.fullmatch(_IDENT, arg):
                        target = imp.get(arg, (mod, arg))
                    elif re.fullmatch(rf"{_IDENT}\.{_IDENT}", arg):
                        obj, attr = arg.split(".")
                        target = (imp.get(obj, ("", None))[0], attr)
                    else:
                        continue
                    if target[0]:
                        mounts.append((um.group(3), mod, um.group(1), target[0], target[1]))

    def prefix(mod: str, var: str, depth: int = 0) -> str:
        if depth > 8 or (mod, var) in apps:
            return ""
        for p, pmod, pvar, tmod, tvar in mounts:
            if tmod == mod and (tvar is None or tvar == var):
                return _join_url(prefix(pmod, pvar, depth + 1), p)
        return ""

    def add(key_mod, key, full, verb, source, fw):
        path, names = _fill_express(full)
        _add(routes, (key_mod, key), Route(
            path=path, template=full, methods=("*",) if verb == "ALL" else (verb,),
            path_params=names, framework=fw, source=source))

    for mod, (stmts, blocks) in lexed.items():
        imp = imports[mod]
        # Express inline callbacks: app.get('/x', (req, res) => { ... })
        for b in blocks:
            if b.route:
                var, verb, path = b.route
                add(mod, b.route_key, _join_url(prefix(mod, var), path), verb,
                    f"{mod}:{b.line}", "express")
        # Express registrations without a block: named handlers or arrow expressions
        for s in stmts:
            r = None if s.is_header else route_of(s.text)
            vm = _VERB_CALL.search(s.text) if r else None
            if not vm:
                continue
            var, verb, path = r
            full = _join_url(prefix(mod, var), path)
            _, spans = split_args(s.text, vm.end() - 1)
            last = s.text[spans[-1][0]:spans[-1][1]].strip() if len(spans) >= 2 else ""
            src = f"{mod}:{s.line}"
            if "=>" in last or re.match(r"(?:async\s+)?function\b", last):
                add(mod, f"@L{s.line}", full, verb, src, "express")
            elif re.fullmatch(_IDENT, last):
                tmod, name = imp.get(last, (mod, last))
                add(tmod or "", name or last, full, verb, src, "express")
                if name is None:                           # default import: match by name
                    add("", last, full, verb, src, "express")
            elif re.fullmatch(rf"{_IDENT}\.{_IDENT}", last):
                obj, attr = last.split(".")
                add(imp.get(obj, ("", None))[0], attr, full, verb, src, "express")
        # NestJS: @Controller('prefix') class with @Get(...)-decorated methods
        for b in blocks:
            ctrl = next((d for d in b.decorators if d.startswith("@Controller")), None) \
                if b.kind == "class" else None
            if ctrl is None:
                continue
            cm = re.search(r"""(['"`])([^'"`]*)\1""", ctrl)
            cprefix = cm.group(2) if cm else ""
            for mb in blocks:
                if mb.parent is not b or mb.kind != "function" or not mb.name:
                    continue
                for d in mb.decorators:
                    dm = re.match(r"""@(%s)\s*\(\s*(?:(['"`])([^'"`]*)\2)?""" %
                                  "|".join(NEST_ROUTE_DECOS), d)
                    if dm:
                        add(mod, mb.name, _join_url(global_prefix, cprefix, dm.group(3) or ""),
                            dm.group(1).upper(), f"{mod}:{mb.line}", "nestjs")
