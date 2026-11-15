"""Static URL-route recovery for Python web frameworks (Django, FastAPI).

Native PHP is file-routed (the URL path *is* the file path), but Python
frameworks map URLs to handler functions through routing code. To let the
search algorithms test a Python project automatically, this module reads that
routing code with the standard-library ``ast`` -- without importing or running
the project -- and returns, for each handler function, the URL path(s) that
reach it.

Supported:

* **Django** -- ``urlpatterns`` built with ``path()``, including nested
  ``include('app.urls')`` prefixes, and views referenced as ``views.fn`` or as a
  name imported with ``from .views import fn``. Converters such as
  ``<int:uid>`` are filled with a placeholder value so the path is requestable.
* **FastAPI** -- ``@app.get('/x')`` / ``@router.post(...)`` / ``api_route``
  decorators, ``APIRouter(prefix=...)`` and ``include_router(..., prefix=...)``.
  ``{param}`` placeholders are filled the same way.

Not supported (documented as a limitation): regex routes (``re_path``/``url``),
class-based views, routes assembled dynamically at run time.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .detect import iter_source_files

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
    framework: str                  # "django" | "fastapi"
    source: str                     # where the route is declared, e.g. urls.py:7


def extract_routes(root: str) -> Dict[RouteKey, List[Route]]:
    """Return ``{(module, function): [Route, ...]}`` for the project at *root*."""
    base = root if os.path.isdir(root) else os.path.dirname(root)
    trees: Dict[str, ast.Module] = {}
    for path in iter_source_files(root):
        if not path.endswith(".py"):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                trees[_noext(os.path.relpath(path, base))] = ast.parse(fh.read())
        except (SyntaxError, ValueError, OSError):
            continue
    routes: Dict[RouteKey, List[Route]] = {}
    _django_routes(trees, routes)
    _fastapi_routes(trees, routes)
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
