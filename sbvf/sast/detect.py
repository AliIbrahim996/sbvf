"""Language and web-framework detection by inspecting a project tree."""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Tuple

from .js import JS_EXT

# Directories never worth scanning (third-party / build / vcs).
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
             "env", "dist", "build", ".idea", ".vscode", "migrations",
             "bootstrap", "storage", ".next", ".nuxt", "coverage",
             "bower_components"}

PHP_EXT = (".php",)
PY_EXT = (".py",)
# JavaScript that is never server code worth analysing: minified/bundled output,
# type declarations, and anything under a front-end asset directory.
JS_SKIP_SUFFIX = (".min.js", ".bundle.js", ".d.ts", ".spec.ts", ".test.ts",
                  ".spec.js", ".test.js")
JS_ASSET_DIRS = {"public", "static", "assets", "www", "client", "frontend",
                 "test", "tests", "__tests__", "e2e", "out"}
JS_MAX_BYTES = 1_000_000


def _wanted_js(root: str, dirpath: str, fn: str) -> bool:
    if not fn.endswith(JS_EXT) or fn.endswith(JS_SKIP_SUFFIX):
        return False
    rel = os.path.relpath(dirpath, root)
    parts = set(rel.replace("\\", "/").split("/"))
    if parts & JS_ASSET_DIRS:
        return False
    try:
        return os.path.getsize(os.path.join(dirpath, fn)) <= JS_MAX_BYTES
    except OSError:
        return False


def iter_source_files(root: str) -> List[str]:
    """Return absolute paths of PHP/Python/JS/TS source files under *root*."""
    files = []
    if os.path.isfile(root):
        return [root]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(PHP_EXT) or fn.endswith(PY_EXT) or _wanted_js(root, dirpath, fn):
                files.append(os.path.join(dirpath, fn))
    return sorted(files)


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def detect_frameworks(root: str, files: List[str]) -> Dict[str, str]:
    """Return {'php': fw, 'python': fw, 'node': fw} for the project.

    PHP frameworks: 'laravel' | 'yii' | 'php-native'
    Python frameworks: 'django' | 'fastapi' | 'python-native'
    Node.js frameworks: 'nestjs' | 'express' | 'node-native'
    An empty string means that language is not present.
    """
    names = {os.path.basename(f) for f in files}
    has_php = any(f.endswith(PHP_EXT) for f in files)
    has_py = any(f.endswith(PY_EXT) for f in files)
    has_js = any(f.endswith(JS_EXT) for f in files)

    result = {"php": "", "python": "", "node": ""}

    # --- PHP framework ---
    if has_php:
        fw = "php-native"
        composer = ""
        for f in files + [os.path.join(root, "composer.json")]:
            if f.endswith("composer.json") and os.path.isfile(f):
                composer = _read(f)
                break
        blade = any(f.endswith(".blade.php") for f in files)
        if "laravel/framework" in composer or "artisan" in names or blade:
            fw = "laravel"
        elif "yiisoft/yii2" in composer or "yiisoft/yii" in composer:
            fw = "yii"
        else:
            # fall back to scanning a few files for framework signatures
            sig = _scan_signatures(files, PHP_EXT, max_files=40)
            if re.search(r"Illuminate\\|use\s+Illuminate|Laravel", sig):
                fw = "laravel"
            elif re.search(r"yii\\web|use\s+yii\\|Yii::\$app", sig):
                fw = "yii"
        result["php"] = fw

    # --- Python framework ---
    if has_py:
        fw = "python-native"
        if "manage.py" in names or any(f.endswith("settings.py") for f in files):
            fw = "django"
        else:
            sig = _scan_signatures(files, PY_EXT, max_files=40)
            if re.search(r"from\s+django|import\s+django", sig):
                fw = "django"
            elif re.search(r"from\s+fastapi|import\s+fastapi|APIRouter", sig):
                fw = "fastapi"
        result["python"] = fw

    # --- Node.js framework ---
    if has_js:
        deps = _node_dependencies(root)
        fw = "node-native"
        if any(d.startswith("@nestjs/") for d in deps):
            fw = "nestjs"
        elif "express" in deps:
            fw = "express"
        else:
            sig = _scan_signatures(files, JS_EXT, max_files=60)
            if re.search(r"""from\s+['"]@nestjs/|require\(\s*['"]@nestjs/""", sig):
                fw = "nestjs"
            elif re.search(r"""from\s+['"]express['"]|require\(\s*['"]express['"]\s*\)""", sig):
                fw = "express"
        result["node"] = fw

    return result


def _node_dependencies(root: str) -> set:
    """Dependency names from package.json files (root first, then sub-packages)."""
    deps = set()
    base = root if os.path.isdir(root) else os.path.dirname(root)
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if dirpath[len(base):].count(os.sep) > 3:
            dirnames[:] = []
        if "package.json" in filenames:
            try:
                with open(os.path.join(dirpath, "package.json"), encoding="utf-8") as fh:
                    pkg = json.load(fh)
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    deps.update((pkg.get(key) or {}).keys())
            except (OSError, ValueError, AttributeError):
                continue
    return deps


def _scan_signatures(files: List[str], ext: Tuple[str, ...], max_files: int = 40) -> str:
    """Concatenate the heads of up to *max_files* files for signature matching."""
    buf = []
    count = 0
    for f in files:
        if not f.endswith(ext):
            continue
        buf.append(_read(f)[:2000])
        count += 1
        if count >= max_files:
            break
    return "\n".join(buf)


def framework_for(path: str, frameworks: Dict[str, str]) -> str:
    """Map a single file to its analyzer framework string."""
    if path.endswith(PHP_EXT):
        return frameworks.get("php") or "php-native"
    if path.endswith(PY_EXT):
        return frameworks.get("python") or "python-native"
    if path.endswith(JS_EXT):
        return frameworks.get("node") or "node-native"
    return ""
