"""Static taint analysis for Node.js source: native ``http``, Express and NestJS.

There is no JavaScript/TypeScript parser in the Python standard library, so --
as for PHP -- this module implements a pragmatic lexer (:func:`lex`) and runs a
scoped, flow-insensitive taint analysis over the statements it produces.

The lexer understands what matters for taint tracking in real code:

* ``//`` and ``/* */`` comments (line numbers preserved), string literals,
  template literals with nested ``${ ... }`` expressions, and regex literals
  (told apart from division by the preceding token);
* statements ended by ``;`` or by a newline under JavaScript's automatic
  semicolon insertion (continuation lines such as ``.then(...)`` are joined);
* **blocks** versus **object literals**: a ``{`` after ``)``, ``=>``, a class
  header, ``else``/``try``/... opens a block (a new scope); anything else is an
  object literal and stays inside the current statement;
* decorators (``@Controller('users')``, ``@Get(':id')``), attached to the class
  or method that follows -- which is how NestJS routes are recognised.

Every block records its header, so each statement knows its enclosing function,
class and -- for Express -- the inline route callback it belongs to
(``app.get('/search', (req, res) => { ... })``).

Taint model
-----------
* **Sources** -- Express/Node ``req.query|params|body|cookies|headers|url``,
  ``req.get()/header()/param()``; NestJS parameter decorators ``@Query('q') q``,
  ``@Param()``, ``@Body()``, ``@Headers()`` and ``@Req() req``.
* **Propagation** -- assignments (incl. ``+=``, TypeScript annotations and
  object/array destructuring such as ``const { q } = req.query``), within the
  function scope and visible to nested closures.
* **Sinks** -- SQL (``db.query``, ``knex.raw``, ``whereRaw``,
  ``$queryRawUnsafe`` ... with a *dynamically built* query string), OS commands
  (``child_process.exec``), code evaluation (``eval``, ``new Function``,
  ``vm``), file paths (``fs.*``, ``res.sendFile``), SSRF (``axios``, ``fetch``),
  open redirect (``res.redirect``, ``Location`` header) and XSS (``res.send``,
  ``res.write``, ``res.end``, and strings returned by a NestJS route handler,
  which Nest serves as ``text/html``).
* **Sanitizers** -- ``escape``/``escapeHtml``/``encodeURIComponent``/
  ``validator.*``/``DOMPurify.sanitize``/``parseInt``/``Number``/
  ``path.basename``/``mysql.escape`` ...; parameterized queries are not flagged
  because their query text is a constant.

Limitations (documented as threats to validity): heuristic lexer, intra-file
analysis, no type information, and ``.jsx``/``.tsx`` front-end files are not
analysed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .model import Finding

# .jsx/.tsx are front-end components: JSX text (e.g. "Don't") breaks string
# lexing and holds no server-side request handling, so they are not analysed.
JS_EXT = (".js", ".mjs", ".cjs", ".ts")

# --- lexer ----------------------------------------------------------------------

_CONTROL = re.compile(
    r"^(?:\}\s*)?(?:else\b|if\b|for\b|while\b|switch\b|try\b|catch\b|finally\b|do\b|with\b)")
_CLASS = re.compile(
    r"^(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:abstract\s+)?class\b\s*([A-Za-z_$][\w$]*)?")
_TYPE_BLOCK = re.compile(       # interface X / enum X / namespace X / declare module 'x'
    r"^(?:export\s+)?(?:declare\s+)?(?:const\s+)?(?:interface|enum|namespace|module)\s+[\w$'\"]")
_FUNC_NAMED = re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(")
_ASSIGNED_FN = re.compile(
    r"(?:(?:const|let|var)\s+|(?:module\.)?exports\.|this\.)?([A-Za-z_$][\w$]*)\s*[:=]\s*"
    r"(?:async\s+)?(?:function\b|\([^()]*\)\s*(?::[^=]+)?=>|[A-Za-z_$][\w$]*\s*=>)")
_METHOD = re.compile(
    r"^(?:(?:public|private|protected|static|async|override|readonly|get|set)\s+)*\*?\s*"
    r"([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\(", re.S)
ROUTE_VERBS = ("get", "post", "put", "delete", "patch", "all", "options", "head")
_ROUTE_CALL = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*(" + "|".join(ROUTE_VERBS) +
    r")\s*\(\s*(['\"`])([^'\"`]*)\3")
_ROUTE_CHAIN = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(\s*(['\"`])([^'\"`]*)\2\s*\)"
    r"(?:\s*\.\s*\w+\s*\((?:[^()]|\([^()]*\))*\))*\s*\.\s*(" + "|".join(ROUTE_VERBS) + r")\s*\(")
# Objects with .get(url, cb) that are HTTP *clients*, not route registrations.
_NOT_ROUTERS = {"axios", "http", "https", "request", "got", "needle", "superagent",
                "client", "fetch", "$", "jQuery", "cy", "map", "cache", "headers"}
_REGEX_KEYWORDS = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
                   "void", "throw", "yield", "await", "instanceof"}
_DECORATOR = re.compile(r"@[A-Za-z_$][\w$.]*\s*(?:\((?:.|\n)*\))?")


@dataclass(eq=False)
class Block:
    """A ``{ ... }`` block: function/method body, class body, control block..."""
    header: str
    line: int
    kind: str                           # function | class | control | other
    name: str = ""                      # function/method/class name if any
    decorators: List[str] = field(default_factory=list)
    route: Optional[Tuple[str, str, str]] = None   # (router var, VERB, path)
    params: List[str] = field(default_factory=list)  # callback parameter names
    parent: Optional["Block"] = None

    @property
    def route_key(self) -> str:
        return f"@L{self.line}" if self.route else ""

    def function(self) -> Optional["Block"]:
        """Nearest enclosing function block (self included), or None."""
        b = self
        while b is not None and b.kind != "function":
            b = b.parent
        return b


@dataclass(eq=False)
class Stmt:
    line: int
    text: str
    block: Optional[Block]
    decorators: List[str] = field(default_factory=list)
    is_header: bool = False


def _skip_string(src: str, i: int) -> int:
    quote, j, n = src[i], i + 1, len(src)
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == quote:
            return j + 1
        if c == "\n":            # unterminated: recover at end of line
            return j
        j += 1
    return n


def _skip_template(src: str, i: int) -> int:
    j, n = i + 1, len(src)
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            return j + 1
        if c == "$" and src.startswith("{", j + 1):
            j = _skip_expr(src, j + 2)
            continue
        j += 1
    return n


def _skip_expr(src: str, j: int) -> int:
    """Skip a ``${ ... }`` expression body; return the index after its ``}``."""
    depth, n = 1, len(src)
    while j < n:
        c = src[j]
        if c in "'\"":
            j = _skip_string(src, j)
            continue
        if c == "`":
            j = _skip_template(src, j)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


def _skip_regex(src: str, i: int) -> int:
    """End index of a regex literal starting at *i*, or 0 if it is not one."""
    j, n, in_class = i + 1, len(src), False
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return 0
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "/":
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            return j
        j += 1
    return 0


def split_decorators(text: str) -> Tuple[List[str], str]:
    """Split leading ``@Decorator(...)`` items off *text*: (decorators, rest)."""
    decos, i, n = [], 0, len(text)
    while True:
        while i < n and text[i].isspace():
            i += 1
        m = re.match(r"@[A-Za-z_$][\w$.]*", text[i:])
        if not m:
            return decos, text[i:]
        j = i + m.end()
        k = j
        while k < n and text[k] in " \t":
            k += 1
        if k < n and text[k] == "(":
            depth = 0
            while k < n:
                c = text[k]
                if c in "'\"":
                    k = _skip_string(text, k)
                    continue
                if c == "`":
                    k = _skip_template(text, k)
                    continue
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        k += 1
                        break
                k += 1
            j = k
        decos.append(text[i:j].strip())
        i = j


def route_of(header: str) -> Optional[Tuple[str, str, str]]:
    """(var, VERB, path) if *header* registers an Express route, else None."""
    m = _ROUTE_CHAIN.search(header)
    if m and m.group(1) not in _NOT_ROUTERS:
        return m.group(1), m.group(4).upper(), m.group(3)
    m = _ROUTE_CALL.search(header)
    if m and m.group(1) not in _NOT_ROUTERS and (m.group(4).startswith("/") or m.group(4) == "*"):
        return m.group(1), m.group(2).upper(), m.group(4)
    return None


def _callback_params(header: str) -> List[str]:
    """Parameter names of the function literal that ends *header*."""
    m = re.search(r"(?:function\s*\*?\s*[\w$]*\s*)?\(([^()]*)\)\s*(?::[^=()]*)?(?:=>)?\s*$", header)
    if not m:
        m2 = re.search(r"([A-Za-z_$][\w$]*)\s*=>\s*$", header)
        return [m2.group(1)] if m2 else []
    out = []
    for p in m.group(1).split(","):
        p = re.sub(r"@\w+\s*\([^)]*\)\s*", "", p).strip()
        p = re.sub(r"^(?:public|private|protected|readonly)\s+", "", p)
        mm = re.match(r"([A-Za-z_$][\w$]*)", p)
        if mm:
            out.append(mm.group(1))
    return out


def _classify(header: str, line: int, decorators: List[str], parent: Optional[Block]) -> Block:
    decos, h = split_decorators(header)
    decorators = decorators + decos
    h = h.strip()
    if not h or _CONTROL.match(h):
        return Block(header, line, "control", decorators=decorators, parent=parent)
    m = _CLASS.match(h)
    if m:
        return Block(header, line, "class", m.group(1) or "", decorators, parent=parent)
    if _TYPE_BLOCK.match(h):
        return Block(header, line, "other", decorators=decorators, parent=parent)
    is_fn = h.endswith("=>") or re.search(r"\bfunction\b", h) or (
        re.search(r"\)\s*(?::[^=;]*)?$", h) and _METHOD.match(h))
    if not is_fn:
        return Block(header, line, "other", decorators=decorators, parent=parent)
    route = route_of(h)
    name = ""
    m = _FUNC_NAMED.search(h)
    if m:
        name = m.group(1)
    elif not route:
        m = _ASSIGNED_FN.search(h)
        if m:
            name = m.group(1)
        else:
            m = _METHOD.match(h)
            if m and not h.endswith("=>"):
                name = m.group(1)
    return Block(header, line, "function", name, decorators, route,
                 _callback_params(h), parent)


def lex(src: str) -> Tuple[List[Stmt], List[Block]]:
    """Split JS/TS *src* into statements (with their enclosing blocks)."""
    stmts: List[Stmt] = []
    blocks: List[Block] = []
    n, i, line = len(src), 0, 1
    buf: List[str] = []
    st = {"start": 1, "started": False}
    depth = 0
    braces: list = []          # ("obj",) | ("block", saved_depth, parent_block)
    block: Optional[Block] = None
    pending: List[str] = []

    if src.startswith("#!"):
        while i < n and src[i] != "\n":
            i += 1

    def mark():
        if not st["started"]:
            st["start"], st["started"] = line, True

    def take() -> Tuple[int, str]:
        t, ln = "".join(buf).strip(), st["start"]
        buf.clear()
        st["started"] = False
        return ln, t

    def emit():
        nonlocal pending
        ln, t = take()
        if not t:
            return
        if _DECORATOR.fullmatch(t):
            pending.append(t)
            return
        stmts.append(Stmt(ln, t, block, pending))
        pending = []

    def tail() -> str:
        return "".join(buf).rstrip()

    def regex_ctx() -> bool:
        t = tail()
        if not t:
            return True
        if t[-1] in "(,=:[!&|?{};+-*%<>~^":
            return True
        m = re.search(r"([A-Za-z_$][\w$]*)$", t)
        return bool(m and m.group(1) in _REGEX_KEYWORDS)

    def block_brace() -> bool:
        t = tail()
        if not t:
            return True
        _, core = split_decorators(t)
        core = core.strip()
        if t.endswith("=>") or t[-1] == ")":
            return True
        if re.search(r"(?:^|[^\w$.])(?:else|try|finally|do)$", t):
            return True
        if _CLASS.match(core) or _TYPE_BLOCK.match(core):
            return True
        if re.search(r"\)\s*:\s*[\w$.<>\[\]|&,\s]+$", t):      # ): Promise<T> {
            return True
        if re.match(r"^(?:case\b.*|default)\s*:$", t.split("\n")[-1].strip()):
            return True
        return False

    def complete(at: int) -> bool:
        t = tail()
        if not t or t[-1] in ",([{+-*/%=&|?:.<>!^~" or t.endswith("=>"):
            return False
        j = at + 1
        while j < n and src[j] in " \t\r\n":
            j += 1
        if j < n and src[j] in ".?:+*%&|=,)]>" or src.startswith("=>", j):
            return False
        if j < n and src[j] == "/" and not src.startswith(("//", "/*"), j):
            return False
        return True

    while i < n:
        ch = src[i]
        two = src[i:i + 2]
        if two == "//":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j
            line += src.count("\n", i, j)
            buf.append(" ")
            i = j + 2
            continue
        if ch in "'\"":
            mark()
            j = _skip_string(src, i)
            buf.append(src[i:j])
            line += src.count("\n", i, j)
            i = j
            continue
        if ch == "`":
            mark()
            j = _skip_template(src, i)
            buf.append(src[i:j])
            line += src.count("\n", i, j)
            i = j
            continue
        if ch == "/" and regex_ctx():
            j = _skip_regex(src, i)
            if j:
                mark()
                buf.append("/re/")
                i = j
                continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif ch == "{":
            if block_brace():
                hline, header = take()
                b = _classify(header, hline if header else line, pending, block)
                pending = []
                if header:
                    stmts.append(Stmt(hline, header, block, [], True))
                blocks.append(b)
                braces.append(("block", depth, block))
                block, depth = b, 0
                i += 1
                continue
            braces.append(("obj",))
            depth += 1
        elif ch == "}":
            if braces and braces[-1][0] == "block":
                emit()
                _, depth, block = braces.pop()
                i += 1
                continue
            if braces:
                braces.pop()
            depth = max(0, depth - 1)
        elif ch == ";" and depth == 0:
            emit()
            i += 1
            continue
        elif ch == "\n":
            line += 1
            if depth == 0 and complete(i):
                emit()
            else:
                buf.append(ch)
            i += 1
            continue
        if not ch.isspace():
            mark()
        buf.append(ch)
        i += 1
    emit()
    return stmts, blocks


def mask_strings(text: str) -> str:
    """Blank out string-literal contents (same length, so offsets stay valid).

    Template literals keep their ``${ ... }`` expressions, which are code. This
    stops an identifier inside a string -- ``'/app/products'`` -- from being
    mistaken for a use of the variable ``products``.
    """
    out, j, n = [], 0, len(text)
    while j < n:
        c = text[j]
        if c in "'\"":
            k = _skip_string(text, j)
            out.append(c + " " * max(0, k - j - 2) + (text[k - 1] if k - j >= 2 else ""))
            j = k
        elif c == "`":
            k = _skip_template(text, j)
            seg, p, buf = text[j:k], 0, []
            while p < len(seg):
                if seg.startswith("${", p):
                    e = _skip_expr(seg, p + 2)
                    buf.append("${" + mask_strings(seg[p + 2:e - 1]) + "}")
                    p = e
                else:
                    buf.append(seg[p] if seg[p] in "`\n" else " ")
                    p += 1
            out.append("".join(buf))
            j = k
        else:
            out.append(c)
            j += 1
    return "".join(out)


def split_args(text: str, open_idx: int) -> Tuple[int, List[Tuple[int, int]]]:
    """For the call whose ``(`` is at *open_idx*: (close_idx, [(start, end), ...])."""
    n, depth, j = len(text), 0, open_idx
    args, start = [], open_idx + 1
    while j < n:
        c = text[j]
        if c in "'\"":
            j = _skip_string(text, j)
            continue
        if c == "`":
            j = _skip_template(text, j)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                if text[start:j].strip():
                    args.append((start, j))
                return j, args
        elif c == "," and depth == 1:
            args.append((start, j))
            start = j + 1
        j += 1
    if text[start:].strip():
        args.append((start, n))
    return n, args


# --- taint analysis ---------------------------------------------------------------

_REQ_ATTRS = "query|params|body|files|file|cookies|signedCookies|headers|url|originalUrl|path"
_ATTR_METHOD = {"query": "GET", "params": "PATH", "body": "POST", "files": "POST",
                "file": "POST", "cookies": "COOKIE",
                "signedCookies": "COOKIE", "headers": "HEADER", "url": "GET",
                "originalUrl": "GET", "path": "PATH"}
_NEST_PARAM = re.compile(
    r"@(Query|Param|Body|Headers|Req|Request)\s*\(\s*(?:(['\"`])([^'\"`]*)\2)?[^)]*\)\s*"
    r"(?:(?:public|private|protected|readonly)\s+)*([A-Za-z_$][\w$]*)")
_NEST_METHOD = {"Query": "GET", "Param": "PATH", "Body": "POST", "Headers": "HEADER"}
NEST_ROUTE_DECOS = ("Get", "Post", "Put", "Delete", "Patch", "All", "Options", "Head")

_SANITIZER = re.compile(
    r"(?<![\w$])(?:escape|escapeHtml|escapeHTML|htmlEscape|encodeURIComponent|encodeURI|"
    r"xss|filterXSS|sanitize\w*|DOMPurify\s*\.\s*sanitize|"
    r"validator\s*\.\s*(?:escape|toInt|toFloat|isInt|isNumeric|isEmail|isUUID|isAlphanumeric)|"
    r"he\s*\.\s*(?:encode|escape)|_\s*\.\s*escape|lodash\s*\.\s*escape|parseInt|parseFloat|"
    r"Number|Boolean|path\s*\.\s*basename|basename|"
    r"(?:mysql|connection|conn|pool|db|SqlString|sqlstring)\s*\.\s*escape(?:Id)?|"
    r"shellEscape|shellescape)\s*\(")

_DB_RECV = (r"(?:[\w$]+\s*\.\s*)*[\w$]*(?:db|Db|DB|conn|Conn|connection|Connection|pool|Pool|"
            r"client|Client|database|Database|sql|Sql|knex|Knex|dataSource|DataSource|manager|"
            r"Manager|queryRunner|QueryRunner|prisma|sequelize|Sequelize|repository|Repository|"
            r"repo|Repo|sqlite|mysql|pg)")
_SQLI = re.compile(
    r"\b" + _DB_RECV + r"\s*\.\s*(query|execute|raw|exec|all|get|run|each|prepare|"
    r"\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(|"
    r"\.\s*(whereRaw|orWhereRaw|havingRaw|orderByRaw|joinRaw|selectRaw|fromRaw|"
    r"\$queryRawUnsafe|\$executeRawUnsafe)\s*\(")
_CMD = re.compile(
    r"\b(?:child_process|childProcess|cp|proc)\s*\.\s*(exec|execSync)\s*\(|"
    r"\bshell\s*\.\s*(exec)\s*\(")
_CMD_SPAWN = re.compile(
    r"\b(?:child_process|childProcess|cp)\s*\.\s*(spawn|spawnSync|execFile|execFileSync)\s*\(")
_CMD_BARE = re.compile(r"(?<![\w$.])(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(")
_CODE = re.compile(
    r"(?<![\w$.])(eval)\s*\(|\bnew\s+(Function)\s*\(|"
    r"\bvm\s*\.\s*(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|"
    r"\bnew\s+vm\s*\.\s*(Script)\s*\(|"
    r"\b(?:mathjs|math)\s*\.\s*(eval|evaluate)\s*\(|"                 # math.js expression RCE
    r"\b(?:serialize|nodeSerialize|serializer)\s*\.\s*(unserialize)\s*\(")  # node-serialize RCE
_PATH = re.compile(
    r"\b(?:fs|fsp|fse|fs\s*\.\s*promises)\s*\.\s*(readFile|readFileSync|createReadStream|"
    r"writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|readdir|readdirSync|"
    r"rm|rmSync|open|openSync|createWriteStream|access|stat)\s*\(|"
    r"\b(?:res|response|resp)\s*\.\s*(sendFile|download)\s*\(")
_SSRF = re.compile(
    r"(?<![\w$.])(axios(?:\s*\.\s*(?:get|post|put|patch|delete|head|request))?|fetch|"
    r"got(?:\s*\.\s*(?:get|post))?|needle|superagent\s*\.\s*get|"
    r"https?\s*\.\s*(?:get|request))\s*\(")
_REDIRECT = re.compile(r"\b(?:res|response|resp)\s*\.\s*(redirect|location)\s*\(")
_RENDER = re.compile(r"\b(?:res|response|resp)\s*\.\s*render\s*\(")
_SET_HEADER = re.compile(r"\b(?:res|response|resp)\s*\.\s*(setHeader|set|header|writeHead)\s*\(")
_XSS = re.compile(
    r"\b(?:res|response|resp)(?:\s*\.\s*(?:status|type|set|header|cookie|vary|append)"
    r"\s*\((?:[^()]|\([^()]*\))*\))*\s*\.\s*(send|write|end)\s*\(")


class _Scope:
    def __init__(self, parent: Optional["_Scope"]):
        self.parent = parent
        self.tainted: Dict[str, str] = {}
        self.origin: Dict[str, Tuple[str, str]] = {}
        self.objsrc: Dict[str, str] = {}        # var -> method, e.g. q = req.query
        self.aliases = set()                    # extra names bound to the request

    def chain(self):
        s = self
        while s is not None:
            yield s
            s = s.parent

    def find(self, attr: str, var: str):
        for s in self.chain():
            d = getattr(s, attr)
            if var in d:
                return d[var]
        return None

    def names(self):
        out = {"req", "request"}
        for s in self.chain():
            out |= s.aliases
        return out


class JsAnalyzer:
    """Analyze one JS/TS file for a given framework (node-native/express/nestjs)."""

    def __init__(self, framework: str = "node-native"):
        self.framework = framework

    # --- public -----------------------------------------------------------------

    def analyze(self, rel_path: str, source: str,
                on_source: Optional[Callable] = None) -> List[Finding]:
        self._rel, self._on_source = rel_path, on_source
        self._lines = source.splitlines()
        self._has_cp = "child_process" in source
        self._scopes: Dict[Block, _Scope] = {}
        self._module = _Scope(None)
        self._rx_cache: Dict[Tuple[str, ...], tuple] = {}
        stmts, blocks = lex(source)
        self._seed(blocks)

        for _ in range(20):                       # propagate to a fixpoint
            changed = False
            for s in stmts:
                if not s.is_header and self._propagate(s.text, self._scope(s.block), s.line):
                    changed = True
            if not changed:
                break

        findings: List[Finding] = []
        self.template_flows: List[dict] = []
        for s in stmts:
            # headers too: `fs.readFile(p + req.query.f, (err, d) => {` holds a sink
            self._check(s, findings)
            self._record_render(s)
        return findings

    # --- server-side templates (EJS) -------------------------------------------

    def _record_render(self, s: Stmt):
        """Remember ``res.render('view', {...})`` calls that pass tainted values.

        The engine later opens the view and reports XSS if a tainted path is
        printed with EJS's unescaped ``<%- ... %>`` tag (``<%= %>`` escapes).
        """
        sc = self._scope(s.block)
        for m in _RENDER.finditer(s.text):
            _, spans = split_args(s.text, m.end() - 1)
            if len(spans) < 2:
                continue
            view = re.fullmatch(r"\s*(['\"`])([^'\"`]+)\1\s*", s.text[spans[0][0]:spans[0][1]])
            if not view:
                continue
            paths = self._tainted_paths(s.text[spans[1][0]:spans[1][1]], sc, "", 0)
            if paths:
                line = s.line + s.text[:m.start()].count("\n")
                self.template_flows.append({
                    "view": view.group(2), "paths": paths, "line": line,
                    "function": self._handler_key(s), "framework": self.framework,
                    "code": self._lines[line - 1] if 0 < line <= len(self._lines) else ""})

    def _tainted_paths(self, obj: str, sc: _Scope, prefix: str, depth: int):
        """[(dotted path, source, origin)] of tainted values in an object literal."""
        a, out = obj.strip(), []
        if not a.startswith("{") or depth > 3:
            return out
        _, spans = split_args(a, 0)
        for x, y in spans:
            prop = a[x:y].strip()
            m = re.match(r"(['\"]?)([A-Za-z_$][\w$]*)\1\s*:\s*(.+)$", prop, re.S)
            if m:
                key, val = m.group(2), m.group(3)
            elif re.fullmatch(r"[A-Za-z_$][\w$]*", prop):
                key = val = prop                          # shorthand { q }
            else:
                continue
            if val.strip().startswith("{"):
                out += self._tainted_paths(val, sc, f"{prefix}{key}.", depth + 1)
                continue
            src = self._taint_in(val, sc)
            if src:
                out.append((prefix + key, src, self._origin_in(val, sc)))
        return out

    # --- scopes and seeding -----------------------------------------------------

    def _scope(self, block: Optional[Block]) -> _Scope:
        fb = block.function() if block else None
        if fb is None:
            return self._module
        if fb not in self._scopes:
            self._scopes[fb] = _Scope(self._scope(fb.parent))
        return self._scopes[fb]

    def _seed(self, blocks: List[Block]):
        for b in blocks:
            if b.kind != "function":
                continue
            sc = self._scope(b)
            # Express/Node callbacks may name the request differently: (rq, rs) => ...
            if (b.route or re.search(r"createServer\s*\(", b.header)) and b.params \
                    and b.params[0] not in ("req", "request"):
                sc.aliases.add(b.params[0])
            for m in _NEST_PARAM.finditer(b.header):
                deco, key, var = m.group(1), m.group(3), m.group(4)
                if deco in ("Req", "Request"):
                    sc.aliases.add(var)
                    continue
                method = _NEST_METHOD[deco]
                desc = f"@{deco}({key!r})" if key else f"@{deco}()"
                sc.tainted[var] = desc
                if key:
                    sc.origin[var] = (key, method)
                else:
                    sc.objsrc[var] = method
                if self._on_source:
                    self._on_source(desc, b.line)

    # --- source / taint helpers -------------------------------------------------

    def _rx(self, sc: _Scope):
        names = tuple(sorted(sc.names()))
        if names not in self._rx_cache:
            alt = "|".join(re.escape(x) for x in names)
            self._rx_cache[names] = (
                re.compile(rf"(?<![\w$.])({alt})\s*\.\s*({_REQ_ATTRS})\b(?!\s*\()"),
                re.compile(rf"(?<![\w$.])({alt})\s*\.\s*(get|header|param)\s*\("),
                re.compile(rf"(?<![\w$.])({alt})\s*\.\s*(query|params|body|files|cookies|signedCookies|"
                           rf"headers)\s*(?:\??\.\s*([A-Za-z_$][\w$]*)|\[\s*(['\"`])([^'\"`]+)\4\s*\])"),
                re.compile(rf"(?<![\w$.])({alt})\s*\.\s*(get|header|param)\s*\(\s*(['\"`])([^'\"`]+)\3"),
                re.compile(rf"^(?:{alt})\s*\.\s*(query|params|body|cookies|signedCookies|headers)$"),
            )
        return self._rx_cache[names]

    def _sanitized(self, text: str, s: int, e: int) -> bool:
        for m in _SANITIZER.finditer(text):
            open_idx = m.end() - 1
            if open_idx < s:
                close, _ = split_args(text, open_idx)
                if e <= close:
                    return True
        return False

    def _is_use(self, text: str, s: int, e: int) -> bool:
        """False when the identifier at s..e is an object-literal key (``{ q: 1 }``)."""
        after = text[e:].lstrip()
        if after.startswith(":") and not after.startswith("::"):
            before = text[:s].rstrip()
            if before.endswith(("{", ",")):
                return False
        return True

    def _taint_in(self, text: str, sc: _Scope) -> Optional[str]:
        code = mask_strings(text)              # identifiers inside strings are not uses
        src_rx, call_rx = self._rx(sc)[:2]
        for rx in (src_rx, call_rx):
            for m in rx.finditer(code):
                if not self._sanitized(text, m.start(), m.end()):
                    return f"{m.group(1)}.{m.group(2)}"
        seen = set()
        for s in sc.chain():
            for var, desc in s.tainted.items():
                if var in seen:
                    continue
                seen.add(var)
                for m in re.finditer(rf"(?<![\w$.]){re.escape(var)}(?![\w$])", code):
                    if self._is_use(code, m.start(), m.end()) and \
                            not self._sanitized(text, m.start(), m.end()):
                        return desc
        return None

    def _origin_in(self, text: str, sc: _Scope) -> Optional[Tuple[str, str]]:
        """Best-effort (param, method) behind the taint in *text*."""
        cands = []
        keyed, call_keyed = self._rx(sc)[2:4]
        for m in keyed.finditer(text):
            cands.append((m.start(), (m.group(3) or m.group(5), _ATTR_METHOD[m.group(2)])))
        for m in call_keyed.finditer(text):
            meth = "REQUEST" if m.group(2) == "param" else "HEADER"
            cands.append((m.start(), (m.group(4), meth)))
        for m in re.finditer(r"searchParams\s*\.\s*get\s*\(\s*(['\"`])([^'\"`]+)\1", text):
            cands.append((m.start(), (m.group(2), "GET")))
        if re.search(r"\.\s*(?:url|originalUrl)\b", text):
            for m in re.finditer(r"\.\s*query\s*\.\s*([A-Za-z_$][\w$]*)", text):
                cands.append((m.start(), (m.group(1), "GET")))
        code = mask_strings(text)
        for s in sc.chain():
            for var, meth in s.objsrc.items():
                for m in re.finditer(rf"(?<![\w$.]){re.escape(var)}\s*(?:\??\.\s*([A-Za-z_$][\w$]*)|"
                                     rf"\[\s*(['\"`])([^'\"`]+)\2\s*\])", text):
                    if code[m.start()] == text[m.start()]:          # not inside a string
                        cands.append((m.start(), (m.group(1) or m.group(3), meth)))
            for var, ep in s.origin.items():
                for m in re.finditer(rf"(?<![\w$.]){re.escape(var)}(?![\w$])", code):
                    if self._is_use(code, m.start(), m.end()):
                        cands.append((m.start(), ep))
        return min(cands, key=lambda c: c[0])[1] if cands else None

    def _obj_source(self, rhs: str, sc: _Scope) -> Optional[str]:
        """Method if *rhs* is a whole request object (``req.query``) or alias of one."""
        rhs = re.sub(r"^\s*await\s+", "", rhs).strip()
        rhs = re.sub(r"\s+as\s+[\w$.<>\[\]|]+\s*$", "", rhs)
        rhs = re.sub(r"\s*(?:\|\||\?\?)\s*\{\s*\}\s*$", "", rhs).strip()
        m = self._rx(sc)[4].match(rhs)
        if m:
            return _ATTR_METHOD[m.group(1)]
        if re.fullmatch(r"[A-Za-z_$][\w$]*", rhs):
            return sc.find("objsrc", rhs)
        return None

    # --- propagation ------------------------------------------------------------

    def _taint_var(self, sc: _Scope, var: str, desc: str, ep, line: int) -> bool:
        changed = False
        if sc.find("tainted", var) is None:
            sc.tainted[var] = desc
            changed = True
            if self._on_source:
                self._on_source(desc, line)
        if ep and sc.find("origin", var) is None:
            sc.origin[var] = ep
            changed = True
        return changed

    def _propagate(self, text: str, sc: _Scope, line: int) -> bool:
        t = re.sub(r"^export\s+", "", text)
        m = re.match(r"^(?:const|let|var)\s*\{(.*?)\}\s*(?::[^=]+)?=\s*(.+)$", t, re.S)
        if m:
            return self._destructure(m.group(1), m.group(2), sc, line)
        m = re.match(r"^(?:const|let|var)\s*\[(.*?)\]\s*(?::[^=]+)?=\s*(.+)$", t, re.S)
        if m:
            src = self._taint_in(m.group(2), sc)
            changed = False
            if src and not _SQLI.search(m.group(2)):
                for v in re.findall(r"[A-Za-z_$][\w$]*", m.group(1)):
                    changed |= self._taint_var(sc, v, src, self._origin_in(m.group(2), sc), line)
            return changed
        m = re.match(r"^(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?\s*\+?=(?![=>])\s*(.+)$",
                     t, re.S)
        if not m:
            return False
        var, rhs = m.group(1), m.group(2)
        if re.match(r"^(?:async\s+)?(?:function\b|\([^()]*\)\s*=>)", rhs.strip()):
            return False                           # a function definition, not a value
        if _SQLI.search(rhs):
            return False                           # a query *result*, not the input itself
        changed = False
        objm = self._obj_source(rhs, sc)
        if objm and sc.find("objsrc", var) is None:
            sc.objsrc[var] = objm
            changed = True
        src = self._taint_in(rhs, sc)
        if src:
            changed |= self._taint_var(sc, var, src, self._origin_in(rhs, sc), line)
        return changed

    def _destructure(self, props: str, rhs: str, sc: _Scope, line: int) -> bool:
        objm = self._obj_source(rhs, sc)
        src = None if objm else self._taint_in(rhs, sc)
        if not objm and not src:
            return False
        if src and _SQLI.search(rhs):
            return False
        changed = False
        for p in props.split(","):
            p = p.strip()
            if not p:
                continue
            if p.startswith("..."):
                var = p[3:].strip()
                if objm and sc.find("objsrc", var) is None:
                    sc.objsrc[var] = objm
                    changed = True
                changed |= self._taint_var(sc, var, src or "request object", None, line)
                continue
            mm = re.match(r"([A-Za-z_$][\w$]*)\s*(?::\s*([A-Za-z_$][\w$]*))?\s*(?:=.*)?$", p, re.S)
            if not mm:
                continue
            key, var = mm.group(1), mm.group(2) or mm.group(1)
            if objm:
                changed |= self._taint_var(sc, var, f"request {objm} parameter '{key}'",
                                           (key, objm), line)
            else:
                changed |= self._taint_var(sc, var, src, self._origin_in(rhs, sc), line)
        return changed

    # --- sinks ------------------------------------------------------------------

    def _check(self, s: Stmt, findings: List[Finding]):
        t, sc = s.text, self._scope(s.block)

        def args_of(m):
            close, spans = split_args(t, m.end() - 1)
            return t[m.end() - 1:close + 1], [t[a:b] for a, b in spans]

        def emit(vuln, m, sink, src, region):
            return self._emit(findings, s, vuln, m, sink, src, region, sc)

        for m in _SQLI.finditer(t):                                   # SQL injection
            region, args = args_of(m)
            if args and self._dynamic(args[0]):
                src = self._taint_in(args[0], sc)
                if src:
                    return emit("sqli", m, self._sink_name(m), src, args[0])
        for m in _CMD.finditer(t):                                    # OS command
            region, args = args_of(m)
            src = self._taint_in(args[0], sc) if args else None
            if src:
                return emit("command_injection", m, self._sink_name(m), src, args[0])
        for rx in (_CMD_SPAWN, _CMD_BARE):
            for m in rx.finditer(t):
                if rx is _CMD_BARE and not self._has_cp:
                    continue
                region, args = args_of(m)
                if not args:
                    continue
                shell = m.group(1) in ("exec", "execSync") or re.search(r"shell\s*:\s*true", region)
                src = self._taint_in(args[0], sc) or (self._taint_in(region, sc) if shell else None)
                if src:
                    return emit("command_injection", m, m.group(1), src, region)
        for m in _CODE.finditer(t):                                   # code injection
            region, _ = args_of(m)
            src = self._taint_in(region, sc)
            if src:
                return emit("code_injection", m, self._sink_name(m), src, region)
        for m in _PATH.finditer(t):                                   # path traversal
            region, args = args_of(m)
            if m.group(2) and re.search(r"\broot\s*:", region):
                continue                    # res.sendFile(p, { root }) confines the path
            src = self._taint_in(args[0], sc) if args else None
            if src:
                return emit("path_traversal", m, self._sink_name(m), src, args[0])
        for m in _SSRF.finditer(t):                                   # SSRF
            region, args = args_of(m)
            src = self._taint_in(args[0], sc) if args else None
            if src:
                return emit("ssrf", m, re.sub(r"\s+", "", m.group(1)), src, args[0])
        for m in _REDIRECT.finditer(t):                               # open redirect
            region, _ = args_of(m)
            src = self._taint_in(region, sc)
            if src:
                return emit("open_redirect", m, "res." + m.group(1), src, region)
        for m in _SET_HEADER.finditer(t):
            region, args = args_of(m)
            if m.group(1) == "writeHead":
                hit = re.search(r"['\"]?location['\"]?\s*:", region, re.I) and \
                    self._taint_in(region, sc)
            else:
                hit = len(args) >= 2 and re.fullmatch(r"\s*['\"`]location['\"`]\s*", args[0], re.I) \
                    and self._taint_in(args[1], sc)
            if hit:
                return emit("open_redirect", m, "Location header", hit, region)
        for m in _XSS.finditer(t):                                    # reflected XSS
            region, args = args_of(m)
            if args and self._xss_arg(args[0], sc):
                return emit("xss", m, "res." + m.group(1), self._taint_in(args[0], sc), args[0])
        rm = re.match(r"return\s+(.+)$", t, re.S)                     # NestJS handler return
        if rm and not s.is_header and self._nest_route(s.block) \
                and self._builds_string(rm.group(1)):
            src = self._taint_in(rm.group(1), sc)
            if src:
                return emit("xss", rm, "return (Nest controller, text/html)", src, rm.group(1))

    def _dynamic(self, arg: str) -> bool:
        """True if a SQL text argument is built dynamically (not a constant/tagged)."""
        a = arg.strip()
        if re.match(r"^[A-Za-z_$][\w$.]*\s*`", a):
            return False                  # tagged template (sql`...`) -> parameterized
        if a.startswith("`"):
            return "${" in a
        if re.match(r"^(['\"])(?:\\.|(?!\1).)*\1$", a, re.S):
            return False                  # a single constant string literal
        return True

    @staticmethod
    def _builds_string(expr: str) -> bool:
        """True if *expr* is, at its top level, a string literal/template or a
        ``+`` concatenation involving one (i.e. it produces text, not a call's
        result such as a query row set)."""
        a = expr.strip().rstrip(";")
        if not a or a[0] in "{[":
            return False
        if a[0] in "'\"`":
            return True
        depth, j, n, has_str, has_plus = 0, 0, len(a), False, False
        while j < n:
            c = a[j]
            if c in "'\"`":
                if depth == 0:
                    has_str = True
                j = _skip_template(a, j) if c == "`" else _skip_string(a, j)
                continue
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == "+" and depth == 0:
                has_plus = True
            j += 1
        return has_str and has_plus

    def _xss_arg(self, arg: str, sc: _Scope) -> bool:
        a = arg.strip()
        if not a or a[0] in "{[":
            return False                  # objects/arrays are sent as JSON
        if not self._taint_in(a, sc):
            return False
        if self._builds_string(a):
            return True                   # HTML/text built around the tainted value
        if re.fullmatch(r"[A-Za-z_$][\w$]*", a):
            # a tainted variable: a request value (res.send(q)), but not a whole
            # request object such as req.query, which Express sends as JSON
            return sc.find("objsrc", a) is None
        return True                       # direct source / call on tainted input

    def _nest_route(self, block: Optional[Block]) -> bool:
        fb = block.function() if block else None
        if fb is None or not any(re.match(r"@(?:%s)\b" % "|".join(NEST_ROUTE_DECOS), d)
                                 for d in fb.decorators):
            return False
        if any(re.match(r"@Header\s*\(\s*['\"]content-type['\"]\s*,\s*['\"][^'\"]*json", d, re.I)
               for d in fb.decorators):
            return False
        cls = fb.parent
        while cls is not None and cls.kind != "class":
            cls = cls.parent
        return cls is not None and any(d.startswith("@Controller") for d in cls.decorators)

    @staticmethod
    def _sink_name(m) -> str:
        return re.sub(r"\s+", "", m.group(0)).rstrip("(")

    def _handler_key(self, s: Stmt) -> str:
        b = s.block
        while b is not None:
            if b.kind == "function":
                if b.route:
                    return b.route_key
                if b.name:
                    return b.name
            b = b.parent
        if route_of(s.text):              # app.get('/x', (req, res) => res.send(...))
            return f"@L{s.line}"
        return ""

    def _emit(self, findings, s: Stmt, vuln, m, sink, source, region, sc):
        line = s.line + s.text[:m.start()].count("\n")
        code = self._lines[line - 1] if 0 < line <= len(self._lines) else ""
        param, method = self._origin_in(region, sc) or ("", "GET")
        findings.append(Finding(
            vuln=vuln, file=self._rel, line=line, sink=sink, source=source,
            framework=self.framework, code=code, param=param, method=method,
            function=self._handler_key(s),
            message=f"Tainted value from {source} reaches {sink}."))
        if self._on_source:
            self._on_source(source, line)
