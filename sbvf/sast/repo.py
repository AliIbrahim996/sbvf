"""Remote repository acquisition for the static analyzer.

The SAST entry points (dashboard and ``sbvf.scan_code``) accept either a local
folder or the URL of a *remote repository*. Remote repositories are restricted to
the three public code hosts below (plus any self-hosted hosts an operator adds
via ``SBVF_EXTRA_GIT_HOSTS`` -- e.g. an internal GitLab), fetched with a shallow
``git clone`` into a temporary folder, scanned, and deleted afterwards.

Safety measures applied to every clone:

* only ``https://`` URLs on ``github.com``, ``gitlab.com``, ``bitbucket.org``
  or a host listed in ``SBVF_EXTRA_GIT_HOSTS`` (an optional ``www.`` prefix is
  tolerated);
* no credentials, ports, query strings or SSH/``file://``/``ext::`` transports;
* web-UI URLs (``.../tree/main``, ``.../-/blob/...``, ``.../src/...``) are
  normalised to the repository's clone URL, and every path segment is validated;
* ``git`` runs non-interactively (no credential prompt for private repos), with
  only the https protocol allowed, ``--`` before the URL (no option injection),
  symlinks checked out as plain files (they cannot point the scanner outside the
  clone), no submodules, and a timeout.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.parse

# host -> human name. Matched exactly (after stripping an optional "www.").
ALLOWED_HOSTS = {"github.com": "GitHub", "gitlab.com": "GitLab",
                 "bitbucket.org": "Bitbucket"}

# Built-in hosts that use flat "owner/repo" paths. Every other accepted host
# (gitlab.com and self-hosted hosts) is parsed GitLab-style: nested groups and
# a "/-/" web-UI separator.
_OWNER_REPO_HOSTS = {"github.com", "bitbucket.org"}

_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")
# A conservative hostname (at least one dot, no scheme/port/path).
_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


class RepoURLError(ValueError):
    """The text is not an accepted remote-repository URL."""


def _extra_hosts() -> dict:
    """Self-hosted git hosts added via the ``SBVF_EXTRA_GIT_HOSTS`` env var.

    The value is a comma/semicolon/space-separated list of hostnames (e.g.
    ``gitlab.corp.example.com`` for an internal GitLab). They are validated as
    hostnames, parsed GitLab-style, and -- like the built-ins -- cloned over
    https only. Returns ``{host: host}`` (the host doubles as its display name).
    """
    out = {}
    for tok in re.split(r"[,;\s]+", os.environ.get("SBVF_EXTRA_GIT_HOSTS", "")):
        h = tok.strip().lower()
        if h.startswith("www."):
            h = h[4:]
        if h and h not in ALLOWED_HOSTS and _HOSTNAME.match(h):
            out[h] = h
    return out


def allowed_hosts() -> dict:
    """The effective accepted hosts: the built-ins plus ``SBVF_EXTRA_GIT_HOSTS``."""
    return {**ALLOWED_HOSTS, **_extra_hosts()}


def is_repo_url(text: str) -> bool:
    """True if *text* looks like a remote URL (as opposed to a local folder)."""
    t = (text or "").strip().lower()
    return "://" in t or t.startswith("git@") or t.startswith(
        tuple(h + "/" for h in allowed_hosts())) or t.startswith("www.")


def normalize_repo_url(text: str) -> str:
    """Validate *text* and return the canonical ``https://host/owner/repo.git``.

    Raises :class:`RepoURLError` with a user-facing message otherwise.
    """
    raw = (text or "").strip()
    if raw.lower().startswith("git@"):
        raise RepoURLError("SSH URLs are not supported; paste the https:// URL instead")
    if "://" not in raw:                         # "github.com/owner/repo"
        raw = "https://" + raw
    p = urllib.parse.urlparse(raw)
    if p.scheme.lower() != "https":
        raise RepoURLError("only https:// repository URLs are accepted")
    if p.username or p.password:
        raise RepoURLError("URLs containing credentials are not accepted")
    try:
        port = p.port
    except ValueError:
        port = -1
    if port is not None:
        raise RepoURLError("URLs with an explicit port are not accepted")
    host = (p.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host not in allowed_hosts():
        raise RepoURLError(
            "only GitHub, GitLab and Bitbucket repositories (or a host listed in "
            f"SBVF_EXTRA_GIT_HOSTS) are supported (got '{host or raw}')")

    segs = [s for s in urllib.parse.unquote(p.path).split("/") if s]
    if host in _OWNER_REPO_HOSTS:                 # GitHub/Bitbucket: owner/repo
        segs = segs[:2]
    else:                                         # GitLab-style (incl. self-hosted)
        if "-" in segs:                           # .../group/sub/repo/-/tree/main
            segs = segs[:segs.index("-")]
    if segs and segs[-1].endswith(".git"):
        segs[-1] = segs[-1][:-4]
    if len(segs) < 2:
        raise RepoURLError(f"expected https://{host}/<owner>/<repository>")
    for s in segs:
        if not _SEGMENT.match(s) or ".." in s:
            raise RepoURLError(f"invalid repository path segment '{s}'")
    return f"https://{host}/{'/'.join(segs)}.git"


# A conservative git branch name: letters/digits and . _ / - only, no leading
# dash (so it can't be read as a git option) and no "..".
_BRANCH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/-]*$")


def clone_repo(url: str, timeout: int = 300, all_branches: bool = False) -> str:
    """Shallow-clone an accepted repository URL into a new temp dir; return it.

    The caller owns the directory and should delete it with :func:`remove_tree`.
    Raises :class:`RepoURLError` for a rejected URL and ``RuntimeError`` if the
    clone fails (not found, private, network error, timeout).

    With *all_branches* the clone fetches the shallow tip of **every** branch
    (``--no-single-branch``) so :func:`list_branches` can offer them and
    :func:`checkout_branch` can switch to one without another network round trip;
    by default only the remote's default branch is fetched.
    """
    clean = normalize_repo_url(url)
    dest = tempfile.mkdtemp(prefix="sbvf_sast_")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never",
               GIT_ASKPASS="echo", SSH_ASKPASS="echo")
    branch_scope = "--no-single-branch" if all_branches else "--single-branch"
    cmd = ["git",
           "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
           "-c", "core.symlinks=false", "-c", "credential.helper=",
           "clone", "--depth", "1", branch_scope, "--no-tags",
           "--", clean, dest]
    try:
        subprocess.run(cmd, check=True, env=env, timeout=timeout,
                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True)
    except subprocess.TimeoutExpired:
        remove_tree(dest)
        raise RuntimeError(f"cloning {clean} timed out after {timeout}s")
    except subprocess.CalledProcessError as exc:
        remove_tree(dest)
        lines = [ln for ln in (exc.stderr or "").splitlines() if ln.strip()]
        detail = lines[-1].strip() if lines else f"exit code {exc.returncode}"
        raise RuntimeError(
            f"could not clone {clean} ({detail}). Is the repository public?")
    except FileNotFoundError:
        remove_tree(dest)
        raise RuntimeError("git is not installed or not on PATH")
    return dest


def _git(clone_dir: str, *args: str, timeout: int = 60):
    """Run ``git -C clone_dir <args>`` non-interactively and return the result."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never",
               GIT_ASKPASS="echo", SSH_ASKPASS="echo")
    return subprocess.run(["git", "-C", clone_dir, *args], check=True, env=env,
                          timeout=timeout, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def list_branches(clone_dir: str):
    """Return ``(branches, current)`` for a clone made with ``all_branches=True``.

    *branches* is the de-duplicated list of branch names (the ``origin/`` prefix
    stripped, ``HEAD`` dropped), *current* the checked-out branch. On any git
    failure returns ``([], "")`` so the caller can fall back to the default branch.
    """
    try:
        out = _git(clone_dir, "for-each-ref", "--format=%(refname:short)",
                   "refs/remotes/origin")
    except (subprocess.SubprocessError, OSError):
        return [], ""
    branches = []
    for line in out.stdout.splitlines():
        name = line.strip()
        # Skip the remote's symbolic HEAD, which shows up as "origin" or
        # "origin/HEAD" (and as "origin/HEAD -> origin/main" from `git branch -r`).
        if not name or name == "origin" or name.endswith("/HEAD") or "->" in name:
            continue
        if name.startswith("origin/"):
            name = name[len("origin/"):]
        if name and name != "HEAD":
            branches.append(name)
    seen = set()
    branches = [b for b in branches if not (b in seen or seen.add(b))]
    try:
        current = _git(clone_dir, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    except (subprocess.SubprocessError, OSError):
        current = ""
    if current and current not in branches:
        branches.insert(0, current)
    return branches, current


def checkout_branch(clone_dir: str, branch: str) -> None:
    """Check out *branch* in *clone_dir*. Validates the name first.

    Raises :class:`RepoURLError` for an unacceptable name and ``RuntimeError`` if
    git cannot switch to it.
    """
    if not branch or ".." in branch or not _BRANCH_RE.match(branch):
        raise RepoURLError(f"invalid branch name '{branch}'")
    try:
        _git(clone_dir, "checkout", branch, timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"checking out branch '{branch}' timed out")
    except subprocess.CalledProcessError as exc:
        lines = [ln for ln in (exc.stderr or "").splitlines() if ln.strip()]
        detail = lines[-1].strip() if lines else f"exit code {exc.returncode}"
        raise RuntimeError(f"could not check out branch '{branch}' ({detail})")
    except FileNotFoundError:
        raise RuntimeError("git is not installed or not on PATH")


def remove_tree(path: str) -> None:
    """Delete *path* recursively, clearing read-only bits (git objects on Windows)."""
    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    if path and os.path.isdir(path):
        shutil.rmtree(path, onerror=_onerror)
