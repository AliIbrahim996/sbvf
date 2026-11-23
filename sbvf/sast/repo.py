"""Remote repository acquisition for the static analyzer.

The SAST entry points (dashboard and ``sbvf.scan_code``) accept either a local
folder or the URL of a *remote repository*. Remote repositories are restricted to
the three public code hosts below, fetched with a shallow ``git clone`` into a
temporary folder, scanned, and deleted afterwards.

Safety measures applied to every clone:

* only ``https://`` URLs on exactly ``github.com``, ``gitlab.com`` or
  ``bitbucket.org`` (an optional ``www.`` prefix is tolerated);
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

_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*$")


class RepoURLError(ValueError):
    """The text is not an accepted remote-repository URL."""


def is_repo_url(text: str) -> bool:
    """True if *text* looks like a remote URL (as opposed to a local folder)."""
    t = (text or "").strip().lower()
    return "://" in t or t.startswith("git@") or t.startswith(
        tuple(h + "/" for h in ALLOWED_HOSTS)) or t.startswith("www.")


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
    if host not in ALLOWED_HOSTS:
        raise RepoURLError(
            "only GitHub, GitLab and Bitbucket repositories are supported "
            f"(got '{host or raw}')")

    segs = [s for s in urllib.parse.unquote(p.path).split("/") if s]
    if host == "gitlab.com":
        if "-" in segs:                           # .../group/sub/repo/-/tree/main
            segs = segs[:segs.index("-")]
    else:                                         # GitHub/Bitbucket: owner/repo
        segs = segs[:2]
    if segs and segs[-1].endswith(".git"):
        segs[-1] = segs[-1][:-4]
    if len(segs) < 2:
        raise RepoURLError(f"expected https://{host}/<owner>/<repository>")
    for s in segs:
        if not _SEGMENT.match(s) or ".." in s:
            raise RepoURLError(f"invalid repository path segment '{s}'")
    return f"https://{host}/{'/'.join(segs)}.git"


def clone_repo(url: str, timeout: int = 300) -> str:
    """Shallow-clone an accepted repository URL into a new temp dir; return it.

    The caller owns the directory and should delete it with :func:`remove_tree`.
    Raises :class:`RepoURLError` for a rejected URL and ``RuntimeError`` if the
    clone fails (not found, private, network error, timeout).
    """
    clean = normalize_repo_url(url)
    dest = tempfile.mkdtemp(prefix="sbvf_sast_")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never",
               GIT_ASKPASS="echo", SSH_ASKPASS="echo")
    cmd = ["git",
           "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
           "-c", "core.symlinks=false", "-c", "credential.helper=",
           "clone", "--depth", "1", "--single-branch", "--no-tags",
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
