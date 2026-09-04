"""Code intake for the web app — uploads and remote repositories.

This is the untrusted edge of the system. Everything scanned here arrives from
whoever is holding the browser, so the threat model is not "will the scanner
find the crypto" but "can the archive make us write outside the workspace, read
/etc/shadow through a symlink, or fill the disk". Each of those is handled
explicitly below rather than delegated to `ZipFile.extractall`, which does none
of it.

Extracted trees are *kept*, not deleted. `cbom-compass verify` re-reads findings
from the artefact on disk to prove they were not fabricated, and that guarantee
disappears if the tree is thrown away the moment the scan finishes. Retention is
bounded by `prune_workspace`.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# --- Limits ---------------------------------------------------------------
# Chosen to comfortably hold a real service repository while refusing an
# archive bomb. A 42 KB zip that expands to 4.5 PB is a real artefact; the
# declared size in the central directory is attacker-controlled, so the ceiling
# below is enforced against bytes actually read, not against what the header
# claims.
MAX_UPLOAD_BYTES = 200 * 1024 * 1024        # compressed payload accepted
MAX_EXTRACTED_BYTES = 800 * 1024 * 1024     # total written to disk
MAX_ENTRIES = 40_000                        # files per archive
MAX_MEMBER_BYTES = 64 * 1024 * 1024         # any single file
MAX_REPO_BYTES = 800 * 1024 * 1024          # checkout size after clone
CLONE_TIMEOUT_SECONDS = 180

ARCHIVE_SUFFIXES = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".whl", ".jar"}

# Only hosts that serve public source control. An arbitrary git URL is an SSRF
# primitive: `git clone http://169.254.169.254/...` and ext:: / file:: helpers
# both reach places a scan request has no business reaching.
ALLOWED_GIT_HOSTS = {"github.com", "www.github.com", "gitlab.com", "www.gitlab.com",
                     "bitbucket.org", "www.bitbucket.org", "codeberg.org"}

# Dots are legal in repository names ("requests.git", "docs.rs"), so the
# character class alone would admit "." and ".." — path traversal against the
# host — and a leading "-" would make the segment look like a command-line flag
# to anything that later splits the URL. Both are excluded explicitly.
_REPO_SEGMENT = re.compile(r"^(?!-)(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$")
_SLUG = re.compile(r"[^a-z0-9]+")

DEFAULT_WORKSPACE = Path(".cbom-workspace")


class IngestError(ValueError):
    """Rejected input. The message is safe to show the user verbatim."""


@dataclass
class Ingested:
    """A tree on local disk that is ready to hand to the scanners."""
    root: Path
    label: str          # human-readable origin, e.g. "github.com/psf/requests"
    kind: str           # "upload" | "repo"
    file_count: int
    byte_count: int


# --- Workspace ------------------------------------------------------------

def resolve_workspace(workspace: Path | str | None = None) -> Path:
    """Where trees go, without touching the filesystem.

    Kept separate from `workspace_dir` so that importing the API does not
    create a directory as a side effect of module import.
    """
    return Path(workspace or os.environ.get("CBOM_WORKSPACE") or DEFAULT_WORKSPACE)


def workspace_dir(workspace: Path | str | None = None) -> Path:
    root = resolve_workspace(workspace)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _slug(text: str, fallback: str = "source") -> str:
    out = _SLUG.sub("-", text.lower()).strip("-")
    return out[:40] or fallback


def _new_tree(workspace: Path, label: str) -> Path:
    tree = workspace / f"{_slug(label)}-{uuid.uuid4().hex[:8]}"
    tree.mkdir(parents=True)
    return tree


def prune_workspace(workspace: Path | str | None = None, keep: int = 20) -> int:
    """Drop all but the `keep` most recent trees. Returns how many were removed."""
    root = resolve_workspace(workspace)
    if not root.is_dir():
        return 0
    trees = sorted((p for p in root.iterdir() if p.is_dir()),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    removed = 0
    for stale in trees[keep:]:
        shutil.rmtree(stale, ignore_errors=True)
        removed += 1
    return removed


# --- Shared safety helpers ------------------------------------------------

def _safe_member_path(root: Path, name: str) -> Path:
    """Resolve an archive member against the root, refusing anything that escapes.

    Covers absolute paths, `..` traversal, Windows drive letters and backslash
    separators, all of which appear in real malicious archives.
    """
    if not name or name in (".", "/"):
        raise IngestError("archive contains an unnamed entry")
    cleaned = name.replace("\\", "/")
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        raise IngestError(f"archive entry uses an absolute path: {name!r}")
    parts = [p for p in cleaned.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise IngestError(f"archive entry escapes the extraction root: {name!r}")
    target = (root / Path(*parts)).resolve()
    if target != root.resolve() and root.resolve() not in target.parents:
        raise IngestError(f"archive entry escapes the extraction root: {name!r}")
    return target


def _write_member(target: Path, source: io.BufferedIOBase, budget: list[int]) -> int:
    """Stream one member to disk, enforcing the per-file and total ceilings.

    The budget is checked against bytes actually read so a lying header buys
    nothing.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with open(target, "wb") as out:
        while True:
            chunk = source.read(64 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_MEMBER_BYTES:
                raise IngestError(
                    f"'{target.name}' exceeds the {MAX_MEMBER_BYTES // (1024 * 1024)} MB "
                    f"per-file limit")
            budget[0] -= len(chunk)
            if budget[0] < 0:
                raise IngestError(
                    f"archive expands beyond the "
                    f"{MAX_EXTRACTED_BYTES // (1024 * 1024)} MB limit — refusing to "
                    f"continue (possible decompression bomb)")
            out.write(chunk)
    return written


def _tree_size(root: Path) -> tuple[int, int]:
    files = total = 0
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        files += 1
        total += path.stat().st_size
    return files, total


def strip_symlinks(root: Path) -> int:
    """Remove every symlink under `root`.

    The scanners walk with `rglob` and `is_file()`, which follows links. A
    checkout containing `config -> /etc/shadow` would otherwise be read and
    quoted back as evidence.
    """
    removed = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            path.unlink(missing_ok=True)
            removed += 1
    return removed


# --- Uploads --------------------------------------------------------------

def _extract_zip(data: bytes, dest: Path) -> None:
    budget = [MAX_EXTRACTED_BYTES]
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError(f"not a readable zip archive: {exc}") from exc
    entries = archive.infolist()
    if len(entries) > MAX_ENTRIES:
        raise IngestError(f"archive holds {len(entries)} entries, over the "
                          f"{MAX_ENTRIES} limit")
    for info in entries:
        if info.is_dir():
            continue
        # Unix mode lives in the top 16 bits of external_attr for archives
        # written by zip(1); a symlink member must never be materialised.
        if stat.S_ISLNK(info.external_attr >> 16):
            continue
        target = _safe_member_path(dest, info.filename)
        with archive.open(info) as member:
            _write_member(target, member, budget)


def _extract_tar(data: bytes, dest: Path) -> None:
    budget = [MAX_EXTRACTED_BYTES]
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as exc:
        # tarfile reports every codec it tried, across several lines. The user
        # needs one sentence, not the decoder's diary.
        raise IngestError("this file is not a readable archive — expected a zip "
                          "or tar (.zip, .tar, .tar.gz, .tgz)") from exc
    with archive:
        count = 0
        for member in archive:
            if not member.isfile():          # skips dirs, symlinks, devices, FIFOs
                continue
            count += 1
            if count > MAX_ENTRIES:
                raise IngestError(f"archive holds more than {MAX_ENTRIES} entries")
            target = _safe_member_path(dest, member.name)
            source = archive.extractfile(member)
            if source is None:
                continue
            _write_member(target, source, budget)


def ingest_upload(data: bytes, filename: str,
                  workspace: Path | str | None = None) -> Ingested:
    """Accept an uploaded archive or single source file.

    Archives are expanded; anything else is stored as a one-file tree so a
    developer can check a single module without zipping it first.
    """
    if not data:
        raise IngestError("the uploaded file is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise IngestError(f"upload is {len(data) // (1024 * 1024)} MB, over the "
                          f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit")

    name = Path(filename or "upload").name or "upload"
    tree = _new_tree(workspace_dir(workspace), Path(name).stem)
    try:
        suffixes = {s.lower() for s in Path(name).suffixes}
        if zipfile.is_zipfile(io.BytesIO(data)):
            _extract_zip(data, tree)
        elif ".zip" in suffixes:
            raise IngestError(f"'{name}' is named as a zip but its contents are not a "
                              f"readable zip archive")
        elif suffixes & ARCHIVE_SUFFIXES:
            _extract_tar(data, tree)
        else:
            # Not an archive: keep it as a one-file tree so a single module can
            # be checked without zipping it first.
            _write_member(tree / name, io.BytesIO(data), [MAX_EXTRACTED_BYTES])
        strip_symlinks(tree)
        files, total = _tree_size(tree)
        if files == 0:
            raise IngestError("nothing readable was extracted from the upload")
    except Exception:
        shutil.rmtree(tree, ignore_errors=True)
        raise
    return Ingested(root=tree, label=name, kind="upload",
                    file_count=files, byte_count=total)


# --- Repositories ---------------------------------------------------------

def normalise_repo_url(raw: str) -> tuple[str, str]:
    """Validate a repository reference. Returns (clone_url, label).

    Accepts `owner/name`, `github.com/owner/name`, and full https URLs
    including deep links such as `/tree/main/src`. Everything else is refused:
    this string becomes an argument to `git clone`.
    """
    text = (raw or "").strip()
    if not text:
        raise IngestError("enter a repository URL")
    if len(text) > 400:
        raise IngestError("repository URL is too long")
    if "@" in text.split("://")[-1].split("/")[0]:
        raise IngestError("credentials in the URL are not accepted — public "
                          "repositories only")

    if "://" in text:
        parsed = urlparse(text)
        if parsed.scheme not in ("http", "https"):
            raise IngestError(f"scheme '{parsed.scheme}' is not allowed — use https")
        host = parsed.hostname or ""
        path = parsed.path
    elif text.count("/") == 1:
        host, path = "github.com", "/" + text
    else:
        host, _, path = text.partition("/")
        path = "/" + path

    host = host.lower()
    if host not in ALLOWED_GIT_HOSTS:
        raise IngestError(
            f"'{host}' is not an allowed host. Public repositories on "
            f"{', '.join(sorted({h for h in ALLOWED_GIT_HOSTS if not h.startswith('www.')}))} "
            f"only.")

    segments = [s for s in path.split("/") if s]
    if len(segments) < 2:
        raise IngestError("expected a repository path like owner/name")
    owner, name = segments[0], segments[1]
    if name.endswith(".git"):
        name = name[:-4]
    for segment in (owner, name):
        if not _REPO_SEGMENT.match(segment):
            raise IngestError(f"'{segment}' is not a valid repository path segment")

    host = host.removeprefix("www.")
    return f"https://{host}/{owner}/{name}.git", f"{host}/{owner}/{name}"


def ingest_repo(url: str, workspace: Path | str | None = None,
                timeout: int = CLONE_TIMEOUT_SECONDS) -> Ingested:
    """Shallow-clone a public repository into the workspace."""
    clone_url, label = normalise_repo_url(url)
    tree = _new_tree(workspace_dir(workspace), label.replace("/", "-"))

    # A hostile repository can carry a .gitmodules pointing anywhere and a
    # config with core.fsmonitor set to a shell command, so submodules stay off
    # and the ambient git config is not read. core.symlinks=false makes git
    # write link targets as plain text files instead of real symlinks.
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",     # never block waiting for credentials
        "GIT_ASKPASS": "",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_ALLOW_PROTOCOL": "https",
    }
    command = ["git", "-c", "core.symlinks=false", "-c", "protocol.ext.allow=never",
               "clone", "--depth", "1", "--single-branch", "--no-tags",
               "--recurse-submodules=no", "--quiet", clone_url, str(tree)]
    try:
        done = subprocess.run(command, env=env, timeout=timeout,
                              capture_output=True, text=True)
    except FileNotFoundError:
        shutil.rmtree(tree, ignore_errors=True)
        raise IngestError("git is not installed on this server") from None
    except subprocess.TimeoutExpired:
        shutil.rmtree(tree, ignore_errors=True)
        raise IngestError(f"cloning {label} took longer than {timeout}s") from None

    if done.returncode != 0:
        shutil.rmtree(tree, ignore_errors=True)
        detail = (done.stderr or "").strip().splitlines()
        hint = detail[-1] if detail else "clone failed"
        low = hint.lower()
        # GitHub answers 401 for both a private repo and one that does not
        # exist, so git falls through to asking for a username. With prompts
        # disabled that surfaces as a credentials error, which would be a
        # misleading thing to show someone who simply mistyped the name.
        if any(k in low for k in ("could not read username", "authentication failed",
                                  "terminal prompts disabled", "not found",
                                  "repository does not exist")):
            raise IngestError(f"{label} was not found. It must exist and be public — "
                              f"private repositories are not supported.")
        if "resolve host" in low or "connect to" in low:
            raise IngestError(f"could not reach {label} — the server has no network access "
                              f"to that host")
        raise IngestError(f"could not clone {label}: {hint[:200]}")

    shutil.rmtree(tree / ".git", ignore_errors=True)   # history is not scanned
    strip_symlinks(tree)
    files, total = _tree_size(tree)
    if total > MAX_REPO_BYTES:
        shutil.rmtree(tree, ignore_errors=True)
        raise IngestError(f"{label} checks out at {total // (1024 * 1024)} MB, over the "
                          f"{MAX_REPO_BYTES // (1024 * 1024)} MB limit")
    if files == 0:
        shutil.rmtree(tree, ignore_errors=True)
        raise IngestError(f"{label} contains no readable files")
    return Ingested(root=tree, label=label, kind="repo",
                    file_count=files, byte_count=total)
