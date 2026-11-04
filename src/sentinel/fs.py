"""The only host-read policy for files inside a scan target.

Callers pass a relative candidate. Absolute paths, NUL, backslashes, and
``..`` are refused before the operating system walks them. Directory symlinks
are not followed. A file symlink is opened only when every hop stays inside
the resolved root. After ``open``, the descriptor inode must match the
``lstat`` that authorized it; a mismatch returns no bytes.
"""

from __future__ import annotations

import errno
import os
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path

_READ_FLAGS = os.O_RDONLY
if hasattr(os, "O_NOFOLLOW"):
    _READ_FLAGS |= os.O_NOFOLLOW

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY
if hasattr(os, "O_NOFOLLOW"):
    _DIR_FLAGS |= os.O_NOFOLLOW

_MAX_SYMLINK_HOPS = 8
_PERMISSION = frozenset({errno.EACCES, errno.EPERM})


@dataclass(frozen=True)
class OpenInsideResult:
    """Bytes from a file inside the root, or a refusal with no prefix."""

    data: bytes | None
    relative_posix: str | None
    limitation: str | None


@dataclass(frozen=True)
class _Outcome:
    data: bytes | None
    relative_posix: str | None
    limitation: str | None
    reason: str


def confined_directory_flags() -> int | None:
    """Flags for a confined directory open, or None when that open is impossible.

    Listing must use ``O_DIRECTORY`` and ``O_NOFOLLOW`` together. A platform
    without ``O_NOFOLLOW`` gets no path-based fallback.
    """

    if not hasattr(os, "O_NOFOLLOW"):
        return None
    return _DIR_FLAGS


def open_confined_directory(
    root: Path,
    relative: str,
    expected: tuple[int, int],
) -> tuple[int | None, str]:
    """Open one directory under ``root`` on a confined descriptor.

    ``expected`` is the ``(st_dev, st_ino)`` captured when the directory was
    accepted. The caller closes a returned descriptor. The reason is empty on
    success and otherwise one of ``symlink``, ``mismatch``, ``mismatch-root``,
    ``permission``, ``unreadable``, or ``unsupported``.
    """

    parts = tuple(part for part in relative.split("/") if part not in {"", "."})
    fd, reason = _open_dir_chain(root, parts)
    if fd is None:
        return None, reason
    try:
        got = os.fstat(fd)
    except OSError:
        os.close(fd)
        return None, "unreadable"
    if (got.st_dev, got.st_ino) != expected:
        os.close(fd)
        if not parts:
            return None, "mismatch-root"
        return None, "mismatch"
    return fd, ""


def open_inside(
    root: Path,
    candidate: Path | str,
    max_bytes: int | None = None,
) -> OpenInsideResult:
    """Read a file inside the resolved scan root, or refuse it."""
    if max_bytes is not None and max_bytes < 0:
        raise ValueError("max_bytes must be zero or greater")
    text = candidate.as_posix() if isinstance(candidate, Path) else candidate
    relative, refusal = _normalize_candidate(text)
    if refusal is not None:
        return _public(_refuse(refusal))
    try:
        root_real = Path(os.path.realpath(root))
    except OSError:
        return _public(_fail("unreadable", ""))
    if not root_real.is_dir():
        return _public(_fail("unreadable", ""))
    return _public(_read_relative(root_real, relative, max_bytes, hops=0))


def _read_relative(
    root_real: Path,
    relative: str,
    max_bytes: int | None,
    *,
    hops: int,
) -> _Outcome:
    if hops > _MAX_SYMLINK_HOPS:
        return _fail("hop", relative)
    parts = tuple(relative.split("/")) if relative else ()
    if any(part in {"", ".", ".."} for part in parts):
        return _fail("empty", "")
    parent, reason = _open_dir_chain(root_real, parts[:-1])
    if parent is None:
        mapped = _chain_reason(reason)
        return _fail(mapped, relative, max_bytes)
    try:
        return _read_final(root_real, parent, parts, relative, max_bytes, hops)
    finally:
        os.close(parent)


def _read_final(
    root_real: Path,
    parent_fd: int,
    parts: tuple[str, ...],
    relative: str,
    max_bytes: int | None,
    hops: int,
) -> _Outcome:
    final = parts[-1]
    try:
        info = os.lstat(final, dir_fd=parent_fd)
    except OSError as exc:
        return _fail(_errno_reason(exc, missing="unreadable"), relative)
    if stat.S_ISLNK(info.st_mode):
        return _follow_symlink(root_real, relative, max_bytes, hops)
    if stat.S_ISDIR(info.st_mode):
        return _fail("unreadable", relative)
    if not stat.S_ISREG(info.st_mode):
        return _fail("unusual", relative)
    if max_bytes is not None and info.st_size > max_bytes:
        return _fail("size", relative, max_bytes)
    try:
        file_fd = os.open(final, _READ_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return _fail("mismatch", relative)
        return _fail(_errno_reason(exc, missing="unreadable"), relative)
    try:
        try:
            got = os.fstat(file_fd)
        except OSError:
            return _fail("unreadable", relative)
        if (got.st_dev, got.st_ino) != (info.st_dev, info.st_ino):
            return _fail("mismatch", relative)
        if max_bytes is not None and got.st_size > max_bytes:
            return _fail("size", relative, max_bytes)
        data = _read_capped(file_fd, max_bytes)
    finally:
        os.close(file_fd)
    if data is None:
        return _fail("size", relative, max_bytes)
    return _ok(data, relative)


def _follow_symlink(
    root_real: Path,
    relative: str,
    max_bytes: int | None,
    hops: int,
) -> _Outcome:
    if hops >= _MAX_SYMLINK_HOPS:
        return _fail("hop", relative)
    kind, file_relative, used = _chase_symlink(root_real, relative, _MAX_SYMLINK_HOPS - hops)
    if kind == "file" and file_relative is not None:
        followed = _read_relative(root_real, file_relative, max_bytes, hops=hops + used)
        return _retag(followed, relative, max_bytes)
    if kind == "dir":
        return _fail("dir", relative)
    return _fail(kind, relative, max_bytes)


def _chase_symlink(root_real: Path, relative: str, budget: int) -> tuple[str, str | None, int]:
    """Follow symlinks without reading file bytes. ``budget`` counts readlinks."""
    current = relative
    used = 0
    while True:
        kind, target = _lstat_kind(root_real, current)
        if kind != "symlink":
            if kind == "file":
                return "file", current, used
            return kind, None, used
        if used >= budget:
            return "hop", None, used
        if target is None:
            return "broken", None, used
        used += 1
        nxt, reason = _link_destination(root_real, current, target)
        if nxt is None:
            return reason, None, used
        current = nxt


def _lstat_kind(root_real: Path, relative: str) -> tuple[str, str | None]:
    parts = tuple(relative.split("/"))
    fd, reason = _open_dir_chain(root_real, parts[:-1])
    if fd is None:
        if reason == "symlink":
            return "dir", None
        if reason == "mismatch":
            return "mismatch", None
        return reason, None
    try:
        try:
            info = os.lstat(parts[-1], dir_fd=fd)
        except OSError as exc:
            return _errno_reason(exc, missing="broken"), None
        if stat.S_ISLNK(info.st_mode):
            try:
                target = os.readlink(parts[-1], dir_fd=fd)
            except OSError as exc:
                return _errno_reason(exc, missing="broken"), None
            return "symlink", target
        if stat.S_ISDIR(info.st_mode):
            return "dir", None
        if stat.S_ISREG(info.st_mode):
            return "file", None
        return "unusual", None
    finally:
        os.close(fd)


def _link_destination(
    root_real: Path,
    current: str,
    link_target: str,
) -> tuple[str | None, str]:
    if "\x00" in link_target or "\\" in link_target:
        return None, "broken"
    parent = tuple(current.split("/")[:-1])
    if link_target.startswith("/"):
        return _absolute_link(root_real, link_target)
    lexical = _lexical_join(parent, link_target)
    if lexical is None:
        return _escaped_link(root_real, parent, link_target)
    if lexical == "":
        return None, "dir"
    return lexical, ""


def _absolute_link(root_real: Path, link_target: str) -> tuple[str | None, str]:
    norm = os.path.normpath(link_target)
    root_text = os.path.normpath(os.fspath(root_real))
    if norm == root_text:
        return None, "dir"
    prefix = root_text + os.sep
    if norm.startswith(prefix):
        relative = norm[len(prefix) :].replace(os.sep, "/")
        if relative and all(part not in {"", ".", ".."} for part in relative.split("/")):
            return relative, ""
    return _escaped_link(root_real, (), link_target)


def _escaped_link(
    root_real: Path,
    parent_parts: tuple[str, ...],
    link_target: str,
) -> tuple[str | None, str]:
    if link_target.startswith("/"):
        full: Path = Path(link_target)
    else:
        full = root_real.joinpath(*parent_parts) / link_target
    try:
        real = Path(os.path.realpath(full, strict=True))
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, "hop"
        if exc.errno == errno.ENOENT:
            loose = Path(os.path.realpath(full))
            return _missing_resolved(root_real, loose)
        if exc.errno in _PERMISSION:
            return None, "permission"
        return None, "unreadable"
    return _relative_or_outside(root_real, real)


def _missing_resolved(root_real: Path, loose: Path) -> tuple[str | None, str]:
    try:
        relative = loose.relative_to(root_real)
    except ValueError:
        return None, "outside"
    if not relative.parts:
        return None, "dir"
    return None, "broken"


def _relative_or_outside(root_real: Path, real: Path) -> tuple[str | None, str]:
    try:
        relative = real.relative_to(root_real)
    except ValueError:
        return None, "outside"
    if not relative.parts:
        return None, "dir"
    return "/".join(relative.parts), ""


def _open_dir_chain(root_real: Path, dir_parts: tuple[str, ...]) -> tuple[int | None, str]:
    """Open ``root_real / dir_parts`` without following a directory symlink.

    Each segment's descriptor inode is compared with the ``lstat`` taken just
    before ``open``. The caller closes a successful descriptor.
    """

    flags = confined_directory_flags()
    if flags is None:
        return None, "unsupported"
    try:
        fd = os.open(root_real, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, "symlink"
        return None, _errno_reason(exc, missing="unreadable")
    close_fd = True
    try:
        for segment in dir_parts:
            try:
                info = os.lstat(segment, dir_fd=fd)
            except OSError as exc:
                return None, _errno_reason(exc, missing="unreadable")
            if stat.S_ISLNK(info.st_mode):
                return None, "symlink"
            if not stat.S_ISDIR(info.st_mode):
                return None, "unreadable"
            try:
                child = os.open(segment, flags, dir_fd=fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    return None, "symlink"
                return None, _errno_reason(exc, missing="unreadable")
            os.close(fd)
            fd = child
            try:
                got = os.fstat(fd)
            except OSError:
                return None, "unreadable"
            if (got.st_dev, got.st_ino) != (info.st_dev, info.st_ino):
                return None, "mismatch"
        close_fd = False
        return fd, ""
    finally:
        if close_fd:
            os.close(fd)


def _lexical_join(parent_parts: tuple[str, ...], link_target: str) -> str | None:
    """Join one relative link target. ``""`` is the root. None escapes it."""
    raw = [part for part in link_target.split("/") if part not in {"", "."}]
    stack = list(parent_parts)
    for part in raw:
        if part == "..":
            if not stack:
                return None
            stack.pop()
            continue
        stack.append(part)
    if not stack:
        return ""
    return "/".join(stack)


def _read_capped(fd: int, max_bytes: int | None) -> bytes | None:
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(fd, 65536)
        if not block:
            break
        total += len(block)
        if max_bytes is not None and total > max_bytes:
            return None
        chunks.append(block)
    return b"".join(chunks)


def _normalize_candidate(text: str) -> tuple[str, str | None]:
    if "\x00" in text:
        return "", "refused NUL in path"
    if "\\" in text:
        return "", "refused backslash in path"
    if text.startswith("/") or (len(text) >= 2 and text[1] == ":" and text[0].isalpha()):
        return "", "refused absolute path"
    normalized = unicodedata.normalize("NFC", text)
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", "."}:
        return "", "refused empty path"
    parts = normalized.split("/")
    if any(part == ".." for part in parts):
        return "", "refused parent segment"
    if any(part == "" for part in parts):
        return "", "refused empty path"
    cleaned = [part for part in parts if part != "."]
    if not cleaned:
        return "", "refused empty path"
    return "/".join(cleaned), None


def _nfc(relative: str) -> str:
    return unicodedata.normalize("NFC", relative)


def _chain_reason(reason: str) -> str:
    if reason == "symlink":
        return "dir"
    if reason == "mismatch-root":
        return "mismatch"
    if reason == "unsupported":
        return "unreadable"
    return reason or "unreadable"


def _errno_reason(exc: OSError, *, missing: str) -> str:
    if exc.errno == errno.ENOENT:
        return missing
    if exc.errno == errno.ELOOP:
        return "hop"
    if exc.errno in _PERMISSION:
        return "permission"
    return "unreadable"


def _ok(data: bytes, relative: str) -> _Outcome:
    return _Outcome(data, _nfc(relative), None, "")


def _fail(reason: str, relative: str, max_bytes: int | None = None) -> _Outcome:
    text = _limitation_text(reason, relative, max_bytes)
    return _Outcome(None, None, text, reason)


def _refuse(limitation: str) -> _Outcome:
    return _Outcome(None, None, limitation, "lexical")


def _limitation_text(reason: str, relative: str, max_bytes: int | None) -> str:
    if reason == "outside":
        return f"skipped symlink outside target: {relative}"
    if reason == "broken":
        return f"skipped broken symlink: {relative}"
    if reason == "hop":
        return f"refused symlink hop limit: {relative}"
    if reason == "permission":
        return f"permission denied: {relative}"
    if reason == "unusual":
        return f"refused non-regular file: {relative}"
    if reason == "dir":
        return f"refused directory symlink: {relative}"
    if reason == "mismatch":
        return f"refused inode mismatch: {relative}"
    if reason == "size" and max_bytes is not None:
        return f"read skipped, larger than {max_bytes} bytes: {relative}"
    if reason == "empty":
        return "refused empty path"
    if relative:
        return f"unreadable path: {relative}"
    return "unreadable path"


def _retag(outcome: _Outcome, relative: str, max_bytes: int | None) -> _Outcome:
    if outcome.data is not None:
        return _ok(outcome.data, relative)
    return _fail(outcome.reason or "unreadable", relative, max_bytes)


def _public(outcome: _Outcome) -> OpenInsideResult:
    return OpenInsideResult(outcome.data, outcome.relative_posix, outcome.limitation)


def classify_symlink(root: Path, relative: str) -> str:
    """Classify one symlink without reading file bytes.

    ``inside-file`` and ``inside-dir`` are strictly inside the resolved root.
    ``outside`` is only a target whose real path is outside the root.
    ``broken``, ``hop``, ``unusual``, ``permission``, and ``unreadable`` keep
    their own meanings. ``not-link`` means the final entry is not a symlink.
    """

    normalized, refusal = _normalize_candidate(relative if isinstance(relative, str) else "")
    if refusal is not None:
        return "unreadable"
    try:
        root_real = Path(os.path.realpath(root))
    except OSError:
        return "unreadable"
    if not root_real.is_dir():
        return "unreadable"
    kind, _target = _lstat_kind(root_real, normalized)
    if kind != "symlink":
        if kind in {"file", "dir", "unusual"}:
            return "not-link"
        return kind or "unreadable"
    chased, _file_relative, _used = _chase_symlink(root_real, normalized, _MAX_SYMLINK_HOPS)
    if chased == "file":
        return "inside-file"
    if chased == "dir":
        return "inside-dir"
    return chased
