"""The only host-read policy for files inside a scan target.

Callers pass a relative candidate. Absolute paths, NUL, backslashes, and
``..`` are refused before the operating system walks them. Directory symlinks
are not followed. A file symlink is opened only when every hop stays inside
the resolved root.
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


@dataclass(frozen=True)
class OpenInsideResult:
    """Bytes from a file inside the root, or a refusal with no prefix."""

    data: bytes | None
    relative_posix: str | None
    limitation: str | None


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
        return _refuse(refusal)
    try:
        root_real = Path(os.path.realpath(root))
    except OSError:
        return _refuse("unreadable path")
    if not root_real.is_dir():
        return _refuse("unreadable path")
    return _read_relative(root_real, relative, max_bytes, hops=0)


def _read_relative(
    root_real: Path,
    relative: str,
    max_bytes: int | None,
    *,
    hops: int,
) -> OpenInsideResult:
    if hops > _MAX_SYMLINK_HOPS:
        return _refuse(f"skipped symlink outside target: {relative}")
    parts = tuple(relative.split("/")) if relative else ()
    if any(part in {"", ".", ".."} for part in parts):
        return _refuse("refused empty path")
    try:
        root_fd = os.open(root_real, _DIR_FLAGS)
    except OSError:
        return _refuse("unreadable path")
    try:
        return _read_from_root(root_real, root_fd, parts, relative, max_bytes, hops)
    finally:
        os.close(root_fd)


def _read_from_root(
    root_real: Path,
    root_fd: int,
    parts: tuple[str, ...],
    relative: str,
    max_bytes: int | None,
    hops: int,
) -> OpenInsideResult:
    parent_fd = root_fd
    opened: list[int] = []
    try:
        for segment in parts[:-1]:
            try:
                info = os.lstat(segment, dir_fd=parent_fd)
            except OSError:
                return _refuse(f"unreadable path: {relative}")
            if stat.S_ISLNK(info.st_mode):
                return _refuse(f"refused directory symlink: {relative}")
            if not stat.S_ISDIR(info.st_mode):
                return _refuse(f"unreadable path: {relative}")
            try:
                parent_fd = os.open(segment, _DIR_FLAGS, dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    return _refuse(f"refused directory symlink: {relative}")
                return _refuse(f"unreadable path: {relative}")
            opened.append(parent_fd)
        final = parts[-1]
        try:
            info = os.lstat(final, dir_fd=parent_fd)
        except OSError:
            return _refuse(f"unreadable path: {relative}")
        if stat.S_ISLNK(info.st_mode):
            return _follow_symlink(
                root_real, parent_fd, parts[:-1], final, relative, max_bytes, hops
            )
        if stat.S_ISDIR(info.st_mode):
            return _refuse(f"unreadable path: {relative}")
        if not stat.S_ISREG(info.st_mode):
            return _refuse(f"unreadable path: {relative}")
        if max_bytes is not None and info.st_size > max_bytes:
            return _refuse(f"read skipped, larger than {max_bytes} bytes: {relative}")
        try:
            file_fd = os.open(final, _READ_FLAGS, dir_fd=parent_fd)
        except OSError:
            return _refuse(f"unreadable path: {relative}")
        try:
            data = _read_capped(file_fd, max_bytes)
        finally:
            os.close(file_fd)
        if data is None:
            return _refuse(f"read skipped, larger than {max_bytes} bytes: {relative}")
        return OpenInsideResult(data, _nfc(relative), None)
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _follow_symlink(
    root_real: Path,
    parent_fd: int,
    parent_parts: tuple[str, ...],
    name: str,
    relative: str,
    max_bytes: int | None,
    hops: int,
) -> OpenInsideResult:
    try:
        link_target = os.readlink(name, dir_fd=parent_fd)
    except OSError:
        return _refuse(f"skipped symlink outside target: {relative}")
    if "\x00" in link_target or "\\" in link_target:
        return _refuse(f"skipped symlink outside target: {relative}")
    if link_target.startswith("/"):
        inside = _absolute_target_inside(root_real, link_target)
    else:
        inside = _lexical_join(parent_parts, link_target)
        if inside is not None:
            real_inside = _confirm_real_inside(root_real, parent_parts, link_target)
            if real_inside is None:
                inside = None
            else:
                inside = real_inside
    if inside is None or inside == "":
        return _refuse(f"skipped symlink outside target: {relative}")
    if _is_directory(root_real, inside):
        return _refuse(f"refused directory symlink: {relative}")
    followed = _read_relative(root_real, inside, max_bytes, hops=hops + 1)
    if followed.data is None:
        if (
            followed.limitation
            and followed.limitation.startswith("read skipped")
            and max_bytes is not None
        ):
            return _refuse(f"read skipped, larger than {max_bytes} bytes: {relative}")
        return _refuse(f"skipped symlink outside target: {relative}")
    return OpenInsideResult(followed.data, _nfc(relative), None)


def _is_directory(root_real: Path, relative: str) -> bool:
    try:
        info = os.lstat(root_real.joinpath(*relative.split("/")))
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode)


def _absolute_target_inside(root_real: Path, link_target: str) -> str | None:
    try:
        real = Path(os.path.realpath(link_target))
        relative = real.relative_to(root_real)
    except (OSError, ValueError):
        return None
    if relative.parts == ():
        return None
    return "/".join(relative.parts)


def _confirm_real_inside(
    root_real: Path,
    parent_parts: tuple[str, ...],
    link_target: str,
) -> str | None:
    parent = root_real.joinpath(*parent_parts)
    try:
        real = Path(os.path.realpath(parent / link_target))
        relative = real.relative_to(root_real)
    except (OSError, ValueError):
        return None
    if relative.parts == ():
        return None
    return "/".join(relative.parts)


def _lexical_join(parent_parts: tuple[str, ...], link_target: str) -> str | None:
    raw = [part for part in link_target.split("/") if part not in {"", "."}]
    stack = list(parent_parts)
    for part in raw:
        if part == "..":
            if not stack:
                return None
            stack.pop()
            continue
        if part in {"", "."}:
            continue
        stack.append(part)
    if not stack:
        return None
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


def _refuse(limitation: str) -> OpenInsideResult:
    return OpenInsideResult(None, None, limitation)


def classify_symlink(root: Path, relative: str) -> str:
    """Classify one symlink without reading file bytes.

    ``inside-file`` and ``inside-dir`` are strictly inside the resolved root.
    ``outside`` covers an escaping target, a broken link, the root itself, and
    a path this module would refuse. ``not-link`` means the final entry is not
    a symlink. Intermediate directory symlinks are not followed.
    """
    normalized, refusal = _normalize_candidate(relative if isinstance(relative, str) else "")
    if refusal is not None:
        return "outside"
    try:
        root_real = Path(os.path.realpath(root))
    except OSError:
        return "outside"
    if not root_real.is_dir():
        return "outside"
    kind = _symlink_kind(root_real, normalized)
    return kind


def _symlink_kind(root_real: Path, relative: str) -> str:
    parts = tuple(relative.split("/"))
    try:
        root_fd = os.open(root_real, _DIR_FLAGS)
    except OSError:
        return "outside"
    parent_fd = root_fd
    opened = [root_fd]
    try:
        for segment in parts[:-1]:
            try:
                info = os.lstat(segment, dir_fd=parent_fd)
            except OSError:
                return "outside"
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                return "outside"
            try:
                parent_fd = os.open(segment, _DIR_FLAGS, dir_fd=parent_fd)
            except OSError:
                return "outside"
            opened.append(parent_fd)
        final = parts[-1]
        try:
            info = os.lstat(final, dir_fd=parent_fd)
        except OSError:
            return "outside"
        if not stat.S_ISLNK(info.st_mode):
            return "not-link"
        try:
            link_target = os.readlink(final, dir_fd=parent_fd)
        except OSError:
            return "outside"
    finally:
        for fd in reversed(opened):
            os.close(fd)
    if "\x00" in link_target or "\\" in link_target:
        return "outside"
    if link_target.startswith("/"):
        inside = _absolute_target_inside(root_real, link_target)
    else:
        inside = _lexical_join(parts[:-1], link_target)
        if inside is not None:
            real_inside = _confirm_real_inside(root_real, parts[:-1], link_target)
            inside = real_inside
    if inside is None or inside == "":
        return "outside"
    try:
        target_info = os.lstat(root_real.joinpath(*inside.split("/")))
    except OSError:
        return "outside"
    if stat.S_ISDIR(target_info.st_mode):
        return "inside-dir"
    if stat.S_ISREG(target_info.st_mode):
        return "inside-file"
    return "outside"
