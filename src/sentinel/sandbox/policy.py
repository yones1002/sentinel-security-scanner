"""Resource ceilings and the mount denylist for one container spec.

Values above a ceiling raise ``UsageError``. Nothing here clamps a value
or imports a Docker client.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from sentinel.errors import UsageError

MEM_LIMIT_DEFAULT = "512m"
MEM_LIMIT_CEILING = 2048
NANO_CPUS_DEFAULT = 1_000_000_000
NANO_CPUS_CEILING = 2_000_000_000
PIDS_LIMIT_DEFAULT = 256
PIDS_LIMIT_CEILING = 512
TIMEOUT_S_DEFAULT = 180
TIMEOUT_S_CEILING = 600
TMPFS_SIZE_DEFAULT = "128m"
TMPFS_SIZE_CEILING = 512

_EXACT_DENY = frozenset({
    "/",
    "/etc",
    "/usr",
    "/var",
    "/proc",
    "/sys",
    "/root",
    "/home",
})
_DENIED_NAMES = frozenset({".ssh", ".aws"})
_MIB = re.compile(r"^([1-9][0-9]*)m$")
_SECRET_KEY = re.compile(
    r"(?i)(SECRET|PASSWORD|TOKEN|CREDENTIAL|PRIVATE|AWS_|GITHUB_|SSH_|DATABASE_URL|DSN)"
)


def resolve_mem_limit(value: str | None) -> str:
    """Return the memory limit, or the default when ``value`` is omitted."""

    return _mebibytes(
        value,
        default=MEM_LIMIT_DEFAULT,
        ceiling=MEM_LIMIT_CEILING,
        label="mem_limit",
    )


def resolve_tmpfs_size(value: str | None) -> str:
    """Return the tmpfs size, or the default when ``value`` is omitted."""

    return _mebibytes(
        value,
        default=TMPFS_SIZE_DEFAULT,
        ceiling=TMPFS_SIZE_CEILING,
        label="tmpfs_size",
    )


def resolve_nano_cpus(value: int | None) -> int:
    """Return the CPU quota, or the default when ``value`` is omitted."""

    return _bounded_int(
        value,
        default=NANO_CPUS_DEFAULT,
        ceiling=NANO_CPUS_CEILING,
        label="nano_cpus",
    )


def resolve_pids_limit(value: int | None) -> int:
    """Return the process-id ceiling, or the default when ``value`` is omitted."""

    return _bounded_int(
        value,
        default=PIDS_LIMIT_DEFAULT,
        ceiling=PIDS_LIMIT_CEILING,
        label="pids_limit",
    )


def resolve_timeout_s(value: int | None) -> int:
    """Return the wall-clock budget, or the default when ``value`` is omitted."""

    return _bounded_int(
        value,
        default=TIMEOUT_S_DEFAULT,
        ceiling=TIMEOUT_S_CEILING,
        label="timeout_s",
    )


def tmpfs_options(size: str) -> str:
    """Build the ``/tmp`` mount options. ``noexec`` is always present."""

    return f"rw,nosuid,nodev,noexec,size={size}"


def checked_root(root: Path) -> Path:
    """Resolve ``root`` or refuse a denylisted mount source.

    A project directory inside the operator's home is allowed. The home
    directory itself is not. A path is refused when any component is
    ``docker.sock``.
    """

    if _denied(root):
        raise UsageError("refused mount root")
    try:
        resolved = root.resolve()
        home = Path.home().resolve()
    except OSError as exc:
        raise UsageError("refused mount root") from exc
    if resolved == home or _denied(resolved):
        raise UsageError("refused mount root")
    return resolved


def sandbox_env(
    extra: Mapping[str, str] | None,
    *,
    allow_secret_env: bool,
) -> tuple[tuple[str, str], ...]:
    """Return ``HOME`` and ``PORT``, then the operator pairs.

    The host environment is not copied. A denied key raises unless
    ``allow_secret_env`` is true.
    """

    pairs: list[tuple[str, str]] = [("HOME", "/tmp"), ("PORT", "8080")]
    if not extra:
        return tuple(pairs)
    for key, value in extra.items():
        if not allow_secret_env and _secret_key(key, value):
            raise UsageError(f"refused environment key: {key}")
        pairs.append((key, value))
    return tuple(pairs)


def _mebibytes(value: str | None, *, default: str, ceiling: int, label: str) -> str:
    chosen = default if value is None else value
    if not isinstance(chosen, str):
        raise UsageError(f"{label} is not a mebibyte size")
    match = _MIB.fullmatch(chosen)
    if match is None:
        raise UsageError(f"{label} is not a mebibyte size")
    if int(match.group(1)) > ceiling:
        raise UsageError(f"{label} is outside the ceiling")
    return chosen


def _bounded_int(value: int | None, *, default: int, ceiling: int, label: str) -> int:
    chosen = default if value is None else value
    if isinstance(chosen, bool) or not isinstance(chosen, int):
        raise UsageError(f"{label} is outside the ceiling")
    if chosen < 1 or chosen > ceiling:
        raise UsageError(f"{label} is outside the ceiling")
    return chosen


def _denied(path: Path) -> bool:
    if path.as_posix() in _EXACT_DENY:
        return True
    if path.name in _DENIED_NAMES:
        return True
    return "docker.sock" in path.parts


def _secret_key(key: str, value: str) -> bool:
    if _SECRET_KEY.search(key):
        return True
    return key.lower().endswith("_url") and "://" in value
