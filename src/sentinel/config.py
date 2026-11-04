"""Scan configuration. In-repo policy keys never become engine fields."""

from __future__ import annotations

import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

from sentinel.errors import UsageError
from sentinel.fs import open_inside
from sentinel.models import Framework

_FAIL_ON = frozenset({"critical", "high", "medium", "low", "informational", "none"})
# Same ceiling as a manifest read. Over-cap input is refused with no partial parse.
_CONFIG_MAX_BYTES = 1_048_576
_IGNORED_IN_REPO = (
    "authorized",
    "allow_hosts",
    "start_command",
    "enable_entry_points",
    "ignore",
    "components",
    "confirm_ambiguous_reads",
)
_KNOWN_TOP_LEVEL = frozenset(_IGNORED_IN_REPO)
_COMPONENT_KEYS = frozenset({"path", "frameworks", "suppress"})
_IGNORE_KEYS = frozenset({"fingerprint", "reason"})


@dataclass(frozen=True)
class DetectLimits:
    """Walk ceilings. Hitting one records a limitation and does not raise."""

    max_files: int = 50_000
    max_directories: int = 20_000


@dataclass(frozen=True)
class ComponentOverride:
    """An external label. It does not create a component or a start plan."""

    path: str
    frameworks: tuple[Framework, ...]
    suppress: bool


@dataclass(frozen=True)
class IgnoreRule:
    """Stored for a later milestone. PR 4 does not apply it to findings."""

    fingerprint: str
    reason: str


@dataclass(frozen=True)
class Authorization:
    """True only when this invocation's argv included ``--authorized``."""

    attested: bool


@dataclass(frozen=True)
class ScanConfig:
    """What the engine reads. Argv and TOML parsing stay outside the engine."""

    detect: DetectLimits
    strict_tools: bool
    fail_on: str
    history: bool
    semgrep_config: Path | None
    component_overrides: tuple[ComponentOverride, ...]
    ignores: tuple[IgnoreRule, ...]
    confirm_ambiguous_reads: bool = False


@dataclass(frozen=True)
class LoadedConfig:
    """A config plus limitation lines produced while dropping in-repo policy.

    ``authorization`` is the argv attestation. A config file cannot set it.
    """

    config: ScanConfig
    limitations: tuple[str, ...]
    authorization: Authorization


def load_scan_config(
    config_path: Path | None,
    *,
    target: Path | None,
    attested: bool = False,
    strict_tools: bool = False,
    fail_on: str = "none",
    history: bool = False,
    semgrep_config: Path | None = None,
    confirm_ambiguous_reads: bool = False,
    detect: DetectLimits | None = None,
) -> LoadedConfig:
    """Load TOML when a path is given. Files inside the target cannot widen scope."""
    if not isinstance(attested, bool):
        raise UsageError("attested must be a boolean")
    if fail_on not in _FAIL_ON:
        raise UsageError(f"unknown fail_on value: {fail_on}")
    limits = detect if detect is not None else DetectLimits()
    if limits.max_files < 1 or limits.max_directories < 1:
        raise UsageError("detect ceilings must be at least 1")
    authorization = Authorization(attested=attested)
    base = ScanConfig(
        detect=limits,
        strict_tools=strict_tools,
        fail_on=fail_on,
        history=history,
        semgrep_config=semgrep_config,
        component_overrides=(),
        ignores=(),
        confirm_ambiguous_reads=confirm_ambiguous_reads,
    )
    if config_path is None:
        return LoadedConfig(base, (), authorization)
    data, inside = _read_config(config_path, target)
    unknown = sorted(set(data) - _KNOWN_TOP_LEVEL)
    if unknown:
        raise UsageError(f"unknown config key: {', '.join(unknown)}")
    if inside:
        present = [key for key in _IGNORED_IN_REPO if key in data]
        limitations = ()
        if present:
            limitations = (
                f"in-repo sentinel.toml attempted to set {', '.join(present)}; ignored",
            )
        return LoadedConfig(base, limitations, authorization)
    overrides = _component_overrides(data.get("components", []), target)
    ignores = _ignore_rules(data.get("ignore", []))
    config = ScanConfig(
        detect=base.detect,
        strict_tools=base.strict_tools,
        fail_on=base.fail_on,
        history=base.history,
        semgrep_config=base.semgrep_config,
        component_overrides=overrides,
        ignores=ignores,
        confirm_ambiguous_reads=confirm_ambiguous_reads,
    )
    return LoadedConfig(config, (), authorization)


def _read_config(config_path: Path, target: Path | None) -> tuple[dict[str, object], bool]:
    if target is not None and _is_inside(config_path, target):
        relative = config_path.resolve().relative_to(target.resolve()).as_posix()
        opened = open_inside(target.resolve(), relative, max_bytes=_CONFIG_MAX_BYTES)
        if opened.data is None:
            if opened.limitation and opened.limitation.startswith("read skipped"):
                raise UsageError("config file exceeds size limit")
            raise UsageError("config file cannot be read")
        try:
            parsed = tomllib.loads(opened.data.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise UsageError("malformed config") from exc
        if not isinstance(parsed, dict):
            raise UsageError("malformed config")
        return parsed, True
    try:
        raw = _read_bounded(config_path)
    except OSError as exc:
        raise UsageError("config file cannot be read") from exc
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise UsageError("malformed config") from exc
    if not isinstance(parsed, dict):
        raise UsageError("malformed config")
    return parsed, False


def _read_bounded(path: Path) -> bytes:
    """Read an outside config up to the cap. A longer file is not parsed."""
    with path.open("rb") as handle:
        data = handle.read(_CONFIG_MAX_BYTES + 1)
    if len(data) > _CONFIG_MAX_BYTES:
        raise UsageError("config file exceeds size limit")
    return data


def _is_inside(path: Path, target: Path) -> bool:
    try:
        path.resolve().relative_to(target.resolve())
    except (OSError, ValueError):
        return False
    return True


def _component_overrides(value: object, target: Path | None) -> tuple[ComponentOverride, ...]:
    if value == []:
        return ()
    if not isinstance(value, list):
        raise UsageError("components must be a table array")
    overrides: list[ComponentOverride] = []
    for item in value:
        if not isinstance(item, dict):
            raise UsageError("components must be a table array")
        unknown = sorted(set(item) - _COMPONENT_KEYS)
        if unknown:
            raise UsageError(f"unknown config key: {', '.join(unknown)}")
        path = item.get("path")
        if not isinstance(path, str) or path == "":
            raise UsageError("component path is required")
        if target is None or not _relative_exists(target, path):
            raise UsageError(f"component path does not exist: {path}")
        frameworks = _frameworks(item.get("frameworks", []))
        suppress = item.get("suppress", False)
        if not isinstance(suppress, bool):
            raise UsageError("suppress must be a boolean")
        overrides.append(
            ComponentOverride(path=path, frameworks=frameworks, suppress=suppress)
        )
    return tuple(overrides)


def _frameworks(value: object) -> tuple[Framework, ...]:
    if value == []:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise UsageError("unknown framework")
    found: list[Framework] = []
    for item in value:
        try:
            found.append(Framework(item))
        except ValueError as exc:
            raise UsageError(f"unknown framework: {item}") from exc
    return tuple(found)


def _ignore_rules(value: object) -> tuple[IgnoreRule, ...]:
    if value == []:
        return ()
    if not isinstance(value, list):
        raise UsageError("ignore must be a table array")
    rules: list[IgnoreRule] = []
    for item in value:
        if not isinstance(item, dict):
            raise UsageError("ignore must be a table array")
        unknown = sorted(set(item) - _IGNORE_KEYS)
        if unknown:
            raise UsageError(f"unknown config key: {', '.join(unknown)}")
        fingerprint = item.get("fingerprint")
        reason = item.get("reason")
        if (
            not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(char not in "0123456789abcdef" for char in fingerprint)
        ):
            raise UsageError("ignore fingerprint must be 64 lowercase hex characters")
        if not isinstance(reason, str) or reason == "":
            raise UsageError("ignore reason is required")
        rules.append(IgnoreRule(fingerprint=fingerprint, reason=reason))
    return tuple(rules)


def _relative_exists(target: Path, relative: str) -> bool:
    if "\x00" in relative or "\\" in relative or relative.startswith("/"):
        return False
    if any(part == ".." for part in relative.split("/")):
        return False
    normalized = relative
    while normalized.startswith("./"):
        normalized = normalized.removeprefix("./")
    if normalized in {"", "."}:
        try:
            info = target.resolve().lstat()
        except OSError:
            return False
        return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if not parts:
        return False
    current = target.resolve()
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(info.st_mode):
            return False
    return True
