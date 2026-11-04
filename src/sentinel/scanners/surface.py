"""Filename and deployment-literal scanner.

Content is read only for the three literal rules, and only through
``open_inside``. Filename rules do not read file bytes. The engine stamps
``component_id`` and replaces the fingerprint.
"""

from __future__ import annotations

import os
import stat
import unicodedata
import uuid
from collections import deque
from collections.abc import Sequence
from pathlib import Path

from sentinel import __version__
from sentinel.config import DetectLimits
from sentinel.errors import ScanFailure
from sentinel.fingerprint import fingerprint
from sentinel.fs import open_confined_directory, open_inside
from sentinel.models import (
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Location,
    Recommendation,
    Severity,
)
from sentinel.protocols import (
    Component,
    ComponentScanTarget,
    ProbeResult,
    ScanContext,
    ScannerScope,
    ScanPluginResult,
)
from sentinel.recommendations import fallback_remediation, recommendation_for
from sentinel.redact import redact_snippet

_CONTENT_MAX = 1_048_576
_MAX_DEPTH = 8
_ENV = "sentinel.surface.env-file"
_KEY = "sentinel.surface.private-key-filename"
_VCS = "sentinel.surface.vcs-metadata"
_WP = "sentinel.surface.wp-config-in-tree"
_SOCK = "sentinel.surface.compose-docker-sock"
_PRIV = "sentinel.surface.compose-privileged"
_K8S = "sentinel.surface.k8s-host-network"
_WW = "sentinel.surface.world-writable"
_NEEDLES = {
    _SOCK: "docker.sock",
    _PRIV: "privileged: true",
    _K8S: "hostNetwork: true",
}
_COMPOSE_NAMES = frozenset({"docker-compose.yml", "compose.yml", "compose.yaml"})
_K8S_PARENTS = frozenset({"k8s", "kubernetes", "deploy"})
_ENV_EXCLUDED = frozenset({".env.example", ".env.sample"})
_KEY_SUFFIXES = (".pem", "id_rsa", "id_dsa", "id_ed25519")
SKIP_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        "venv",
        ".venv",
        "dist",
        "build",
        "target",
        "__pycache__",
        ".tox",
        ".eggs",
    }
)
_POSIX_SKIP = "world-writable check skipped: not a POSIX platform"
_ENV_NOTES = (
    "A deliberately fake .env used as a fixture is still a match. "
    "Suppress by removing the file from the tree or by an operator ignore list "
    "in a later milestone."
)
_NAME_NOTES = "The file contents were not read. The match is the filename only."
_VCS_NOTES = "The match is the path segment .git. Contents were not read."
_TEXT_NOTES = (
    "One matching line is stored after redaction. This is not proof the setting is active."
)
_WW_NOTES = (
    "A workstation umask is weak evidence. The check did not follow a symlink "
    "to use the target mode."
)
_OWASP_SECRETS = "https://owasp.org/www-project-secrets-management/"


class SurfaceScanner:
    """One root pass over filenames and three deployment literals."""

    name = "surface"
    version = __version__
    rule_pack_version = "surface-1"
    timeout_s = 60
    modes = frozenset({"static"})
    scope = ScannerScope.ROOT

    def probe(self, ctx: ScanContext) -> ProbeResult:
        del ctx
        return ProbeResult(True, __version__, None)

    def supports(self, component: Component) -> bool:
        del component
        return True

    def scan(self, ctx: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del target
        if ctx.target is None:
            return ScanPluginResult(findings=())
        try:
            root = Path(os.path.realpath(ctx.target))
        except OSError as exc:
            raise ScanFailure("target root cannot be listed") from exc
        found, limitations = _walk(root, ctx.config.detect)
        return ScanPluginResult(findings=tuple(found), limitations=tuple(limitations))


class _Walk:
    def __init__(self, root: Path, limits: DetectLimits) -> None:
        self.root = root
        self.limits = limits
        self.findings: list[Finding] = []
        self.limitations: list[str] = []
        self.files_seen = 0
        self.entered = 0
        self.stopped: str | None = None
        self.depth_noted = False
        self.posix = _platform_is_posix()
        if not self.posix:
            self.limitations.append(_POSIX_SKIP)

    def take_file(self) -> bool:
        if self.files_seen >= self.limits.max_files:
            self._stop("file")
            return False
        self.files_seen += 1
        return True

    def _stop(self, kind: str) -> None:
        if self.stopped is not None:
            return
        self.stopped = kind
        if kind == "file":
            self.limitations.append(
                f"detection stopped: file cap {self.limits.max_files} reached; "
                "results are incomplete"
            )
            return
        self.limitations.append(
            f"detection stopped: directory cap {self.limits.max_directories} reached; "
            "results are incomplete"
        )

    def note_depth(self) -> None:
        if self.depth_noted:
            return
        self.depth_noted = True
        self.limitations.append(
            "detection did not descend below depth 8; deeper paths were not scanned"
        )

    def note(self, text: str) -> None:
        if text and text not in self.limitations:
            self.limitations.append(text)


def _walk(root: Path, limits: DetectLimits) -> tuple[list[Finding], list[str]]:
    try:
        root_info = os.lstat(root)
    except OSError as exc:
        raise ScanFailure("target root cannot be listed") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ScanFailure("target root cannot be listed")
    state = _Walk(root, limits)
    pending: deque[tuple[str, int, tuple[int, int]]] = deque(
        [("", 0, (root_info.st_dev, root_info.st_ino))]
    )
    while pending and state.stopped is None:
        rel, depth, expected = pending.popleft()
        if state.entered >= limits.max_directories:
            state._stop("directory")
            break
        state.entered += 1
        fd, reason = open_confined_directory(root, rel, expected)
        if fd is None:
            _directory_failure(state, rel, reason)
            continue
        try:
            entries = _list(fd)
            dotnet = _dotnet_parent(entries)
            for entry in entries:
                if state.stopped is not None:
                    break
                _entry(state, fd, rel, depth, entry, dotnet=dotnet, pending=pending)
        finally:
            os.close(fd)
    return state.findings, state.limitations


def _list(fd: int) -> list[os.DirEntry[str]]:
    iterator = os.scandir(fd)
    try:
        return sorted(iterator, key=lambda item: item.name)
    finally:
        iterator.close()


def _dotnet_parent(entries: Sequence[os.DirEntry[str]]) -> bool:
    for entry in entries:
        if not (entry.name.endswith(".csproj") or entry.name.endswith(".sln")):
            continue
        try:
            if entry.is_symlink() or entry.is_file(follow_symlinks=False):
                return True
        except OSError:
            continue
    return False


def _entry(
    state: _Walk,
    fd: int,
    rel: str,
    depth: int,
    entry: os.DirEntry[str],
    *,
    dotnet: bool,
    pending: deque[tuple[str, int, tuple[int, int]]],
) -> None:
    name = entry.name
    if name in {"", ".", ".."}:
        return
    child = _child(rel, name)
    try:
        if entry.is_symlink():
            _symlink(state, fd, rel, name, child)
            return
        if entry.is_dir(follow_symlinks=False):
            _directory(state, fd, rel, depth, name, child, dotnet=dotnet, pending=pending)
            return
        if entry.is_file(follow_symlinks=False):
            _file(state, fd, rel, name, child)
    except OSError:
        state.note(f"unreadable path: {child}")


def _symlink(state: _Walk, fd: int, rel: str, name: str, child: str) -> None:
    if not state.take_file():
        return
    if rel == "" and name == ".git":
        return
    rules = _rules(name, _parent_name(child))
    if not rules:
        return
    try:
        info = os.lstat(name, dir_fd=fd)
    except OSError:
        state.note(f"unreadable path: {child}")
        return
    if not stat.S_ISLNK(info.st_mode):
        return
    _emit(state, child, info.st_mode, rules)


def _directory(
    state: _Walk,
    fd: int,
    rel: str,
    depth: int,
    name: str,
    child: str,
    *,
    dotnet: bool,
    pending: deque[tuple[str, int, tuple[int, int]]],
) -> None:
    if name == ".git":
        if rel != "":
            _emit_name(state, child, _VCS, name)
        return
    if name in SKIP_DIRECTORY_NAMES or (name in {"bin", "obj"} and dotnet):
        return
    if depth >= _MAX_DEPTH:
        state.note_depth()
        return
    try:
        info = os.lstat(name, dir_fd=fd)
    except OSError:
        state.note(f"unreadable path: {child}")
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return
    pending.append((child, depth + 1, (info.st_dev, info.st_ino)))


def _file(state: _Walk, fd: int, rel: str, name: str, child: str) -> None:
    if not state.take_file():
        return
    if rel == "" and name == ".git":
        return
    rules = _rules(name, _parent_name(child))
    if not rules:
        return
    try:
        info = os.lstat(name, dir_fd=fd)
    except OSError:
        state.note(f"unreadable path: {child}")
        return
    if not stat.S_ISREG(info.st_mode):
        return
    _emit(state, child, info.st_mode, rules)


def _emit(state: _Walk, child: str, mode: int, rules: tuple[str, ...]) -> None:
    reading = any(rule in _NEEDLES for rule in rules)
    opened = open_inside(state.root, child, max_bytes=_CONTENT_MAX if reading else 0)
    place = _placement(opened.limitation, opened.data is not None, reading=reading)
    if place == "outside":
        state.note(opened.limitation or f"skipped symlink outside target: {child}")
        return
    if place == "drop":
        state.note(opened.limitation or f"unreadable path: {child}")
        return
    if place == "oversize":
        state.note(f"surface skipped content read over 1 MiB: {child}")
    if _world_writable(state, mode):
        _emit_name(state, child, _WW, Path(child).name)
    for rule in rules:
        if rule in _NEEDLES:
            continue
        _emit_name(state, child, rule, Path(child).name)
    if place == "inside" and opened.data is not None:
        _emit_literals(state, child, opened.data, rules)


def _emit_literals(state: _Walk, child: str, data: bytes, rules: tuple[str, ...]) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    lines = text.splitlines()
    for rule in rules:
        needle = _NEEDLES.get(rule)
        if needle is None:
            continue
        match = _matching_line(lines, needle)
        if match is None:
            continue
        number, line = match
        snippet = redact_snippet(line)
        if snippet is None or snippet == "":
            continue
        state.findings.append(_finding(rule, child, line=number, snippet=snippet, name=needle))


def _emit_name(state: _Walk, child: str, rule: str, name: str) -> None:
    state.findings.append(_finding(rule, child, line=None, snippet=None, name=name))


def _placement(limitation: str | None, has_data: bool, *, reading: bool) -> str:
    text = limitation or ""
    if text.startswith("skipped symlink outside target"):
        return "outside"
    if text.startswith("read skipped"):
        return "oversize" if reading else "inside"
    if has_data:
        return "inside"
    return "drop"


def _platform_is_posix() -> bool:
    """Return whether this process should apply the POSIX mode check.

    The check reads ``os.name``. Tests replace this function. Replacing
    ``os.name`` itself makes ``pathlib.Path`` raise on Python 3.13.
    """

    return os.name == "posix"


def _world_writable(state: _Walk, mode: int) -> bool:
    if not state.posix:
        return False
    return stat.S_IMODE(mode) & 0o002 != 0


def _rules(name: str, parent: str) -> tuple[str, ...]:
    found: list[str] = []
    if name == ".env" or (name.startswith(".env.") and name not in _ENV_EXCLUDED):
        found.append(_ENV)
    if name.endswith(_KEY_SUFFIXES):
        found.append(_KEY)
    if name == ".git":
        found.append(_VCS)
    if name == "wp-config.php":
        found.append(_WP)
    if name in _COMPOSE_NAMES:
        found.append(_SOCK)
        found.append(_PRIV)
    if parent in _K8S_PARENTS and name.endswith((".yml", ".yaml")):
        found.append(_K8S)
    return tuple(found)


def _matching_line(lines: list[str], needle: str) -> tuple[int, str] | None:
    for number, line in enumerate(lines, start=1):
        if needle in line:
            return number, line
    return None


def _finding(
    rule: str,
    path: str,
    *,
    line: int | None,
    snippet: str | None,
    name: str,
) -> Finding:
    title, explanation, summary, notes, references, severity, confidence, kind = _FACE[rule]
    if rule == _ENV:
        explanation = f"A file named {name} was found. Contents were not read or stored."
        summary = f"filename matched {name}"
    elif rule in {_KEY, _WP}:
        summary = f"filename matched {name}"
    elif rule == _WW:
        summary = f"filename matched world-writable {name}"
    finding = Finding(
        id=str(uuid.uuid4()),
        fingerprint="ab" * 32,
        title=title,
        severity=severity,
        confidence=confidence,
        kind=kind,
        location=Location(path=path, line=line),
        explanation=explanation,
        evidence=Evidence(
            scanner="surface",
            scanner_version=__version__,
            rule_pack_version="surface-1",
            summary=summary,
            snippet=snippet,
            rule_id=rule,
        ),
        remediation=_remediation(rule, path, line),
        references=list(references),
        scanner="surface",
        scanner_version=__version__,
        false_positive_notes=notes,
        component_id=".",
    )
    return finding.model_copy(update={"fingerprint": fingerprint(finding)})


def _remediation(rule: str, path: str, line: int | None) -> Recommendation:
    where = path if line is None else f"{path}:{line}"
    verify = (
        "Re-run sentinel scan on this path and confirm rule "
        f"{rule} is absent for {where}."
    )
    base = recommendation_for(rule, None)
    if base is None:
        return fallback_remediation("pattern matched", path, line, rule)
    return base.model_copy(update={"where": where, "how_to_verify": verify})


def _directory_failure(state: _Walk, rel: str, reason: str) -> None:
    if rel == "" or reason == "mismatch-root":
        raise ScanFailure("target root cannot be listed")
    if reason == "symlink":
        state.note(f"refused directory symlink: {rel}")
        return
    if reason == "mismatch":
        state.note(f"refused directory inode mismatch: {rel}")
    elif reason == "permission":
        state.note(f"permission denied: {rel}")
    elif reason == "unsupported":
        state.note(f"directory listing refused, no confined descriptor: {rel}")
    else:
        state.note(f"unreadable directory: {rel}")


def _child(rel: str, name: str) -> str:
    text = name if rel == "" else f"{rel}/{name}"
    return unicodedata.normalize("NFC", text)


def _parent_name(rel: str) -> str:
    if "/" not in rel:
        return ""
    return rel.rsplit("/", 1)[0].rsplit("/", 1)[-1]


_FACE: dict[
    str,
    tuple[str, str, str, str, tuple[str, ...], Severity, Confidence, FindingKind],
] = {
    _ENV: (
        "Environment file is present in the tree",
        "A file named .env was found. Contents were not read or stored.",
        "filename matched .env",
        _ENV_NOTES,
        (_OWASP_SECRETS,),
        Severity.HIGH,
        Confidence.HIGH,
        FindingKind.MISCONFIGURATION,
    ),
    _KEY: (
        "Private key filename is present in the tree",
        "A private-key filename was found. Contents were not read or stored.",
        "filename matched private key",
        _NAME_NOTES,
        (),
        Severity.HIGH,
        Confidence.MEDIUM,
        FindingKind.MISCONFIGURATION,
    ),
    _VCS: (
        "Git metadata is present below the scan root",
        (
            "A path segment named .git was found below the scan root. "
            "Contents were not read or stored."
        ),
        "filename matched .git",
        _VCS_NOTES,
        (),
        Severity.MEDIUM,
        Confidence.HIGH,
        FindingKind.MISCONFIGURATION,
    ),
    _WP: (
        "wp-config.php is present in the tree",
        "A file named wp-config.php was found. Contents were not read or stored.",
        "filename matched wp-config.php",
        _NAME_NOTES,
        (),
        Severity.MEDIUM,
        Confidence.HIGH,
        FindingKind.MISCONFIGURATION,
    ),
    _SOCK: (
        "Compose file references the Docker socket",
        "The compose file contains the literal docker.sock.",
        "literal matched docker.sock",
        _TEXT_NOTES,
        (),
        Severity.HIGH,
        Confidence.MEDIUM,
        FindingKind.MISCONFIGURATION,
    ),
    _PRIV: (
        "Compose file contains privileged mode",
        "The compose file contains the literal privileged: true.",
        "literal matched privileged: true",
        _TEXT_NOTES,
        (),
        Severity.HIGH,
        Confidence.MEDIUM,
        FindingKind.MISCONFIGURATION,
    ),
    _K8S: (
        "Kubernetes manifest contains hostNetwork",
        "The manifest contains the literal hostNetwork: true.",
        "literal matched hostNetwork: true",
        _TEXT_NOTES,
        (),
        Severity.MEDIUM,
        Confidence.LOW,
        FindingKind.MISCONFIGURATION,
    ),
    _WW: (
        "Candidate file is world-writable",
        "The candidate's own mode has the other-write bit set. Contents were not read.",
        "filename matched world-writable",
        _WW_NOTES,
        (),
        Severity.INFORMATIONAL,
        Confidence.LOW,
        FindingKind.INFORMATIONAL,
    ),
}
