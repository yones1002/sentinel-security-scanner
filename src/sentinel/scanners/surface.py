"""Filename and deployment-literal scanner.

Content is read only for the three literal rules, and only through
``open_inside``. Filename rules do not read file bytes. The engine stamps
``component_id`` and replaces the fingerprint.
"""

from __future__ import annotations

import heapq
import os
import stat
import unicodedata
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
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
_PATH_MAX = 1024
_PATH_SKIP = "surface skipped a path longer than 1024 characters"
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
        self._noted: set[str] = set()
        self.files_seen = 0
        self.entered = 0
        self.stopped: str | None = None
        self.depth_noted = False
        self.posix = _platform_is_posix()
        self.directory_overflow = False
        if not self.posix:
            self._append_limitation(_POSIX_SKIP)

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
            self._append_limitation(
                f"detection stopped: file cap {self.limits.max_files} reached; "
                "results are incomplete"
            )
            return
        self._append_limitation(
            f"detection stopped: directory cap {self.limits.max_directories} reached; "
            "results are incomplete"
        )

    def note_depth(self) -> None:
        if self.depth_noted:
            return
        self.depth_noted = True
        self._append_limitation(
            "detection did not descend below depth 8; deeper paths were not scanned"
        )

    def note(self, text: str) -> None:
        if text and text not in self._noted:
            self._append_limitation(text)

    def _append_limitation(self, text: str) -> None:
        """Append one limitation and remember it for a constant-time repeat check."""

        self._noted.add(text)
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
            file_budget = state.limits.max_files - state.files_seen
            dir_slots = state.limits.max_directories - state.entered - len(pending)
            plan = _plan_directory(
                fd,
                file_budget=file_budget,
                dir_slots=max(0, dir_slots),
                depth=depth,
            )
            _apply_plan(state, fd, rel, depth, plan, pending)
        finally:
            os.close(fd)
    if state.stopped is None and state.directory_overflow:
        state._stop("directory")
    return state.findings, state.limitations


class _HeapName:
    """Max-heap entry. The largest name sorts first so the budget can drop it."""

    __slots__ = ("kind", "name")

    def __init__(self, name: str, kind: str) -> None:
        self.name = name
        self.kind = kind

    def __lt__(self, other: _HeapName) -> bool:
        return self.name > other.name


@dataclass(frozen=True)
class _DirectoryPlan:
    """Bounded selection for one directory, in alphabetical order."""

    seen: int
    dotnet: bool
    files: tuple[tuple[str, str], ...]
    file_overflow: bool
    dirs: tuple[str, ...]
    directory_overflow: bool
    git_dir: bool
    deep_name: str | None
    unreadable: tuple[str, ...]

    @property
    def retained_entries(self) -> int:
        """Names retained from the directory, including reported unreadable paths."""

        return (
            len(self.files)
            + len(self.dirs)
            + len(self.unreadable)
            + int(self.file_overflow)
            + int(self.git_dir)
            + int(self.deep_name is not None)
        )


def _plan_directory(
    fd: int,
    *,
    file_budget: int,
    dir_slots: int,
    depth: int,
) -> _DirectoryPlan:
    def lstat_dir(name: str) -> str:
        try:
            info = os.lstat(name, dir_fd=fd)
        except OSError:
            return "unreadable"
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return "skip"
        return "ok"

    iterator = os.scandir(fd)
    try:
        return _plan_entries(
            _entry_kinds(iterator),
            file_budget=file_budget,
            dir_slots=dir_slots,
            depth=depth,
            lstat_dir=lstat_dir,
        )
    finally:
        iterator.close()


def _entry_kinds(iterator: Iterator[os.DirEntry[str]]) -> Iterator[tuple[str, str]]:
    for entry in iterator:
        name = entry.name
        try:
            if entry.is_symlink():
                kind = "symlink"
            elif entry.is_dir(follow_symlinks=False):
                kind = "dir"
            elif entry.is_file(follow_symlinks=False):
                kind = "file"
            else:
                kind = "other"
        except OSError:
            kind = "unreadable"
        yield name, kind


def _plan_entries(
    entries: Iterable[tuple[str, str]],
    *,
    file_budget: int,
    dir_slots: int,
    depth: int,
    lstat_dir: Callable[[str], str] | None = None,
) -> _DirectoryPlan:
    """Select a directory budget without retaining every name.

    Alphabetical order needs one look at each name. The kept names are at
    most the file budget, one cutoff name, and the directory slots.
    """

    check_dir = lstat_dir if lstat_dir is not None else _directory_stat_ok
    budget = max(0, file_budget)
    slots = max(0, dir_slots)
    files: list[_HeapName] = []
    file_count = 0
    dirs: list[_HeapName] = []
    eligible = 0
    side: list[tuple[str, bool]] = []
    unreadable: list[str] = []
    dotnet = False
    git_dir = False
    deep_name: str | None = None
    seen = 0
    for name, kind in entries:
        seen += 1
        if name in {"", ".", ".."}:
            continue
        if kind == "unreadable":
            unreadable.append(name)
            continue
        if kind in {"file", "symlink"}:
            file_count += 1
            if name.endswith((".csproj", ".sln")):
                dotnet = True
            _offer(files, budget + 1, _HeapName(name, kind))
            continue
        if kind != "dir":
            continue
        if name == ".git":
            git_dir = True
            continue
        if name in SKIP_DIRECTORY_NAMES:
            continue
        if name in {"bin", "obj"}:
            side.append((name, depth >= _MAX_DEPTH))
            continue
        if depth >= _MAX_DEPTH:
            deep_name = _earlier(deep_name, name)
            continue
        checked = check_dir(name)
        if checked == "unreadable":
            unreadable.append(name)
            continue
        if checked != "ok":
            continue
        eligible += 1
        _offer(dirs, slots, _HeapName(name, "dir"))
    return _finish_plan(
        seen=seen,
        budget=budget,
        slots=slots,
        files=files,
        file_count=file_count,
        dirs=dirs,
        eligible=eligible,
        side=side,
        unreadable=unreadable,
        dotnet=dotnet,
        git_dir=git_dir,
        deep_name=deep_name,
        check_dir=check_dir,
    )


def _finish_plan(
    *,
    seen: int,
    budget: int,
    slots: int,
    files: list[_HeapName],
    file_count: int,
    dirs: list[_HeapName],
    eligible: int,
    side: list[tuple[str, bool]],
    unreadable: list[str],
    dotnet: bool,
    git_dir: bool,
    deep_name: str | None,
    check_dir: Callable[[str], str],
) -> _DirectoryPlan:
    file_overflow = file_count > budget
    cutoff: str | None = None
    if file_overflow and files:
        cutoff = files[0].name
        chosen = [item for item in files if item.name != cutoff]
    else:
        chosen = list(files)
    chosen.sort(key=lambda item: item.name)
    kept_files = tuple((item.name, item.kind) for item in chosen)
    directory_overflow = False
    queued: list[str] = []
    if not file_overflow:
        queued = [item.name for item in dirs]
        directory_overflow = eligible > slots
    for name, depth_limited in side:
        if dotnet:
            continue
        if depth_limited:
            deep_name = _earlier(deep_name, name)
            continue
        checked = check_dir(name)
        if checked == "unreadable":
            unreadable.append(name)
            continue
        if checked != "ok" or file_overflow:
            continue
        queued.append(name)
    if not file_overflow:
        queued.sort()
        if len(queued) > slots:
            directory_overflow = True
            del queued[slots:]
    else:
        queued = []
    if cutoff is not None:
        deep_name = deep_name if deep_name is not None and deep_name < cutoff else None
        git_dir = git_dir and ".git" < cutoff
        unreadable = [name for name in unreadable if name < cutoff]
    return _DirectoryPlan(
        seen=seen,
        dotnet=dotnet,
        files=kept_files,
        file_overflow=file_overflow,
        dirs=tuple(queued),
        directory_overflow=directory_overflow,
        git_dir=git_dir,
        deep_name=deep_name,
        unreadable=tuple(sorted(unreadable)),
    )


def _offer(heap: list[_HeapName], limit: int, item: _HeapName) -> None:
    if limit <= 0:
        return
    if len(heap) < limit:
        heapq.heappush(heap, item)
        return
    if item.name < heap[0].name:
        heapq.heapreplace(heap, item)


def _earlier(current: str | None, name: str) -> str:
    if current is None or name < current:
        return name
    return current


def _directory_stat_ok(_name: str) -> str:
    return "ok"


def _apply_plan(
    state: _Walk,
    fd: int,
    rel: str,
    depth: int,
    plan: _DirectoryPlan,
    pending: deque[tuple[str, int, tuple[int, int]]],
) -> None:
    """Replay the bounded selection in alphabetical order."""

    events: list[tuple[str, str, str]] = []
    for name, kind in plan.files:
        events.append((name, "file", kind))
    for name in plan.dirs:
        events.append((name, "dir", ""))
    for name in plan.unreadable:
        events.append((name, "unreadable", ""))
    if plan.git_dir:
        events.append((".git", "git", ""))
    if plan.deep_name is not None:
        events.append((plan.deep_name, "deep", ""))
    events.sort()
    for name, action, kind in events:
        child = _child(rel, name)
        if action == "unreadable":
            state.note(f"unreadable path: {child}")
        elif action == "deep":
            state.note_depth()
        elif action in {"git", "dir"}:
            _directory(
                state, fd, rel, depth, name, child, dotnet=plan.dotnet, pending=pending
            )
        elif kind == "symlink":
            _symlink(state, fd, rel, name, child)
        else:
            _file(state, fd, rel, name, child)
    if plan.file_overflow:
        state._stop("file")
    elif plan.directory_overflow:
        state.directory_overflow = True


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
    if not _path_ok(state, child):
        return
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
        _keep(state, _finding(rule, child, line=number, snippet=snippet, name=needle))


def _emit_name(state: _Walk, child: str, rule: str, name: str) -> None:
    if not _path_ok(state, child):
        return
    _keep(state, _finding(rule, child, line=None, snippet=None, name=name))


def _path_ok(state: _Walk, child: str) -> bool:
    """Reject a relative path the finding model cannot store.

    ``Location.path`` allows 1024 characters. A longer candidate must not be
    read and must not abort the rest of the scan.
    """

    if len(child) <= _PATH_MAX:
        return True
    state.note(_PATH_SKIP)
    return False


def _keep(state: _Walk, found: Finding | None) -> None:
    if found is None:
        state.note(_PATH_SKIP)
        return
    state.findings.append(found)


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
) -> Finding | None:
    if len(path) > _PATH_MAX:
        return None
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
