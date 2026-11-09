"""Semgrep adapter. One root process, local config only, no embedded package.

The binary is ``shutil.which("semgrep")``. CI does not need Semgrep installed.
Flag names come from that binary's ``scan --help`` text, not from a hardcoded
vendor list. ``engine.py`` records a scan timeout; this module does not.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import stat
import subprocess
import unicodedata
import uuid
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from sentinel import __version__
from sentinel.config import DetectLimits
from sentinel.engine import remember_group
from sentinel.errors import ScannerError
from sentinel.fingerprint import fingerprint
from sentinel.fs import classify_symlink
from sentinel.models import (
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Location,
    Severity,
)
from sentinel.protocols import (
    Component,
    ComponentScanTarget,
    ProbeResult,
    ScanContext,
    ScannerScope,
    ScannerSkip,
    ScanPluginResult,
)
from sentinel.recommendations import PATTERN_DISCLAIMER, fallback_remediation
from sentinel.redact import redact_snippet

NO_CONFIG_REASON = (
    "no local semgrep config; pass --semgrep-config or install rules in milestone 2"
)
NOT_FOUND_REASON = "semgrep not found on PATH"
VERSION_FAILED_REASON = "semgrep version check failed"
SEMGREPIGNORE_REASON = "project .semgrepignore could not be disabled"
NOFOLLOW_REASON = (
    "tree contains a symlink that resolves outside the target "
    "and this semgrep build has no no-follow flag"
)
GITIGNORE_LIMITATION = "Semgrepignore v2 still applies the target's .gitignore"
NON_JSON_REASON = "semgrep returned non-JSON output"
MISSING_CHECK_REASON = "semgrep result dropped, missing check_id"
EMPTY_REMEDIATION_REASON = "semgrep result dropped, empty remediation"
INVALID_RESULT_REASON = "semgrep result dropped, invalid result"

_PROBE_TIMEOUT_S = 30
_MAX_DEPTH = 8
_RULE_PACK = re.compile(r"# sentinel-rule-pack: (\S+)\Z")
_CWE = re.compile(r"CWE-[0-9]+")
_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}
_CONFIDENCE = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
}
_SKIP_DIRECTORY_NAMES = frozenset(
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
_UNRECOGNIZED_SEVERITY = " The tool severity was unrecognized."


@dataclass(frozen=True)
class _Plan:
    """What probe decided. ``scan`` launches only when ``available`` is true."""

    available: bool
    failed: bool
    reason: str | None
    tool_version: str | None = None
    binary: str | None = None
    config_path: Path | None = None
    extra_args: tuple[str, ...] = ()
    gitignore_note: str | None = None
    rule_pack: str | None = None


class SemgrepScanner:
    """One Semgrep process for the scan root. Scope is ``ROOT``."""

    name = "semgrep"
    version = __version__
    rule_pack_version: str | None = None
    timeout_s = 300
    modes = frozenset({"static"})
    scope = ScannerScope.ROOT

    def probe(self, ctx: ScanContext) -> ProbeResult:
        plan = self._plan(ctx)
        return ProbeResult(plan.available, plan.tool_version, plan.reason, failed=plan.failed)

    def supports(self, component: Component) -> bool:
        del component
        return True

    def scan(self, ctx: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del target
        plan = self._plan(ctx)
        if not plan.available or plan.binary is None or plan.config_path is None or ctx.target is None:
            reason = plan.reason or NOT_FOUND_REASON
            return ScanPluginResult(
                findings=(),
                skips=(ScannerSkip(self.name, reason, plan.failed),),
            )
        self.rule_pack_version = plan.rule_pack
        argv = [
            plan.binary,
            "scan",
            "--metrics=off",
            "--quiet",
            "--json",
            "--config",
            str(plan.config_path),
            *plan.extra_args,
            str(ctx.target),
        ]
        try:
            completed = _spawn(argv, ctx, timeout=self.timeout_s)
        except OSError as exc:
            raise ScannerError("semgrep could not be started") from exc
        parsed = _parse_document(completed.stdout)
        if parsed is None:
            return ScanPluginResult(
                findings=(),
                skips=(ScannerSkip(self.name, NON_JSON_REASON, True),),
            )
        findings: list[Finding] = []
        limitations: list[str] = []
        if plan.gitignore_note is not None:
            limitations.append(plan.gitignore_note)
        root = Path(ctx.target)
        for item in parsed:
            if not isinstance(item, dict):
                limitations.append(INVALID_RESULT_REASON)
                continue
            finding, limitation = finding_from_semgrep(item, root=root, rule_pack=plan.rule_pack)
            if limitation is not None:
                limitations.append(limitation)
            if finding is not None:
                findings.append(finding)
        return ScanPluginResult(findings=tuple(findings), limitations=tuple(limitations))

    def _plan(self, ctx: ScanContext) -> _Plan:
        cached = getattr(self, "_cached_plan", None)
        if isinstance(cached, tuple) and cached[0] is ctx:
            plan = cached[1]
            if isinstance(plan, _Plan):
                return plan
        plan = _build_plan(ctx)
        self._cached_plan = (ctx, plan)
        return plan


def tool_env(ctx: ScanContext) -> dict[str, str]:
    """Copy ``PATH``, ``LANG``, and ``LC_ALL``. ``HOME`` is the work directory.

    Tool-specific variables such as ``SEMGREP_*`` are not copied.
    """

    env: dict[str, str] = {}
    for key in ("PATH", "LANG", "LC_ALL"):
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env["HOME"] = str(ctx.work_dir)
    return env


def semgrep_title(result: Mapping[str, object]) -> str | None:
    """Title from ``shortlink`` when it is a non-empty string, else ``check_id``."""

    extra = result.get("extra")
    if isinstance(extra, dict):
        metadata = extra.get("metadata")
        if isinstance(metadata, dict):
            shortlink = metadata.get("shortlink")
            if isinstance(shortlink, str) and shortlink.strip():
                return shortlink.strip()[:120]
    check_id = result.get("check_id")
    if isinstance(check_id, str) and check_id.strip():
        return check_id
    return None


def finding_from_semgrep(
    result: Mapping[str, object],
    *,
    root: Path,
    rule_pack: str | None,
) -> tuple[Finding | None, str | None]:
    """Map one Semgrep result. A missing check id is a limitation, not an id."""

    check_id = result.get("check_id")
    if not isinstance(check_id, str) or check_id.strip() == "" or len(check_id) > 200:
        return None, MISSING_CHECK_REASON
    title = semgrep_title(result)
    if title is None:
        return None, MISSING_CHECK_REASON
    extra = result.get("extra")
    if not isinstance(extra, dict):
        extra = {}
    message = extra.get("message")
    if not isinstance(message, str) or message.strip() == "":
        return None, EMPTY_REMEDIATION_REASON
    reported = result.get("path")
    if not isinstance(reported, str) or reported == "":
        return None, INVALID_RESULT_REASON
    relative = relativize_reported_path(root, reported)
    if len(relative) > 1024:
        return None, INVALID_RESULT_REASON
    line = _line(result.get("start"))
    try:
        remediation = fallback_remediation(message, relative, line, check_id)
    except ValueError:
        return None, EMPTY_REMEDIATION_REASON
    severity, confidence, note = _severity(extra)
    explanation = message
    if note:
        explanation = f"{message}{note}"
    if len(explanation) > 2000:
        explanation = explanation[:2000]
    metadata = extra.get("metadata")
    kind = _kind(check_id, metadata)
    if not isinstance(metadata, dict):
        kept_confidence = confidence
    else:
        kept_confidence = confidence if note else _confidence(metadata, confidence)
    summary = f"semgrep matched {check_id}"
    if len(summary) > 500:
        summary = summary[:500]
    snippet = _snippet(extra.get("lines"))
    try:
        finding = Finding(
            id=str(uuid.uuid4()),
            fingerprint="ab" * 32,
            title=title,
            severity=severity,
            confidence=kept_confidence,
            kind=kind,
            cwe=_cwe(metadata),
            cve=None,
            location=Location(path=relative, line=line),
            explanation=explanation,
            evidence=Evidence(
                scanner="semgrep",
                scanner_version=__version__,
                rule_pack_version=rule_pack,
                summary=summary,
                snippet=snippet,
                rule_id=check_id,
            ),
            remediation=remediation,
            references=_references(metadata),
            scanner="semgrep",
            scanner_version=__version__,
            false_positive_notes=PATTERN_DISCLAIMER,
            component_id=".",
        )
    except ValueError:
        return None, INVALID_RESULT_REASON
    # A path the fingerprint rejects (for example ``..``) still has to reach
    # the engine. The engine fails the whole invocation before it hashes.
    try:
        digest = fingerprint(finding)
    except ValueError:
        return finding, None
    return finding.model_copy(update={"fingerprint": digest}), None


def relativize_reported_path(root: Path, reported: str) -> str:
    """Turn an absolute path strictly inside ``root`` into a relative posix path.

    A relative path is not rewritten. ``..``, NUL, and backslash stay in place
    so the engine can refuse them.
    """

    if "\x00" in reported or "\\" in reported:
        return reported
    text = unicodedata.normalize("NFC", reported)
    if not (text.startswith("/") or _drive_path(text)):
        return text
    try:
        resolved = Path(text).resolve()
        base = Path(os.path.realpath(root))
        relative = resolved.relative_to(base)
    except (OSError, ValueError):
        return text
    if not relative.parts:
        return text
    return relative.as_posix()


def _build_plan(ctx: ScanContext) -> _Plan:
    config_path = ctx.config.semgrep_config
    if config_path is None and not _bundled_rules():
        return _Plan(False, False, NO_CONFIG_REASON)
    if config_path is None or not config_path.is_file():
        return _Plan(False, False, NO_CONFIG_REASON)
    binary = shutil.which("semgrep")
    if binary is None:
        return _Plan(False, False, NOT_FOUND_REASON)
    started, version = _tool_version(binary, ctx)
    if not started:
        return _Plan(False, True, VERSION_FAILED_REASON)
    if ctx.target is None:
        return _Plan(True, False, None, tool_version=version, binary=binary, config_path=config_path)
    help_text = _help_text(binary, ctx)
    entries = _option_entries(help_text)
    ignore_flag = _first(entries, _disables_semgrepignore)
    gitignore_flag = _first(entries, _disables_gitignore)
    nofollow_flag = _first(entries, _symlinks_not_followed)
    present, outside = _inspect_tree(Path(ctx.target), ctx.config.detect)
    if ignore_flag is None and present:
        return _Plan(False, False, SEMGREPIGNORE_REASON, tool_version=version)
    if outside and nofollow_flag is None:
        return _Plan(False, False, NOFOLLOW_REASON, tool_version=version)
    extra: list[str] = []
    for token in (ignore_flag, gitignore_flag, nofollow_flag if outside else None):
        if token is not None and token not in extra:
            extra.append(token)
    note = None if gitignore_flag is not None else GITIGNORE_LIMITATION
    return _Plan(
        True,
        False,
        None,
        tool_version=version,
        binary=binary,
        config_path=config_path,
        extra_args=tuple(extra),
        gitignore_note=note,
        rule_pack=_rule_pack_token(config_path),
    )


def _bundled_rules() -> bool:
    directory = Path(__file__).resolve().parents[1] / "rules" / "semgrep"
    if not directory.is_dir():
        return False
    for dirpath, dirnames, filenames in os.walk(directory, followlinks=False):
        del dirpath
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRECTORY_NAMES]
        for name in filenames:
            if name.endswith((".yml", ".yaml")):
                return True
    return False


def _tool_version(binary: str, ctx: ScanContext) -> tuple[bool, str | None]:
    """Return whether ``--version`` started, and its first line when present."""

    try:
        completed = _spawn([binary, "--version"], ctx, timeout=_PROBE_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired):
        return False, None
    if completed.returncode != 0:
        return False, None
    text = completed.stdout.decode("utf-8", errors="replace").splitlines()
    if not text or text[0].strip() == "":
        return True, None
    return True, text[0].strip()[:200]


def _help_text(binary: str, ctx: ScanContext) -> str:
    try:
        completed = _spawn([binary, "scan", "--help"], ctx, timeout=_PROBE_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.decode("utf-8", errors="replace")


def _spawn(argv: list[str], ctx: ScanContext, *, timeout: int) -> subprocess.CompletedProcess[bytes]:
    """Start one session leader and wait. A timeout kills the group and escapes."""

    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=ctx.work_dir,
        env=tool_env(ctx),
        start_new_session=True,
    )
    remember_group(process.pid)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(process.pid)
        _wait(process)
        raise
    code = process.returncode if process.returncode is not None else 1
    return subprocess.CompletedProcess(argv, code, stdout, stderr)


def _wait(process: subprocess.Popen[bytes]) -> None:
    try:
        process.wait(timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        process.kill()
        process.wait(timeout=5)


def _kill_group(pid: int) -> None:
    """SIGKILL the scanner session. Pid 0, pid 1, and this process are refused."""

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return
    if pid == os.getpid() or pid == os.getpgrp():
        return
    try:
        pgid = os.getpgid(pid)
    except OSError:
        pgid = None
    if pgid is not None and (pgid <= 1 or pgid != pid or pgid == os.getpid() or pgid == os.getpgrp()):
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        return


def _option_entries(help_text: str) -> list[tuple[str, str]]:
    """One entry is the first ``-`` token plus lines indented further."""

    lines = help_text.splitlines()
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        token = _flag_token(lines[index])
        if token is None:
            index += 1
            continue
        indent = _indent(lines[index])
        block = [lines[index]]
        index += 1
        while index < len(lines) and lines[index].strip() != "" and _indent(lines[index]) > indent:
            block.append(lines[index])
            index += 1
        entries.append((token, "\n".join(block)))
    return entries


def _flag_token(line: str) -> str | None:
    parts = line.split()
    if not parts or not parts[0].startswith("-"):
        return None
    return parts[0]


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _first(entries: list[tuple[str, str]], predicate: Callable[[str], bool]) -> str | None:
    for token, text in entries:
        if predicate(text):
            return token
    return None


def _disables_semgrepignore(text: str) -> bool:
    lowered = text.casefold()
    return ".semgrepignore" in text and ("disable" in lowered or "not read" in lowered)


def _disables_gitignore(text: str) -> bool:
    lowered = text.casefold()
    return ".gitignore" in text and ("disable" in lowered or "not applied" in lowered)


def _symlinks_not_followed(text: str) -> bool:
    lowered = text.casefold()
    return "symlink" in lowered and "not follow" in lowered


def _inspect_tree(root: Path, limits: DetectLimits) -> tuple[bool, bool]:
    """Return whether ``.semgrepignore`` exists and whether a symlink leaves the root.

    Directory symlinks are not descended. A symlink named ``.semgrepignore``
    counts and is not opened. Depth 8 is visited. Its children are not.
    """

    try:
        base = Path(os.path.realpath(root))
    except OSError:
        return False, False
    present = False
    outside = False
    files = 0
    entered = 0
    pending: deque[tuple[Path, str, int]] = deque([(base, "", 0)])
    while pending and files < limits.max_files and entered < limits.max_directories:
        directory, rel, depth = pending.popleft()
        entered += 1
        try:
            iterator = os.scandir(directory)
        except OSError:
            continue
        dotnet = False
        saved: list[tuple[str, os.stat_result]] = []
        try:
            for entry in iterator:
                name = entry.name
                if name in {"", ".", ".."}:
                    continue
                try:
                    info = os.lstat(entry.path)
                except OSError:
                    continue
                if name.endswith((".csproj", ".sln")) and (
                    _is_regular(info) or stat.S_ISLNK(info.st_mode)
                ):
                    dotnet = True
                saved.append((name, info))
        finally:
            iterator.close()
        for name, info in saved:
            child = name if rel == "" else f"{rel}/{unicodedata.normalize('NFC', name)}"
            if name == ".semgrepignore":
                present = True
                if stat.S_ISLNK(info.st_mode) and classify_symlink(base, child) == "outside":
                    outside = True
                elif _is_regular(info):
                    files += 1
                continue
            if stat.S_ISLNK(info.st_mode):
                if classify_symlink(base, child) == "outside":
                    outside = True
                files += 1
                continue
            if stat.S_ISDIR(info.st_mode):
                skipped = name in _SKIP_DIRECTORY_NAMES or (name in {"bin", "obj"} and dotnet)
                if skipped or depth >= _MAX_DEPTH:
                    continue
                pending.append((directory / name, child, depth + 1))
                continue
            if _is_regular(info):
                files += 1
            if files >= limits.max_files:
                break
    return present, outside


def _is_regular(info: os.stat_result) -> bool:
    return stat.S_ISREG(info.st_mode)


def _rule_pack_token(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            line = handle.readline(256)
    except OSError:
        return None
    if "\n" not in line and len(line) >= 256:
        return None
    match = _RULE_PACK.fullmatch(line.strip())
    if match is None:
        return None
    token = match.group(1)
    if len(token) > 32:
        return None
    return token


def _parse_document(stdout: bytes) -> list[object] | None:
    try:
        parsed = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    results = parsed.get("results")
    if not isinstance(results, list):
        return None
    return results


def _line(start: object) -> int | None:
    if not isinstance(start, dict):
        return None
    line = start.get("line")
    if isinstance(line, bool) or not isinstance(line, int):
        return None
    return line


def _severity(extra: Mapping[str, object]) -> tuple[Severity, Confidence, str]:
    raw = extra.get("severity")
    if isinstance(raw, str) and raw in _SEVERITY:
        return _SEVERITY[raw], Confidence.MEDIUM, ""
    return Severity.MEDIUM, Confidence.LOW, _UNRECOGNIZED_SEVERITY


def _confidence(metadata: Mapping[str, object], default: Confidence) -> Confidence:
    raw = metadata.get("confidence")
    if isinstance(raw, str) and raw in _CONFIDENCE:
        return _CONFIDENCE[raw]
    return default


def _kind(rule_id: str, metadata: object) -> FindingKind:
    if not isinstance(metadata, dict) or metadata.get("category") != "security":
        return FindingKind.POTENTIAL
    if ".dockerfile." in rule_id or ".kubernetes." in rule_id:
        return FindingKind.MISCONFIGURATION
    return FindingKind.POTENTIAL


def _cwe(metadata: object) -> str | None:
    if not isinstance(metadata, dict):
        return None
    raw = metadata.get("cwe")
    texts: list[str] = []
    if isinstance(raw, str):
        texts = [raw]
    elif isinstance(raw, list):
        texts = [item for item in raw if isinstance(item, str)]
    for text in texts:
        match = _CWE.search(text)
        if match is not None:
            return match.group(0)
    return None


def _snippet(lines: object) -> str | None:
    if not isinstance(lines, str):
        return None
    redacted = redact_snippet(lines)
    if redacted is None or redacted == "":
        return None
    return redacted


def _references(metadata: object) -> list[str]:
    if not isinstance(metadata, dict):
        return []
    raw = metadata.get("references")
    items: list[object]
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = list(raw)
    else:
        return []
    kept: list[str] = []
    for item in items:
        if not isinstance(item, str) or len(item) > 500 or not item.startswith("https://"):
            continue
        if not _https_url(item):
            continue
        kept.append(item)
        if len(kept) == 20:
            break
    return kept


def _https_url(value: str) -> bool:
    scheme, separator, rest = value.partition("://")
    return scheme == "https" and separator == "://" and rest != "" and " " not in value


def _drive_path(path: str) -> bool:
    return len(path) >= 2 and path[0].isalpha() and path[1] == ":"
