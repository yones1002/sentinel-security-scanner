"""Scan lifecycle.

The engine receives scanners from the caller. It does not import the registry,
scanner implementations, or Docker.

An in-process ``scan`` that never returns is not killed. ``os.killpg`` runs
only for a process group this invocation recorded and re-checked. The pid must
be the session leader from ``Popen(..., start_new_session=True)``, and the
Linux ``/proc`` start time must still match. A reused pid is not signaled.
``TimeoutExpired`` is not a pid. A process that calls ``setsid`` again, or
double-forks, leaves the recorded group and is not signaled.

The engine does not classify HTTP requests and does not open a socket.
``sent=True`` only records a decision a scanner already made. The URL
component uses ``kind=repository`` because the component enum has no URL kind.
That id is not a directory the engine creates, reads, or scans as a repository.
"""

from __future__ import annotations

import contextvars
import logging
import os
import signal
import subprocess
import time
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import timedelta
from pathlib import Path
from typing import Literal

from sentinel import __version__
from sentinel.detect import (
    apply_external_components,
    assign_component_id,
    assign_endpoint_component,
    detect,
    require_unique_components,
)
from sentinel.errors import ScannerError, UsageError
from sentinel.fingerprint import fingerprint
from sentinel.fs import open_inside
from sentinel.models import (
    Component,
    ComponentKind,
    DynamicRequests,
    ExecutedScanner,
    Finding,
    ReportComponent,
    ScannerSection,
    ScanReport,
    SentRequest,
    Severity,
    SkippedScanner,
    Totals,
    WithheldRequest,
)
from sentinel.protocols import (
    ComponentScanTarget,
    DynamicRuntime,
    ProbeResult,
    RequestRecord,
    ScanContext,
    ScanMode,
    Scanner,
    ScannerRun,
    ScannerRunStatus,
    ScannerScope,
    ScannerSkip,
    ScanPluginResult,
)
from sentinel.redact import redact_finding

logger = logging.getLogger(__name__)

BANDIT_DISABLED_REASON = "bandit disabled because semgrep ran"
STRICT_DYNAMIC_SKIP = "dynamic skipped because --strict-tools failed during static scanning"
HISTORY_UNAVAILABLE = "history store is not in this build (milestone 2)"
OUTSIDE_TARGET_REASON = "tool reported a path outside the target"
_OUTSIDE_SYMLINK = "skipped symlink outside target"
_SEMGREPIGNORE_SKIP = "project .semgrepignore could not be disabled"
_READ_SKIPPED = "read skipped"
_REQUEST_CLASSES = frozenset({"read_candidate", "ambiguous", "state_changing"})
_SENT_METHODS = frozenset({"GET", "HEAD"})
_SEVERITY_RANK = {item: index for index, item in enumerate(Severity)}
_STARTTIME_INDEX = 19

_GROUPS: contextvars.ContextVar[list[RecordedGroup] | None] = contextvars.ContextVar(
    "sentinel_scanner_groups",
    default=None,
)


@dataclass(frozen=True)
class RecordedGroup:
    """A session leader this invocation confirmed. ``starttime`` is Linux field 22."""

    pid: int
    pgid: int
    starttime: int


def parse_proc_starttime(stat_text: str) -> int | None:
    """Return ``starttime`` from a ``/proc/<pid>/stat`` line, or None.

    The command name sits in parentheses and may itself contain spaces and
    parentheses. Fields after the last ``)`` are numbered from ``state``.
    ``starttime`` is the 20th of those fields.
    """
    marker = stat_text.rfind(")")
    if marker < 0:
        return None
    fields = stat_text[marker + 1 :].split()
    if len(fields) <= _STARTTIME_INDEX:
        return None
    try:
        return int(fields[_STARTTIME_INDEX])
    except ValueError:
        return None


def remember_group(pid: int) -> RecordedGroup | None:
    """Record ``Popen.pid`` right after ``Popen(..., start_new_session=True)``.

    Returns None, and signals nothing, when no scan is in flight or the pid is
    not a confirmed session leader. Pid 0, pid 1, the engine pid, and the
    engine's own group are refused. A ``TimeoutExpired`` value is not a pid
    this function accepts by itself.
    """
    bucket = _GROUPS.get()
    if bucket is None:
        return None
    record = _confirm_group(pid)
    if record is None:
        return None
    bucket.append(record)
    return record


def signal_group(record: RecordedGroup) -> bool:
    """SIGKILL one recorded group when its pid and start time still match.

    Returns False without signaling when identity cannot be confirmed. This
    never calls ``os.killpg`` on 0 or on the engine's process group.
    """
    pid = record.pid
    pgid = record.pgid
    if isinstance(pid, bool) or isinstance(pgid, bool):
        return False
    if pid <= 1 or pgid <= 1 or pid != pgid:
        return False
    if pid == os.getpid() or pgid == os.getpgrp():
        return False
    try:
        live_pgid = os.getpgid(pid)
    except OSError:
        return False
    if live_pgid != pgid or live_pgid != pid:
        return False
    starttime = _read_starttime(pid)
    if starttime is None or starttime != record.starttime:
        return False
    if pid == os.getpid() or pgid == os.getpgrp():
        return False
    os.killpg(pgid, signal.SIGKILL)
    return True


def run_scan(
    ctx: ScanContext,
    scanners: Sequence[Scanner],
    *,
    dynamic: DynamicRuntime,
    store: object | None,
) -> ScanReport:
    """Run the selected scanners. ``ScannerError`` becomes a failed skip.

    ``UnavailableDynamicRuntime.prepare`` is not caught. A non-None ``store``
    raises ``UsageError`` because milestone 1 has no history database.
    """
    if store is not None:
        raise UsageError(HISTORY_UNAVAILABLE)
    started = time.monotonic()
    components, limitations = _components_for(ctx)
    root = _scan_root(components, ctx.target, url_component=_url_only(ctx, components))
    norm = _Norm(
        target=None if ctx.url is not None else ctx.target,
        url_mode=ctx.url is not None,
        components=components,
    )
    build = _ReportBuild(
        limitations=limitations,
        confirm=ctx.config.confirm_ambiguous_reads,
        started=started,
    )
    static_scanners, dynamic_scanners = _split(scanners, ctx.mode, url_mode=norm.url_mode)
    static_ctx = replace(ctx, components=components, dynamic_session=None)
    static_problem = _run_scanners(
        static_scanners,
        static_ctx,
        root=root,
        norm=norm,
        build=build,
        watch_strict=True,
    )
    strict_failure = bool(ctx.config.strict_tools and static_problem)
    if strict_failure and ctx.mode == ScanMode.ALL:
        build.limitations.append(STRICT_DYNAMIC_SKIP)
    wants_dynamic = ctx.mode in {ScanMode.DYNAMIC, ScanMode.ALL} or ctx.url is not None
    if wants_dynamic and not strict_failure:
        session = dynamic.prepare(ctx)
        if session is not None:
            build.limitations.extend(session.limitations)
        dynamic_ctx = replace(ctx, components=components, dynamic_session=session)
        _run_scanners(
            dynamic_scanners,
            dynamic_ctx,
            root=root,
            norm=norm,
            build=build,
            watch_strict=False,
        )
    findings = _collapse(build)
    finished_ms = _elapsed_ms(time.monotonic(), _clock_start(build))
    return _report(
        ctx,
        components=components,
        findings=findings,
        build=build,
        strict_failure=strict_failure,
        duration_ms=finished_ms,
    )


@dataclass
class _ReportBuild:
    limitations: list[str]
    confirm: bool
    started: float
    rows: list[_Row] = field(default_factory=list)
    skips: list[SkippedScanner] = field(default_factory=list)
    sent: list[SentRequest] = field(default_factory=list)
    withheld: list[WithheldRequest] = field(default_factory=list)


@dataclass
class _Row:
    name: str
    version: str
    rule_pack_version: str | None
    tool_version: str | None
    duration_ms: int
    status: Literal["executed", "failed"]
    reason: str | None
    findings: list[Finding]


@dataclass(frozen=True)
class _Norm:
    target: Path | None
    url_mode: bool
    components: tuple[Component, ...]


@dataclass(frozen=True)
class _Verdict:
    kind: str
    limitation: str | None = None


@dataclass(frozen=True)
class _Kept:
    finding: Finding | None
    limitation: str | None = None


def _components_for(ctx: ScanContext) -> tuple[tuple[Component, ...], list[str]]:
    if ctx.url is not None:
        return (_url_component(ctx),), []
    if ctx.target is None:
        raise UsageError("scan context has no target")
    detection = detect(ctx.target, ctx.config.detect)
    components = apply_external_components(
        detection.components,
        ctx.config.component_overrides,
    )
    require_unique_components(components)
    return components, list(detection.limitations)


def _url_only(ctx: ScanContext, components: tuple[Component, ...]) -> Component | None:
    if ctx.url is None:
        return None
    return components[0]


def _url_component(ctx: ScanContext) -> Component:
    host = ctx.url_host or ""
    evidence = (host,) if host else ()
    return Component(
        component_id="url",
        root=ctx.work_dir / "url-component",
        languages=(),
        frameworks=(),
        evidence=evidence,
        kind=ComponentKind.REPOSITORY,
    )


def _scan_root(
    components: tuple[Component, ...],
    target: Path | None,
    *,
    url_component: Component | None,
) -> Component:
    if url_component is not None:
        return url_component
    for component in components:
        if component.component_id == ".":
            return component
    if target is None:
        raise UsageError("scan context has no target")
    return Component(
        component_id=".",
        root=target,
        languages=(),
        frameworks=(),
        evidence=(),
        kind=ComponentKind.REPOSITORY,
    )


def _split(
    scanners: Sequence[Scanner],
    mode: ScanMode,
    *,
    url_mode: bool,
) -> tuple[list[Scanner], list[Scanner]]:
    if mode == ScanMode.DYNAMIC:
        static: list[Scanner] = []
        dynamic = [scanner for scanner in scanners if "dynamic" in scanner.modes]
    elif mode == ScanMode.ALL:
        static = [scanner for scanner in scanners if "static" in scanner.modes]
        dynamic = [scanner for scanner in scanners if "dynamic" in scanner.modes]
    else:
        static = [scanner for scanner in scanners if "static" in scanner.modes]
        dynamic = []
    if url_mode:
        static = []
    return static, dynamic


def _run_scanners(
    scanners: Sequence[Scanner],
    seen: ScanContext,
    *,
    root: Component,
    norm: _Norm,
    build: _ReportBuild,
    watch_strict: bool,
) -> bool:
    problem = False
    for scanner in scanners:
        probe = scanner.probe(seen)
        if not probe.available:
            build.skips.append(
                SkippedScanner(
                    name=scanner.name,
                    reason=_one_line(probe.reason or "", fallback="unavailable"),
                    failed=probe.failed,
                )
            )
            if (
                probe.reason == _SEMGREPIGNORE_SKIP
                and _SEMGREPIGNORE_SKIP not in build.limitations
            ):
                build.limitations.append(_SEMGREPIGNORE_SKIP)
            if watch_strict and _probe_is_strict(probe):
                problem = True
            continue
        for invoked in _invocations(scanner, norm.components, root):
            outcome = _invoke(scanner, probe, seen, invoked, norm)
            _store_outcome(scanner, probe, outcome, build)
            if watch_strict and _outcome_is_strict(outcome):
                problem = True
    return problem


def _probe_is_strict(probe: ProbeResult) -> bool:
    if probe.failed:
        return True
    return probe.reason != BANDIT_DISABLED_REASON


def _outcome_is_strict(outcome: _Outcome) -> bool:
    if outcome.status == "failed":
        return True
    return any(skip.failed for skip in outcome.skips)


def _invocations(
    scanner: Scanner,
    components: tuple[Component, ...],
    root: Component,
) -> list[Component]:
    if scanner.scope == ScannerScope.ROOT:
        return [root]
    if scanner.scope == ScannerScope.COMPONENT:
        return [component for component in components if scanner.supports(component)]
    raise UsageError(f"unknown scanner scope {scanner.scope}")


def _invoke(
    scanner: Scanner,
    probe: ProbeResult,
    seen: ScanContext,
    invoked: Component,
    norm: _Norm,
) -> _Outcome:
    exclude = (
        ()
        if scanner.scope == ScannerScope.ROOT
        else _exclude_roots(invoked, norm.components)
    )
    target = ComponentScanTarget(component=invoked, exclude_roots=exclude)
    bucket: list[RecordedGroup] = []
    token = _GROUPS.set(bucket)
    started = time.monotonic()
    result: ScanPluginResult | None = None
    error: ScannerError | None = None
    timed_out = False
    try:
        try:
            result = scanner.scan(seen, target)
        except subprocess.TimeoutExpired:
            timed_out = True
        except ScannerError as exc:
            error = exc
            logger.debug("scanner %s failed", scanner.name, exc_info=True)
        else:
            timed_out = time.monotonic() - started > scanner.timeout_s
        duration_ms = _elapsed_ms(time.monotonic(), started)
    finally:
        _GROUPS.reset(token)
    if timed_out:
        _signal_recorded(bucket)
        return _failed(scanner, probe, duration_ms, f"timeout after {scanner.timeout_s}s")
    if error is not None:
        return _failed(scanner, probe, duration_ms, _scanner_failure(scanner, error))
    assert result is not None
    return _normalize(scanner, probe, result, duration_ms, invoked, norm)


def _exclude_roots(
    component: Component,
    components: tuple[Component, ...],
) -> tuple[Path, ...]:
    parent = component.component_id
    excluded: list[Path] = []
    for other in components:
        child = other.component_id
        if child == parent:
            continue
        if parent == "." or child.startswith(f"{parent}/"):
            excluded.append(Path(other.root).resolve())
    return tuple(excluded)


def _normalize(
    scanner: Scanner,
    probe: ProbeResult,
    result: ScanPluginResult,
    duration_ms: int,
    invoked: Component,
    norm: _Norm,
) -> _Outcome:
    verdicts = [_classify_path(finding.location.path, norm) for finding in result.findings]
    outside = sum(1 for verdict in verdicts if verdict.kind == "outside")
    if outside:
        return _failed(
            scanner,
            probe,
            duration_ms,
            OUTSIDE_TARGET_REASON,
            limitations=[f"dropped {outside} tool paths outside target"],
        )
    findings: list[Finding] = []
    limitations: list[str] = []
    for finding, verdict in zip(result.findings, verdicts, strict=True):
        if verdict.kind == "drop":
            limitations.append(verdict.limitation or "unreadable path")
            continue
        kept = _normalize_finding(finding, scanner, invoked, norm.components, norm.url_mode)
        if kept.limitation:
            limitations.append(kept.limitation)
        if kept.finding is not None:
            findings.append(kept.finding)
    for line in result.limitations:
        cleaned = _one_line(line, fallback="")
        if cleaned:
            limitations.append(cleaned)
    skips = [_plugin_skip(scanner, skip) for skip in result.skips]
    return _Outcome(
        status="executed",
        duration_ms=duration_ms,
        reason=None,
        findings=findings,
        skips=skips,
        limitations=limitations,
        requests=tuple(result.requests),
        tool_version=probe.version or None,
    )


def _normalize_finding(
    finding: Finding,
    scanner: Scanner,
    invoked: Component,
    components: tuple[Component, ...],
    url_mode: bool,
) -> _Kept:
    try:
        redacted = redact_finding(finding)
    except ValueError:
        return _Kept(None, "finding dropped, empty evidence")
    try:
        checked = Finding.model_validate(redacted.model_dump())
    except ValueError as exc:
        if "must match scanner" in str(exc):
            return _Kept(None, "finding dropped, scanner identity mismatch")
        return _Kept(None, "finding dropped, empty evidence")
    if not _identity_matches(checked, scanner):
        return _Kept(None, "finding dropped, scanner identity mismatch")
    if _evidence_empty(checked):
        return _Kept(None, "finding dropped, empty evidence")
    line = checked.location.line
    if line is not None and line < 1:
        return _Kept(None, "finding dropped, invalid line")
    return _stamp(checked, invoked, components, url_mode)


def _stamp(
    finding: Finding,
    invoked: Component,
    components: tuple[Component, ...],
    url_mode: bool,
) -> _Kept:
    path = finding.location.path
    if path is not None:
        if url_mode:
            return _Kept(None, f"unassigned path dropped: {path}")
        assignment = assign_component_id(path, components)
    elif finding.location.endpoint:
        assignment = assign_endpoint_component(invoked, components)
    else:
        return _Kept(None, "unassigned path dropped")
    if assignment.component_id is None:
        return _Kept(None, assignment.reason)
    stamped = finding.model_copy(
        update={
            "component_id": assignment.component_id,
            "fingerprint_version": "v1",
        }
    )
    try:
        digest = fingerprint(stamped)
    except ValueError as exc:
        text = _one_line(str(exc), fallback="finding dropped, empty evidence")
        return _Kept(None, text)
    return _Kept(stamped.model_copy(update={"fingerprint": digest}))


def _classify_path(path: str | None, norm: _Norm) -> _Verdict:
    if path is None:
        return _Verdict("keep")
    if _lexical_outside(path):
        return _Verdict("outside")
    if norm.url_mode or norm.target is None:
        return _Verdict("keep")
    opened = open_inside(norm.target, path, max_bytes=0)
    limitation = opened.limitation
    if limitation is None:
        return _Verdict("keep")
    if limitation.startswith(_OUTSIDE_SYMLINK):
        return _Verdict("outside")
    if limitation.startswith(_READ_SKIPPED):
        return _Verdict("keep")
    return _Verdict("drop", limitation)


def _lexical_outside(path: str) -> bool:
    if "\x00" in path or "\\" in path:
        return False
    text = unicodedata.normalize("NFC", path)
    while text.startswith("./"):
        text = text[2:]
    if text.startswith("/") or _drive_path(text):
        return True
    return any(part == ".." for part in text.split("/"))


def _drive_path(path: str) -> bool:
    return len(path) >= 2 and path[0].isalpha() and path[1] == ":"


def _identity_matches(finding: Finding, scanner: Scanner) -> bool:
    if finding.scanner != scanner.name or finding.scanner_version != scanner.version:
        return False
    evidence = finding.evidence
    return evidence.scanner == scanner.name and evidence.scanner_version == scanner.version


def _evidence_empty(finding: Finding) -> bool:
    evidence = finding.evidence
    required = (
        finding.scanner,
        finding.scanner_version,
        evidence.scanner,
        evidence.scanner_version,
        evidence.rule_id,
        evidence.summary,
    )
    return any(item.strip() == "" for item in required)


def _failed(
    scanner: Scanner,
    probe: ProbeResult,
    duration_ms: int,
    reason: str,
    limitations: list[str] | None = None,
) -> _Outcome:
    return _Outcome(
        status="failed",
        duration_ms=duration_ms,
        reason=reason,
        findings=[],
        skips=[SkippedScanner(name=scanner.name, reason=reason, failed=True)],
        limitations=list(limitations or ()),
        requests=(),
        tool_version=probe.version or None,
    )


@dataclass(frozen=True)
class _Outcome:
    status: Literal["executed", "failed"]
    duration_ms: int
    reason: str | None
    findings: list[Finding]
    skips: list[SkippedScanner]
    limitations: list[str]
    requests: tuple[RequestRecord, ...]
    tool_version: str | None


def _store_outcome(
    scanner: Scanner,
    probe: ProbeResult,
    outcome: _Outcome,
    build: _ReportBuild,
) -> None:
    build.rows.append(
        _Row(
            name=scanner.name,
            version=scanner.version,
            rule_pack_version=scanner.rule_pack_version,
            tool_version=probe.version or None,
            duration_ms=outcome.duration_ms,
            status=outcome.status,
            reason=outcome.reason,
            findings=list(outcome.findings),
        )
    )
    build.skips.extend(outcome.skips)
    build.limitations.extend(outcome.limitations)
    if outcome.status == "executed":
        _collect_requests(scanner.name, outcome.requests, build)


def _collect_requests(
    scanner_name: str,
    requests: tuple[RequestRecord, ...],
    build: _ReportBuild,
) -> None:
    for record in requests:
        _collect_request(scanner_name, record, build)


def _collect_request(scanner_name: str, record: RequestRecord, build: _ReportBuild) -> None:
    """Recording backstop. This does not classify and does not send."""
    reason = (
        "withheld "
        f"{_one_line(record.request_class, fallback='unknown')} "
        f"{_one_line(record.method, fallback='UNKNOWN')} "
        f"{_one_line(record.path, fallback='/')}"
    )
    if _may_record_sent(record, confirm=build.confirm):
        build.sent.append(
            SentRequest(method=record.method.strip().upper(), path=record.path.strip())
        )
        return
    build.skips.append(SkippedScanner(name=scanner_name, reason=reason, failed=False))
    klass = record.request_class.strip()
    method = record.method.strip()
    path = record.path.strip()
    if klass in _REQUEST_CLASSES and method and path:
        build.withheld.append(WithheldRequest(request_class=klass, method=method, path=path))


def _may_record_sent(record: RequestRecord, *, confirm: bool) -> bool:
    if not record.sent:
        return False
    method = record.method.strip().upper()
    klass = record.request_class.strip()
    if klass not in _REQUEST_CLASSES or method not in _SENT_METHODS or not record.path.strip():
        return False
    if klass == "state_changing":
        return False
    if klass == "ambiguous":
        return confirm
    return klass == "read_candidate"


def _collapse(build: _ReportBuild) -> list[Finding]:
    seen: set[str] = set()
    ordered: list[Finding] = []
    for row in build.rows:
        kept: list[Finding] = []
        for finding in row.findings:
            if finding.fingerprint in seen:
                build.limitations.append(
                    "duplicate finding collapsed for "
                    f"{finding.scanner} {finding.evidence.rule_id}"
                )
                continue
            seen.add(finding.fingerprint)
            kept.append(finding)
            ordered.append(finding)
        row.findings = kept
    ordered.sort(key=_finding_sort_key)
    return ordered


def _finding_sort_key(finding: Finding) -> tuple[object, ...]:
    line = finding.location.line
    line_key = (-1, 0) if line is None else (0, line)
    return (
        _SEVERITY_RANK[finding.severity],
        finding.location.path or "",
        line_key,
        finding.evidence.rule_id,
    )


def _report(
    ctx: ScanContext,
    *,
    components: tuple[Component, ...],
    findings: list[Finding],
    build: _ReportBuild,
    strict_failure: bool,
    duration_ms: int,
) -> ScanReport:
    executed: list[ExecutedScanner] = []
    for row in build.rows:
        run = ScannerRun(
            name=row.name,
            version=row.version,
            rule_pack_version=row.rule_pack_version,
            tool_version=row.tool_version,
            duration_ms=row.duration_ms,
            status=ScannerRunStatus(row.status),
            finding_count=len(row.findings),
            reason=row.reason,
        )
        executed.append(
            ExecutedScanner(
                name=run.name,
                version=run.version,
                rule_pack_version=run.rule_pack_version,
                tool_version=run.tool_version,
                duration_ms=run.duration_ms,
                status=run.status.value,
                finding_count=run.finding_count,
                reason=run.reason,
            )
        )
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    target = ctx.url if ctx.url is not None else str(ctx.target)
    return ScanReport(
        sentinel_version=__version__,
        scan_id=ctx.scan_id,
        target=target,
        url=ctx.url,
        mode=ctx.mode.value,
        started_at=ctx.started_at,
        finished_at=ctx.started_at + timedelta(milliseconds=duration_ms),
        duration_ms=duration_ms,
        components=[_report_component(component) for component in components],
        scanners=ScannerSection(executed=executed, skipped=list(build.skips)),
        dynamic_requests=DynamicRequests(sent=list(build.sent), withheld=list(build.withheld)),
        totals=Totals(**counts),
        strict_failure=strict_failure,
        limitations=list(build.limitations),
        findings=findings,
        comparison=None,
    )


def _report_component(component: Component) -> ReportComponent:
    return ReportComponent(
        component_id=component.component_id,
        languages=list(component.languages),
        frameworks=list(component.frameworks),
        evidence=list(component.evidence),
        kind=component.kind,
    )


def _plugin_skip(scanner: Scanner, skip: ScannerSkip) -> SkippedScanner:
    name = _one_line(skip.name, fallback=scanner.name)
    reason = _one_line(skip.reason, fallback="scanner skip")
    return SkippedScanner(name=name, reason=reason, failed=skip.failed)


def _scanner_failure(scanner: Scanner, exc: ScannerError) -> str:
    detail = _one_line(str(exc), fallback=type(exc).__name__)
    return f"scanner {scanner.name} failed: {detail}"


def _one_line(text: str, *, fallback: str) -> str:
    raw = text.splitlines()[0] if text else ""
    cleaned = "".join(char for char in raw if char.isprintable()).strip()
    if len(cleaned) > 300:
        cleaned = cleaned[:300]
    return cleaned or fallback


def _elapsed_ms(now: float, started: float) -> int:
    elapsed = now - started
    if elapsed <= 0:
        return 0
    return int(elapsed * 1000)


def _clock_start(build: _ReportBuild) -> float:
    return build.started


def _signal_recorded(records: list[RecordedGroup]) -> None:
    for record in records:
        signal_group(record)


def _confirm_group(pid: object) -> RecordedGroup | None:
    if isinstance(pid, bool) or not isinstance(pid, int):
        return None
    if pid <= 1 or pid == os.getpid():
        return None
    try:
        pgid = os.getpgid(pid)
    except OSError:
        return None
    if pgid != pid or pgid <= 1 or pgid == os.getpgrp() or pgid == os.getpid():
        return None
    starttime = _read_starttime(pid)
    if starttime is None:
        return None
    return RecordedGroup(pid=pid, pgid=pgid, starttime=starttime)


def _read_starttime(pid: int) -> int | None:
    if pid <= 0:
        return None
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    return parse_proc_starttime(text)
