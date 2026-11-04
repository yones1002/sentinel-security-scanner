"""Engine lifecycle tests. Scanners here are fakes. No Docker and no sockets."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel import __version__
from sentinel.config import (
    Authorization,
    ComponentOverride,
    DetectLimits,
    ScanConfig,
)
from sentinel.detect import Assignment, Detection, assign_component_id
from sentinel.engine import (
    BANDIT_DISABLED_REASON,
    HISTORY_UNAVAILABLE,
    OUTSIDE_TARGET_REASON,
    STRICT_DYNAMIC_SKIP,
    RecordedGroup,
    parse_proc_starttime,
    remember_group,
    run_scan,
    signal_group,
)
from sentinel.errors import ScanFailure, ScannerError, UsageError
from sentinel.fingerprint import fingerprint
from sentinel.fs import OpenInsideResult, open_inside
from sentinel.models import (
    Component,
    ComponentKind,
    Evidence,
    Finding,
    FindingKind,
    Framework,
    Location,
    Recommendation,
    Severity,
)
from sentinel.protocols import (
    ComponentScanTarget,
    DynamicSession,
    ProbeResult,
    RequestRecord,
    ScanContext,
    ScanMode,
    ScannerScope,
    ScanPluginResult,
)
from sentinel.registry import builtin_scanners, enforce_registration, renderers
from sentinel.sandbox.unavailable import DYNAMIC_UNAVAILABLE, UnavailableDynamicRuntime

VERSION = "1.2.3"


class FakeScanner:
    """In-process scanner double. It does not start a tool unless a test does."""

    def __init__(
        self,
        name: str = "fake",
        *,
        modes: frozenset[str] = frozenset({"static"}),
        scope: ScannerScope = ScannerScope.ROOT,
        timeout_s: int = 30,
        version: str = VERSION,
        probe=None,
        supports=None,
        scan=None,
    ) -> None:
        self.name = name
        self.version = version
        self.rule_pack_version = None
        self.timeout_s = timeout_s
        self.modes = modes
        self.scope = scope
        self.probe_calls = 0
        self.scan_calls: list[tuple[ScanContext, ComponentScanTarget]] = []
        self._probe = probe or (lambda ctx: ProbeResult(True, None, None))
        self._supports = supports or (lambda component: True)
        self._scan = scan or (lambda ctx, target: ScanPluginResult(findings=()))

    def probe(self, ctx: ScanContext) -> ProbeResult:
        self.probe_calls += 1
        return self._probe(ctx)

    def supports(self, component: Component) -> bool:
        return self._supports(component)

    def scan(self, ctx: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        self.scan_calls.append((ctx, target))
        return self._scan(ctx, target)


class FakeRuntime:
    def __init__(self, session: DynamicSession | None = None) -> None:
        self.calls: list[ScanContext] = []
        self.session = session or DynamicSession(
            base_url="http://127.0.0.1:9",
            limitations=(),
            handle=None,
        )

    def prepare(self, ctx: ScanContext) -> DynamicSession | None:
        self.calls.append(ctx)
        return self.session


class _Registered:
    def __init__(self, name: str, modes: frozenset[str], timeout_s: int) -> None:
        self.name = name
        self.modes = modes
        self.timeout_s = timeout_s


def _config(**kwargs: object) -> ScanConfig:
    values: dict[str, object] = {
        "detect": DetectLimits(),
        "strict_tools": False,
        "fail_on": "none",
        "history": False,
        "semgrep_config": None,
        "component_overrides": (),
        "ignores": (),
        "confirm_ambiguous_reads": False,
    }
    values.update(kwargs)
    return ScanConfig(**values)  # type: ignore[arg-type]


def _context(tmp_path: Path, **kwargs: object) -> ScanContext:
    work = kwargs.pop("work_dir", tmp_path / "work")
    assert isinstance(work, Path)
    work.mkdir(exist_ok=True)
    if "target" not in kwargs:
        target = tmp_path / "repo"
        target.mkdir(exist_ok=True)
        kwargs["target"] = target
    values: dict[str, object] = {
        "scan_id": str(uuid.uuid4()),
        "mode": ScanMode.STATIC,
        "url": None,
        "url_host": None,
        "pinned_address": None,
        "started_at": datetime.now(UTC),
        "components": (),
        "config": _config(),
        "authorization": Authorization(attested=True),
        "work_dir": work,
        "dynamic_session": None,
    }
    values.update(kwargs)
    return ScanContext(**values)  # type: ignore[arg-type]


def _component(
    component_id: str,
    root: Path,
    *,
    kind: ComponentKind = ComponentKind.APPLICATION,
) -> Component:
    return Component(
        component_id=component_id,
        root=root,
        languages=(),
        frameworks=(),
        evidence=(),
        kind=kind,
    )


def _finding(
    *,
    scanner: str = "fake",
    version: str = VERSION,
    path: str | None = "a/main.go",
    line: int | None = 1,
    endpoint: str | None = None,
    rule_id: str = "rule.one",
    severity: Severity = Severity.LOW,
    component_id: str = "scanner-supplied",
    fingerprint_hex: str | None = None,
    title: str = "A pattern matched",
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        fingerprint=fingerprint_hex or ("ab" * 32),
        title=title,
        severity=severity,
        confidence="high",
        kind=FindingKind.POTENTIAL,
        location=Location(path=path, line=line, endpoint=endpoint),
        explanation="The scanner reported this pattern.",
        evidence=Evidence(
            scanner=scanner,
            scanner_version=version,
            summary="Pattern text without a secret.",
            rule_id=rule_id,
        ),
        remediation=Recommendation(
            what_is_wrong="A pattern matched in the tree.",
            why_dangerous="The match can still be a false positive.",
            where=path or endpoint or "endpoint",
            recommended_fix="Review the match and remove it if it is real.",
            how_to_verify="Re-run the scan and confirm the rule is absent.",
        ),
        references=[],
        scanner=scanner,
        scanner_version=version,
        false_positive_notes="A fixture match is still a match.",
        component_id=component_id,
    )


def _write(root: Path, relative: str, text: str = "package main\n") -> None:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _refuse_supports(component: Component) -> bool:
    raise AssertionError(f"supports called for {component.component_id}")


def _detect_as(components: tuple[Component, ...]):
    def fake(target: Path, limits: DetectLimits | None = None) -> Detection:
        del target, limits
        return Detection(components, (), False)

    return fake


def _run(ctx: ScanContext, *scanners: FakeScanner, dynamic: object | None = None, store=None):
    runtime = dynamic if dynamic is not None else UnavailableDynamicRuntime()
    return run_scan(ctx, scanners, dynamic=runtime, store=store)


def test_static_report_fields_and_context_are_not_mutated(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "notes.txt", "hello\n")
    seen: list[ScanContext] = []

    def scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        seen.append(ctx_seen)
        assert target.component.component_id == "."
        assert target.exclude_roots == ()
        return ScanPluginResult(findings=(_finding(path="notes.txt"),))

    scanner = FakeScanner(scan=scan, supports=_refuse_supports)
    report = _run(ctx, scanner)
    assert ctx.components == ()
    assert ctx.dynamic_session is None
    assert seen[0].dynamic_session is None
    assert seen[0].components[0].component_id == "."
    assert report.sentinel_version == __version__
    assert report.scan_id == ctx.scan_id
    assert report.target == str(ctx.target)
    assert report.url is None
    assert report.mode == "static"
    assert report.started_at == ctx.started_at
    assert report.finished_at.tzinfo is not None
    assert report.duration_ms >= 0
    assert report.comparison is None
    assert report.fingerprint_version == "v1"
    assert report.strict_failure is False
    assert report.findings[0].component_id == "."
    assert report.findings[0].fingerprint_version == "v1"
    assert len(report.scanners.executed) == 1
    assert report.scanners.executed[0].status == "executed"
    assert report.scanners.executed[0].finding_count == 1


def test_ownership_ranks_depth_not_string_length(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    root = ctx.target
    _write(root, "a/main.go")
    _write(root, "apps/api/.env", "CANARY\n")
    components = (
        _component(".", root, kind=ComponentKind.REPOSITORY),
        _component("a", root / "a"),
        _component("very-long-component-name", root / "very-long-component-name"),
        _component("apps", root / "apps"),
        _component("apps/api", root / "apps" / "api"),
    )
    (root / "very-long-component-name").mkdir()
    monkeypatch.setattr("sentinel.engine.detect", _detect_as(components))

    def scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del ctx_seen, target
        return ScanPluginResult(
            findings=(
                _finding(path="a/main.go", rule_id="rule.a"),
                _finding(path="apps/api/.env", rule_id="rule.env", line=1),
            )
        )

    report = _run(ctx, FakeScanner(scan=scan))
    by_rule = {item.evidence.rule_id: item.component_id for item in report.findings}
    assert by_rule == {"rule.a": "a", "rule.env": "apps/api"}
    assert len("very-long-component-name") > len("a")
    assert len(".") == len("a")


def test_suppressed_root_drops_path_and_endpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(
        tmp_path,
        config=_config(
            component_overrides=(ComponentOverride(".", (), True),),
        ),
    )
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "notes.txt", "note\n")
    monkeypatch.setattr(
        "sentinel.engine.detect",
        _detect_as((_component(".", ctx.target, kind=ComponentKind.REPOSITORY),)),
    )

    def scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del ctx_seen, target
        return ScanPluginResult(
            findings=(
                _finding(path="notes.txt", rule_id="rule.path"),
                _finding(path=None, line=None, endpoint="GET /health", rule_id="rule.http"),
            )
        )

    report = _run(ctx, FakeScanner(scan=scan))
    assert report.components == []
    assert report.findings == []
    assert "unassigned path dropped: notes.txt" in report.limitations
    assert "unassigned endpoint dropped" in report.limitations


def test_path_outside_remaining_components_is_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    (ctx.target / "apps").mkdir()
    _write(ctx.target, "notes.txt", "note\n")
    monkeypatch.setattr(
        "sentinel.engine.detect",
        _detect_as((_component("apps", ctx.target / "apps"),)),
    )
    scanner = FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=(_finding(path="notes.txt"),)))
    report = _run(ctx, scanner)
    assert report.findings == []
    assert "unassigned path dropped: notes.txt" in report.limitations


def test_ambiguous_assignment_drops_the_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "tie/main.go")
    real = assign_component_id("tie/main.go", (_component("tie", ctx.target), _component("tie", ctx.target)))
    assert real == Assignment(None, "ambiguous component for tie/main.go")

    def fake_assign(path: str, components: tuple[Component, ...]) -> Assignment:
        if path == "tie/main.go":
            return real
        return assign_component_id(path, components)

    monkeypatch.setattr("sentinel.engine.assign_component_id", fake_assign)
    report = _run(ctx, FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=(_finding(path="tie/main.go"),))))
    assert report.findings == []
    assert "ambiguous component for tie/main.go" in report.limitations


def test_duplicate_component_id_aborts_before_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    apps = _component("apps", ctx.target / "apps")
    monkeypatch.setattr("sentinel.engine.detect", _detect_as((apps, apps)))
    scanner = FakeScanner()
    with pytest.raises(ScanFailure, match="duplicate component_id apps"):
        _run(ctx, scanner)
    assert scanner.scan_calls == []


def test_unlistable_root_skips_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)

    def explode(target: Path, limits: DetectLimits | None = None) -> Detection:
        del target, limits
        raise ScanFailure("target root cannot be listed")

    def apply(*args: object, **kwargs: object) -> tuple[Component, ...]:
        raise AssertionError("overrides applied")

    monkeypatch.setattr("sentinel.engine.detect", explode)
    monkeypatch.setattr("sentinel.engine.apply_external_components", apply)
    scanner = FakeScanner()
    with pytest.raises(ScanFailure, match="target root cannot be listed"):
        _run(ctx, scanner)
    assert scanner.scan_calls == []


def test_file_cap_still_runs_static_scanners(tmp_path: Path) -> None:
    ctx = _context(tmp_path, config=_config(detect=DetectLimits(max_files=2)))
    assert isinstance(ctx.target, Path)
    for name in ("a.txt", "b.txt", "c.txt"):
        _write(ctx.target, name, "x\n")
    scanner = FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=()))
    report = _run(ctx, scanner)
    assert scanner.scan_calls
    assert "detection stopped: file cap 2 reached; results are incomplete" in report.limitations


def test_external_override_unions_a_label_without_changing_the_stamp(tmp_path: Path) -> None:
    ctx = _context(
        tmp_path,
        config=_config(
            component_overrides=(ComponentOverride(".", (Framework.LARAVEL,), False),),
        ),
    )
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "go.mod", "module example.com/demo\n")
    _write(ctx.target, "main.go")
    _write(ctx.target, "a/go.mod", "module example.com/demo/a\n")
    _write(ctx.target, "a/main.go")
    report = _run(
        ctx,
        FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=(_finding(path="a/main.go"),))),
    )
    assert report.findings[0].component_id == "a"
    root = next(item for item in report.components if item.component_id == ".")
    child = next(item for item in report.components if item.component_id == "a")
    assert Framework.LARAVEL in root.frameworks
    assert root.kind == ComponentKind.APPLICATION
    assert "go.mod" in root.evidence
    assert child.frameworks == []


def test_root_runs_once_and_component_scope_receives_exclude_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    root = ctx.target
    for relative in (".", "a", "a/b", "c"):
        directory = root if relative == "." else root.joinpath(*relative.split("/"))
        directory.mkdir(parents=True, exist_ok=True)
    components = (
        _component(".", root, kind=ComponentKind.REPOSITORY),
        _component("a", root / "a"),
        _component("a/b", root / "a" / "b"),
        _component("c", root / "c"),
    )
    monkeypatch.setattr("sentinel.engine.detect", _detect_as(components))
    root_scanner = FakeScanner(name="root-scan", supports=_refuse_supports)
    component_scanner = FakeScanner(name="component-scan", scope=ScannerScope.COMPONENT)
    _run(ctx, root_scanner, component_scanner)
    assert len(root_scanner.scan_calls) == 1
    assert root_scanner.scan_calls[0][1].component.component_id == "."
    assert root_scanner.scan_calls[0][1].exclude_roots == ()
    calls = {
        item.component.component_id: set(item.exclude_roots)
        for _ctx, item in component_scanner.scan_calls
    }
    assert set(calls) == {".", "a", "a/b", "c"}
    assert calls["."] == {(root / "a").resolve(), (root / "a" / "b").resolve(), (root / "c").resolve()}
    assert calls["a"] == {(root / "a" / "b").resolve()}
    assert calls["a/b"] == set()
    assert calls["c"] == set()


def test_unavailable_probe_does_not_scan(tmp_path: Path) -> None:
    ctx = _context(tmp_path)

    def scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        raise AssertionError("scan called")

    scanner = FakeScanner(
        probe=lambda ctx: ProbeResult(False, None, "semgrep not found on PATH"),
        scan=scan,
    )
    report = _run(ctx, scanner)
    assert report.scanners.executed == []
    assert report.scanners.skipped[0].reason == "semgrep not found on PATH"
    assert report.scanners.skipped[0].failed is False


def test_scanner_error_keeps_the_next_scanner(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "ok.txt", "ok\n")

    def fail(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del ctx_seen, target
        raise ScannerError("boom\nTraceback (most recent call last): SECRET-LINE")

    broken = FakeScanner(name="broken", scan=fail)
    healthy = FakeScanner(
        name="healthy",
        scan=lambda ctx, target: ScanPluginResult(
            findings=(_finding(scanner="healthy", path="ok.txt"),)
        ),
    )
    caplog.set_level("DEBUG", logger="sentinel.engine")
    report = _run(ctx, broken, healthy)
    assert [item.scanner for item in report.findings] == ["healthy"]
    assert report.scanners.executed[0].status == "failed"
    assert report.scanners.executed[1].status == "executed"
    assert report.scanners.skipped[0].reason == "scanner broken failed: boom"
    assert report.scanners.skipped[0].failed is True
    dumped = report.model_dump_json()
    assert "SECRET-LINE" not in dumped
    assert "Traceback" not in dumped
    assert "Traceback" in caplog.text


def test_engine_overwrites_fingerprint_and_drops_bad_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "ok.txt", "ok\n")
    hashed: list[int | None] = []
    real = fingerprint

    def spy(finding: Finding) -> str:
        hashed.append(finding.location.line)
        return real(finding)

    monkeypatch.setattr("sentinel.engine.fingerprint", spy)
    supplied = "cd" * 32
    report = _run(
        ctx,
        FakeScanner(
            scan=lambda ctx, target: ScanPluginResult(
                findings=(
                    _finding(path="ok.txt", line=1, fingerprint_hex=supplied, rule_id="kept"),
                    _finding(path="ok.txt", line=0, rule_id="bad-line"),
                    _finding(scanner="other", version="9.9.9", path="ok.txt", rule_id="bad-id"),
                )
            )
        ),
    )
    assert [item.evidence.rule_id for item in report.findings] == ["kept"]
    assert report.findings[0].fingerprint != supplied
    assert report.findings[0].fingerprint == fingerprint(report.findings[0])
    assert report.findings[0].fingerprint_version == "v1"
    assert hashed == [1]
    assert "finding dropped, invalid line" in report.limitations
    assert "finding dropped, scanner identity mismatch" in report.limitations


def test_empty_evidence_is_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "a/main.go")

    def explode(finding: Finding) -> Finding:
        raise ValueError("redaction removed required text")

    monkeypatch.setattr("sentinel.engine.redact_finding", explode)
    report = _run(ctx, FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=(_finding(),))))
    assert report.findings == []
    assert "finding dropped, empty evidence" in report.limitations
    assert report.scanners.executed[0].status == "executed"


def test_duplicate_fingerprints_collapse_and_other_scanners_remain(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "ok.txt", "ok\n")
    first = _finding(path="ok.txt", title="first")
    second = _finding(path="ok.txt", title="second")
    report = _run(
        ctx,
        FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=(first, second))),
        FakeScanner(
            name="other",
            scan=lambda ctx, target: ScanPluginResult(
                findings=(_finding(scanner="other", path="ok.txt", rule_id="rule.one"),)
            ),
        ),
    )
    assert [item.scanner for item in report.findings] == ["fake", "other"]
    assert report.findings[0].id == first.id
    assert report.scanners.executed[0].finding_count == 1
    assert "duplicate finding collapsed for fake rule.one" in report.limitations
    assert len(report.scanners.executed) == 2


def test_findings_sort_by_severity_path_line_and_rule(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    for name in ("a.txt", "m.txt", "z.txt"):
        _write(ctx.target, name, "x\n")
    findings = (
        _finding(path="z.txt", severity=Severity.CRITICAL, rule_id="z", line=3),
        _finding(path=None, line=None, endpoint="GET /a", rule_id="a", severity=Severity.LOW),
        _finding(path="a.txt", line=None, rule_id="b", severity=Severity.LOW),
        _finding(path="a.txt", line=1, rule_id="m", severity=Severity.LOW),
        _finding(path="a.txt", line=1, rule_id="a", severity=Severity.LOW),
        _finding(path="m.txt", severity=Severity.HIGH, rule_id="h", line=1),
    )
    report = _run(ctx, FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=findings)))
    assert [
        (item.severity, item.location.path, item.location.line, item.evidence.rule_id)
        for item in report.findings
    ] == [
        (Severity.CRITICAL, "z.txt", 3, "z"),
        (Severity.HIGH, "m.txt", 1, "h"),
        (Severity.LOW, None, None, "a"),
        (Severity.LOW, "a.txt", None, "b"),
        (Severity.LOW, "a.txt", 1, "a"),
        (Severity.LOW, "a.txt", 1, "m"),
    ]


def test_outside_path_drops_the_whole_invocation(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "ok.txt", "safe\n")
    report = _run(
        ctx,
        FakeScanner(
            scan=lambda ctx, target: ScanPluginResult(
                findings=(
                    _finding(path="ok.txt", rule_id="inside"),
                    _finding(path="/etc/passwd", rule_id="absolute"),
                    _finding(path="../outside.txt", rule_id="parent"),
                )
            )
        ),
    )
    assert report.findings == []
    assert report.scanners.executed[0].status == "failed"
    assert report.scanners.skipped[0].reason == OUTSIDE_TARGET_REASON
    assert report.scanners.skipped[0].failed is True
    assert "dropped 2 tool paths outside target" in report.limitations


def test_outside_symlink_drops_the_whole_invocation(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "ok.txt", "safe\n")
    (ctx.target / "escape").symlink_to("/etc/passwd")
    report = _run(
        ctx,
        FakeScanner(
            scan=lambda ctx, target: ScanPluginResult(
                findings=(
                    _finding(path="ok.txt", rule_id="inside"),
                    _finding(path="escape", rule_id="link"),
                )
            )
        ),
    )
    assert report.findings == []
    assert report.scanners.executed[0].status == "failed"
    assert "dropped 1 tool paths outside target" in report.limitations


def test_inside_refusals_drop_only_that_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    root = ctx.target
    _write(root, "ok.txt", "safe\n")
    (root / "broken").symlink_to(root / "missing-target")
    os.mkfifo(root / "pipe")
    (root / "sub").mkdir()
    (root / "linkdir").symlink_to(root / "sub", target_is_directory=True)
    real = open_inside

    def fake(path_root: Path, candidate: Path | str, max_bytes: int | None = None) -> OpenInsideResult:
        text = candidate.as_posix() if isinstance(candidate, Path) else candidate
        if text == "secret.txt":
            return OpenInsideResult(None, None, "permission denied: secret.txt")
        if text == "raced.txt":
            return OpenInsideResult(None, None, "refused inode mismatch: raced.txt")
        return real(path_root, candidate, max_bytes)

    monkeypatch.setattr("sentinel.engine.open_inside", fake)
    report = _run(
        ctx,
        FakeScanner(
            scan=lambda ctx, target: ScanPluginResult(
                findings=(
                    _finding(path="ok.txt", rule_id="kept"),
                    _finding(path="secret.txt", rule_id="denied"),
                    _finding(path="raced.txt", rule_id="inode"),
                    _finding(path="gone.txt", rule_id="missing"),
                    _finding(path="broken", rule_id="broken"),
                    _finding(path="pipe", rule_id="fifo"),
                    _finding(path="linkdir", rule_id="dirlink"),
                    _finding(path="bad\x00name", rule_id="nul"),
                    _finding(path="dir\\file.txt", rule_id="slash"),
                )
            )
        ),
    )
    assert [item.evidence.rule_id for item in report.findings] == ["kept"]
    assert report.scanners.executed[0].status == "executed"
    assert report.scanners.executed[0].finding_count == 1
    for expected in (
        "permission denied: secret.txt",
        "refused inode mismatch: raced.txt",
        "unreadable path: gone.txt",
        "skipped broken symlink: broken",
        "refused non-regular file: pipe",
        "refused directory symlink: linkdir",
        "refused NUL in path",
        "refused backslash in path",
    ):
        assert expected in report.limitations


def test_read_skipped_inside_file_is_kept_without_reading_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "secret.txt", "CANARY-SECRET-BYTES\n")
    seen: list[int | None] = []
    real = open_inside

    def spy(root: Path, candidate: Path | str, max_bytes: int | None = None) -> OpenInsideResult:
        seen.append(max_bytes)
        return real(root, candidate, max_bytes)

    monkeypatch.setattr("sentinel.engine.open_inside", spy)
    report = _run(
        ctx,
        FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=(_finding(path="secret.txt"),))),
    )
    assert seen == [0]
    assert len(report.findings) == 1
    assert "CANARY-SECRET-BYTES" not in report.model_dump_json()


def test_pure_python_timeout_discards_findings_without_killpg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = _context(tmp_path)
    clock = {"now": 20.0}
    monkeypatch.setattr("sentinel.engine.time.monotonic", lambda: clock["now"])

    def kill(pgid: int, sig: int) -> None:
        raise AssertionError(f"killpg {pgid} {sig}")

    monkeypatch.setattr(os, "killpg", kill)

    def scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del ctx_seen, target
        assert remember_group(0) is None
        assert remember_group(1) is None
        assert remember_group(os.getpid()) is None
        assert remember_group(os.getpgrp()) is None
        clock["now"] += 11
        return ScanPluginResult(findings=(_finding(),))

    scanner = FakeScanner(timeout_s=10, scan=scan)
    report = _run(ctx, scanner)
    assert report.findings == []
    assert report.scanners.executed[0].status == "failed"
    assert report.scanners.skipped[0].reason == "timeout after 10s"
    assert report.scanners.skipped[0].failed is True


def test_timeout_expired_without_a_group_does_not_signal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)

    def kill(pgid: int, sig: int) -> None:
        raise AssertionError(f"killpg {pgid} {sig}")

    monkeypatch.setattr(os, "killpg", kill)

    def scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del ctx_seen, target
        error = subprocess.TimeoutExpired("tool", 1)
        error.pid = os.getpid()  # type: ignore[attr-defined]
        raise error

    report = _run(ctx, FakeScanner(timeout_s=7, scan=scan))
    assert report.findings == []
    assert report.scanners.skipped[0].reason == "timeout after 7s"


def test_only_a_matching_recorded_group_is_signaled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)
    clock = {"now": 5.0}
    procs: dict[str, subprocess.Popen[bytes]] = {}
    saved: dict[str, RecordedGroup] = {}
    calls: list[int] = []
    real_killpg = os.killpg

    def spy(pgid: int, sig: int) -> None:
        calls.append(pgid)
        if "a" not in procs or pgid != procs["a"].pid:
            raise AssertionError(f"unexpected signal {pgid}")
        real_killpg(pgid, sig)

    outsider = subprocess.Popen(["sleep", "30"], start_new_session=True)
    try:
        assert remember_group(outsider.pid) is None
        assert outsider.poll() is None
    finally:
        if outsider.poll() is None:
            real_killpg(outsider.pid, signal.SIGKILL)
            outsider.wait(timeout=5)

    monkeypatch.setattr(os, "killpg", spy)
    monkeypatch.setattr("sentinel.engine.time.monotonic", lambda: clock["now"])

    def scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del ctx_seen, target
        procs["a"] = subprocess.Popen(["sleep", "30"], start_new_session=True)
        procs["b"] = subprocess.Popen(["sleep", "30"], start_new_session=True)
        record = remember_group(procs["a"].pid)
        assert record is not None
        saved["a"] = record
        stat = Path(f"/proc/{procs['b'].pid}/stat").read_text(encoding="utf-8")
        start_b = parse_proc_starttime(stat)
        assert start_b is not None
        assert signal_group(RecordedGroup(procs["b"].pid, procs["b"].pid, start_b + 1)) is False
        assert procs["b"].poll() is None
        clock["now"] += 9
        return ScanPluginResult(findings=(_finding(),))

    try:
        report = _run(ctx, FakeScanner(timeout_s=8, scan=scan))
        procs["a"].wait(timeout=5)
        assert procs["b"].poll() is None
        assert calls == [procs["a"].pid]
        assert report.findings == []
        assert report.scanners.skipped[0].reason == "timeout after 8s"
        calls.clear()
        assert signal_group(saved["a"]) is False
        assert calls == []
        assert procs["b"].poll() is None
    finally:
        for proc in procs.values():
            if proc.poll() is None:
                real_killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)


def test_timeout_expired_kills_only_the_recorded_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)
    procs: dict[str, subprocess.Popen[bytes]] = {}
    real_killpg = os.killpg

    def spy(pgid: int, sig: int) -> None:
        if pgid != procs["a"].pid:
            raise AssertionError(f"unexpected signal {pgid}")
        real_killpg(pgid, sig)

    monkeypatch.setattr(os, "killpg", spy)

    def scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del ctx_seen, target
        procs["a"] = subprocess.Popen(["sleep", "30"], start_new_session=True)
        procs["b"] = subprocess.Popen(["sleep", "30"], start_new_session=True)
        assert remember_group(procs["a"].pid) is not None
        error = subprocess.TimeoutExpired("tool", 1)
        error.pid = procs["b"].pid  # type: ignore[attr-defined]
        raise error

    try:
        report = _run(ctx, FakeScanner(timeout_s=4, scan=scan))
        procs["a"].wait(timeout=5)
        assert procs["b"].poll() is None
        assert report.scanners.skipped[0].reason == "timeout after 4s"
        assert report.findings == []
    finally:
        for proc in procs.values():
            if proc.poll() is None:
                real_killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)


def test_starttime_parser_reads_field_22() -> None:
    after = ["S", *["0"] * 18, "4242", "99"]
    text = "3 (python (test)) " + " ".join(after)
    assert parse_proc_starttime(text) == 4242
    assert parse_proc_starttime("no paren here") is None
    assert parse_proc_starttime("1 (x) S 1") is None
    assert parse_proc_starttime("1 (x) " + " ".join(["S", *["no"] * 19])) is None
    raw = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="utf-8")
    fields = raw[raw.rfind(")") + 1 :].split()
    assert parse_proc_starttime(raw) == int(fields[19])


def test_registration_ceiling_and_empty_builtins() -> None:
    with pytest.raises(UsageError, match="timeout_s 601 exceeds 600"):
        enforce_registration((_Registered("surface", frozenset({"static"}), 601),))
    with pytest.raises(UsageError, match="timeout_s 181 exceeds 180"):
        enforce_registration((_Registered("http", frozenset({"dynamic"}), 181),))
    with pytest.raises(UsageError, match="timeout_s 181 exceeds 180"):
        enforce_registration((_Registered("both", frozenset({"static", "dynamic"}), 181),))
    enforce_registration((_Registered("surface", frozenset({"static"}), 600),))
    enforce_registration((_Registered("http", frozenset({"dynamic"}), 180),))
    enforce_registration((_Registered("both", frozenset({"static", "dynamic"}), 180),))
    with pytest.raises(UsageError, match="duplicate scanner name surface"):
        enforce_registration(
            (
                _Registered("surface", frozenset({"static"}), 30),
                _Registered("surface", frozenset({"static"}), 30),
            )
        )
    assert renderers() == ()
    registered = builtin_scanners()
    assert [item.name for item in registered] == ["surface"]
    assert registered[0].scope == ScannerScope.ROOT
    assert registered[0].modes == frozenset({"static"})
    assert registered[0].timeout_s == 60
    names = [item.name for item in registered]
    assert len(names) == len(set(names))


def test_engine_does_not_clamp_a_legal_or_oversized_timeout(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    assert isinstance(ctx.target, Path)
    _write(ctx.target, "ok.txt", "ok\n")
    report = _run(
        ctx,
        FakeScanner(
            timeout_s=601,
            scan=lambda ctx, target: ScanPluginResult(findings=(_finding(path="ok.txt"),)),
        ),
    )
    assert len(report.findings) == 1
    assert report.scanners.executed[0].status == "executed"


def test_static_mode_does_not_prepare(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    runtime = UnavailableDynamicRuntime()
    report = _run(ctx, FakeScanner(), dynamic=runtime)
    assert report.mode == "static"
    assert report.strict_failure is False


def test_dynamic_mode_raises_before_a_probe(tmp_path: Path) -> None:
    ctx = _context(tmp_path, mode=ScanMode.DYNAMIC)
    scanner = FakeScanner(modes=frozenset({"dynamic"}))
    with pytest.raises(UsageError) as caught:
        _run(ctx, scanner, dynamic=UnavailableDynamicRuntime())
    assert str(caught.value) == DYNAMIC_UNAVAILABLE
    assert scanner.probe_calls == 0
    assert ctx.dynamic_session is None


def test_all_mode_runs_static_then_raises_before_dynamic(tmp_path: Path) -> None:
    ctx = _context(tmp_path, mode=ScanMode.ALL)
    ran = {"static": False}

    def static_scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del ctx_seen, target
        ran["static"] = True
        return ScanPluginResult(findings=())

    static_scanner = FakeScanner(scan=static_scan)
    dynamic_scanner = FakeScanner(name="http", modes=frozenset({"dynamic"}))
    with pytest.raises(UsageError) as caught:
        _run(ctx, static_scanner, dynamic_scanner, dynamic=UnavailableDynamicRuntime())
    assert str(caught.value) == DYNAMIC_UNAVAILABLE
    assert ran["static"] is True
    assert dynamic_scanner.probe_calls == 0
    assert ctx.dynamic_session is None


def test_strict_tools_skips_prepare_on_mode_all(tmp_path: Path) -> None:
    ctx = _context(tmp_path, mode=ScanMode.ALL, config=_config(strict_tools=True))
    runtime = FakeRuntime()
    static_scanner = FakeScanner(
        probe=lambda ctx: ProbeResult(False, None, "semgrep not found on PATH")
    )
    dynamic_scanner = FakeScanner(name="http", modes=frozenset({"dynamic"}))
    report = _run(ctx, static_scanner, dynamic_scanner, dynamic=runtime)
    assert runtime.calls == []
    assert dynamic_scanner.probe_calls == 0
    assert report.strict_failure is True
    assert STRICT_DYNAMIC_SKIP in report.limitations


def test_static_strict_failure_does_not_mention_dynamic(tmp_path: Path) -> None:
    ctx = _context(tmp_path, config=_config(strict_tools=True))
    scanner = FakeScanner(probe=lambda ctx: ProbeResult(False, None, "semgrep not found on PATH", failed=True))
    report = _run(ctx, scanner, dynamic=UnavailableDynamicRuntime())
    assert report.strict_failure is True
    assert STRICT_DYNAMIC_SKIP not in report.limitations


def test_bandit_disabled_reason_does_not_set_strict_failure(tmp_path: Path) -> None:
    ctx = _context(tmp_path, mode=ScanMode.ALL, config=_config(strict_tools=True))
    runtime = FakeRuntime()
    scanner = FakeScanner(
        probe=lambda ctx: ProbeResult(False, None, BANDIT_DISABLED_REASON, failed=False)
    )
    report = _run(ctx, scanner, dynamic=runtime)
    assert report.strict_failure is False
    assert STRICT_DYNAMIC_SKIP not in report.limitations
    assert len(runtime.calls) == 1
    assert runtime.calls[0] is ctx
    assert ctx.dynamic_session is None


def test_request_records_do_not_open_a_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("socket opened")

    monkeypatch.setattr(socket, "socket", fail_open)
    ctx = _context(tmp_path)
    records = (
        RequestRecord("state_changing", "GET", "/logout", True),
        RequestRecord("read_candidate", "POST", "/items", True),
        RequestRecord("ambiguous", "GET", "/maybe", True),
        RequestRecord("read_candidate", "GET", "/health", False),
        RequestRecord("read_candidate", "GET", "/status", True),
        RequestRecord("read_candidate", "HEAD", "/meta", True),
    )
    report = _run(
        ctx,
        FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=(), requests=records)),
    )
    assert [(item.method, item.path) for item in report.dynamic_requests.sent] == [
        ("GET", "/status"),
        ("HEAD", "/meta"),
    ]
    withheld = [
        (item.request_class, item.method, item.path) for item in report.dynamic_requests.withheld
    ]
    assert withheld == [
        ("state_changing", "GET", "/logout"),
        ("read_candidate", "POST", "/items"),
        ("ambiguous", "GET", "/maybe"),
        ("read_candidate", "GET", "/health"),
    ]
    reasons = [item.reason for item in report.scanners.skipped]
    assert "withheld state_changing GET /logout" in reasons
    assert "withheld read_candidate POST /items" in reasons
    assert "withheld ambiguous GET /maybe" in reasons
    assert all(item.failed is False for item in report.scanners.skipped)
    assert report.findings == []


def test_confirm_flag_releases_only_ambiguous_get(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("socket opened")

    monkeypatch.setattr(socket, "socket", fail_open)
    ctx = _context(tmp_path, config=_config(confirm_ambiguous_reads=True))
    records = (
        RequestRecord("ambiguous", "GET", "/maybe", True),
        RequestRecord("state_changing", "GET", "/logout", True),
        RequestRecord("ambiguous", "POST", "/pay", True),
        RequestRecord("read_candidate", "GET", "/status", True),
        RequestRecord("state_changing", "HEAD", "/wipe", True),
    )
    report = _run(
        ctx,
        FakeScanner(scan=lambda ctx, target: ScanPluginResult(findings=(), requests=records)),
    )
    assert [(item.method, item.path) for item in report.dynamic_requests.sent] == [
        ("GET", "/maybe"),
        ("GET", "/status"),
    ]
    withheld = [
        (item.request_class, item.method, item.path) for item in report.dynamic_requests.withheld
    ]
    assert ("state_changing", "GET", "/logout") in withheld
    assert ("ambiguous", "POST", "/pay") in withheld
    assert ("state_changing", "HEAD", "/wipe") in withheld


def test_history_store_is_refused_before_detect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path)

    def explode(target: Path, limits: DetectLimits | None = None) -> Detection:
        raise AssertionError("detect called")

    monkeypatch.setattr("sentinel.engine.detect", explode)
    with pytest.raises(UsageError) as caught:
        _run(ctx, FakeScanner(), store=object())
    assert str(caught.value) == HISTORY_UNAVAILABLE


def test_url_mode_does_not_treat_the_component_as_a_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    ctx = _context(
        tmp_path,
        mode=ScanMode.DYNAMIC,
        target=None,
        url="https://example.test/app",
        url_host="example.test",
        work_dir=work,
    )

    def detect_called(target: Path, limits: DetectLimits | None = None) -> Detection:
        raise AssertionError("detect called")

    def opened(*args: object, **kwargs: object) -> OpenInsideResult:
        raise AssertionError("open_inside called")

    monkeypatch.setattr("sentinel.engine.detect", detect_called)
    monkeypatch.setattr("sentinel.engine.open_inside", opened)

    def root_scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        assert ctx_seen.dynamic_session is not None
        assert target.component.component_id == "url"
        assert target.component.kind == ComponentKind.REPOSITORY
        assert target.component.frameworks == ()
        assert target.component.languages == ()
        assert target.exclude_roots == ()
        assert target.component.root == work / "url-component"
        assert not target.component.root.exists()
        return ScanPluginResult(
            findings=(
                _finding(scanner="passive", path="README", rule_id="path"),
                _finding(
                    scanner="passive",
                    path=None,
                    line=None,
                    endpoint="GET /health",
                    rule_id="http",
                ),
            )
        )

    def component_scan(ctx_seen: ScanContext, target: ComponentScanTarget) -> ScanPluginResult:
        del ctx_seen
        assert target.exclude_roots == ()
        assert not target.component.root.exists()
        return ScanPluginResult(findings=())

    report = _run(
        ctx,
        FakeScanner(name="passive", modes=frozenset({"dynamic"}), scan=root_scan),
        FakeScanner(
            name="per-component",
            modes=frozenset({"dynamic"}),
            scope=ScannerScope.COMPONENT,
            scan=component_scan,
        ),
        dynamic=FakeRuntime(),
    )
    assert not (work / "url-component").exists()
    assert report.target == "https://example.test/app"
    assert report.url == "https://example.test/app"
    assert len(report.components) == 1
    assert report.components[0].component_id == "url"
    assert report.components[0].kind == ComponentKind.REPOSITORY
    assert report.components[0].frameworks == []
    assert report.components[0].languages == []
    assert report.components[0].evidence == ["example.test"]
    assert [item.evidence.rule_id for item in report.findings] == ["http"]
    assert report.findings[0].component_id == "url"
    assert report.findings[0].location.path is None
    assert "unassigned path dropped: README" in report.limitations


def test_url_absolute_path_wipes_without_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(
        tmp_path,
        mode=ScanMode.DYNAMIC,
        target=None,
        url="https://example.test/app",
        url_host="example.test",
    )

    def opened(*args: object, **kwargs: object) -> OpenInsideResult:
        raise AssertionError("open_inside called")

    monkeypatch.setattr("sentinel.engine.open_inside", opened)
    report = _run(
        ctx,
        FakeScanner(
            modes=frozenset({"dynamic"}),
            scan=lambda ctx, target: ScanPluginResult(
                findings=(
                    _finding(path="/etc/passwd", rule_id="abs"),
                    _finding(path=None, line=None, endpoint="GET /health", rule_id="http"),
                )
            ),
        ),
        dynamic=FakeRuntime(),
    )
    assert report.findings == []
    assert report.scanners.skipped[0].reason == OUTSIDE_TARGET_REASON
    assert "dropped 1 tool paths outside target" in report.limitations
