"""Semgrep adapter tests. A fake executable stands in for the real binary."""

from __future__ import annotations

import ast
import json
import signal
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel import __version__
from sentinel.config import Authorization, DetectLimits, ScanConfig
from sentinel.engine import OUTSIDE_TARGET_REASON, run_scan
from sentinel.models import Confidence, FindingKind, Severity
from sentinel.protocols import ScanContext, ScanMode
from sentinel.recommendations import PATTERN_DISCLAIMER
from sentinel.sandbox.unavailable import UnavailableDynamicRuntime
from sentinel.scanners.semgrep import (
    EMPTY_REMEDIATION_REASON,
    GITIGNORE_LIMITATION,
    MISSING_CHECK_REASON,
    NO_CONFIG_REASON,
    NOFOLLOW_REASON,
    NON_JSON_REASON,
    NOT_FOUND_REASON,
    SEMGREPIGNORE_REASON,
    VERSION_FAILED_REASON,
    SemgrepScanner,
    _rule_pack_token,
    finding_from_semgrep,
    semgrep_title,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "semgrep" / "marker.yml"
_CANARY = "CANARY-OUTSIDE-BYTES"
_SCRIPT = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
row = {"argv": sys.argv[1:], "cwd": os.getcwd(), "env": dict(os.environ)}
with (here / "invocations.jsonl").open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(row) + "\\n")
args = sys.argv[1:]
if args == ["--version"]:
    sys.stdout.write((here / "version.txt").read_text(encoding="utf-8"))
    raise SystemExit(int((here / "version_code.txt").read_text(encoding="utf-8")))
if "--help" in args:
    sys.stdout.write((here / "help.txt").read_text(encoding="utf-8"))
    raise SystemExit(0)
sys.stdout.buffer.write((here / "stdout.bin").read_bytes())
raise SystemExit(int((here / "code.txt").read_text(encoding="utf-8")))
"""
_HELP_READY = """Usage: semgrep scan

  --first-token  .semgrepignore files are not read
  --second-token  disable project .semgrepignore
  --git-token  .gitignore rules are not applied
"""
_HELP_NO_SEMGREPIGNORE = """Usage: semgrep scan

  --git-token  .gitignore rules are not applied
"""
_HELP_NO_GITIGNORE = """Usage: semgrep scan

  --first-token  .semgrepignore files are not read
"""
_HELP_NOFOLLOW = """Usage: semgrep scan

  --first-token  .semgrepignore files are not read
  --git-token  .gitignore rules are not applied
  --follow-token  symlinks are not followed
"""


def _config(path: Path | None) -> ScanConfig:
    return ScanConfig(
        detect=DetectLimits(),
        strict_tools=False,
        fail_on="none",
        history=False,
        semgrep_config=path,
        component_overrides=(),
        ignores=(),
    )


def _context(tmp_path: Path, *, config: Path | None, target: Path | None = None) -> ScanContext:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    if target is None:
        target = tmp_path / "repo"
        target.mkdir(exist_ok=True)
    return ScanContext(
        scan_id=str(uuid.uuid4()),
        mode=ScanMode.STATIC,
        target=target,
        url=None,
        url_host=None,
        pinned_address=None,
        started_at=datetime.now(UTC),
        components=(),
        config=_config(config),
        authorization=Authorization(attested=True),
        work_dir=work,
    )


def _run(ctx: ScanContext, scanner: SemgrepScanner | None = None):
    return run_scan(
        ctx,
        (scanner or SemgrepScanner(),),
        dynamic=UnavailableDynamicRuntime(),
        store=None,
    )


def _install_fake(
    tmp_path: Path,
    *,
    help_text: str,
    stdout: bytes = b'{"results": []}\n',
    code: int = 0,
    version_code: int = 0,
) -> Path:
    folder = tmp_path / "fake-bin"
    folder.mkdir()
    script = folder / "semgrep"
    script.write_text(_SCRIPT, encoding="utf-8")
    script.chmod(0o755)
    (folder / "help.txt").write_text(help_text, encoding="utf-8")
    (folder / "stdout.bin").write_bytes(stdout)
    (folder / "code.txt").write_text(f"{code}\n", encoding="utf-8")
    (folder / "version_code.txt").write_text(f"{version_code}\n", encoding="utf-8")
    (folder / "version.txt").write_text("semgrep 1.2.3\n", encoding="utf-8")
    return script


def _use_fake(monkeypatch: pytest.MonkeyPatch, script: Path) -> None:
    monkeypatch.setattr(
        "sentinel.scanners.semgrep.shutil.which",
        lambda name: str(script) if name == "semgrep" else None,
    )


def _invocations(script: Path) -> list[dict[str, object]]:
    log = script.parent / "invocations.jsonl"
    if not log.is_file():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]


def _scan_rows(script: Path) -> list[dict[str, object]]:
    return [row for row in _invocations(script) if "--json" in row["argv"]]


def _result(
    *,
    check_id: str | None = "sentinel.fixture.marker",
    path: str = "app.py",
    line: int | None = 4,
    message: str = "marker reached",
    severity: str = "WARNING",
    metadata: dict[str, object] | None = None,
    lines: str = "def sentinel_fixture_marker():\n",
) -> dict[str, object]:
    extra: dict[str, object] = {
        "message": message,
        "lines": lines,
        "severity": severity,
        "metadata": {} if metadata is None else metadata,
    }
    body: dict[str, object] = {"path": path, "extra": extra}
    if check_id is not None:
        body["check_id"] = check_id
    if line is not None:
        body["start"] = {"line": line}
    return body


def _document(results: list[object]) -> bytes:
    return json.dumps({"results": results, "ignored": True}).encode()


def test_fixture_matches_the_marker_name() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    assert "sentinel_fixture_marker" in text
    assert "pattern: sentinel_fixture_marker" in text


def test_missing_binary_skips_without_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr("sentinel.scanners.semgrep.shutil.which", lambda _name: None)

    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("semgrep was launched")

    monkeypatch.setattr("sentinel.scanners.semgrep.subprocess.Popen", explode)
    report = _run(_context(tmp_path, config=config))
    assert report.findings == []
    assert report.scanners.executed == []
    assert [(item.reason, item.failed) for item in report.scanners.skipped] == [
        (NOT_FOUND_REASON, False)
    ]
    assert NOT_FOUND_REASON not in report.limitations


def test_missing_config_skips_even_when_binary_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sentinel.scanners.semgrep.shutil.which", lambda _name: "/usr/bin/semgrep")

    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("semgrep was launched")

    monkeypatch.setattr("sentinel.scanners.semgrep.subprocess.Popen", explode)
    report = _run(_context(tmp_path, config=None))
    assert report.scanners.executed == []
    assert [(item.reason, item.failed) for item in report.scanners.skipped] == [
        (NO_CONFIG_REASON, False)
    ]
    assert NO_CONFIG_REASON not in report.limitations
    assert SEMGREPIGNORE_REASON not in report.limitations


def test_other_probe_reasons_stay_out_of_limitations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr("sentinel.scanners.semgrep.shutil.which", lambda _name: None)
    report = _run(_context(tmp_path, config=config))
    assert report.scanners.skipped[0].reason == NOT_FOUND_REASON
    assert report.scanners.skipped[0].failed is False
    assert report.limitations == []


def test_version_check_failure_is_a_failed_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _install_fake(tmp_path, help_text=_HELP_READY, version_code=2)
    _use_fake(monkeypatch, script)
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    report = _run(_context(tmp_path, config=config))
    assert report.findings == []
    assert report.scanners.executed == []
    assert [(item.reason, item.failed) for item in report.scanners.skipped] == [
        (VERSION_FAILED_REASON, True)
    ]
    assert _scan_rows(script) == []
    assert VERSION_FAILED_REASON not in report.limitations


def test_probe_without_a_target_does_not_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sentinel.scanners.semgrep.shutil.which", lambda _name: "/usr/bin/semgrep")

    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("semgrep was launched")

    monkeypatch.setattr("sentinel.scanners.semgrep.subprocess.Popen", explode)
    ctx = _context(tmp_path, config=None)
    ctx = ScanContext(
        scan_id=ctx.scan_id,
        mode=ctx.mode,
        target=None,
        url=None,
        url_host=None,
        pinned_address=None,
        started_at=ctx.started_at,
        components=(),
        config=ctx.config,
        authorization=ctx.authorization,
        work_dir=ctx.work_dir,
    )
    probe = SemgrepScanner().probe(ctx)
    assert probe.available is False
    assert probe.failed is False
    assert probe.reason == NO_CONFIG_REASON


def test_semgrep_title_and_severity_from_dicts(tmp_path: Path) -> None:
    assert semgrep_title(_result()) == "sentinel.fixture.marker"
    long_link = "s" * 140
    titled = _result(metadata={"shortlink": f"  {long_link}  "})
    assert semgrep_title(titled) == "s" * 120
    blank = _result(metadata={"shortlink": "   "})
    assert semgrep_title(blank) == "sentinel.fixture.marker"
    root = tmp_path / "repo"
    root.mkdir()
    error = finding_from_semgrep(
        _result(severity="ERROR", metadata={"confidence": "HIGH"}),
        root=root,
        rule_pack=None,
    )[0]
    assert error is not None
    assert error.severity == Severity.HIGH
    assert error.confidence == Confidence.HIGH
    warning = finding_from_semgrep(_result(severity="WARNING"), root=root, rule_pack=None)[0]
    info = finding_from_semgrep(
        _result(severity="INFO", metadata={"confidence": "LOW"}),
        root=root,
        rule_pack=None,
    )[0]
    assert warning is not None and warning.severity == Severity.MEDIUM
    assert info is not None and info.severity == Severity.LOW
    assert info.confidence == Confidence.LOW
    unknown = finding_from_semgrep(_result(severity="NOISE"), root=root, rule_pack=None)[0]
    assert unknown is not None
    assert unknown.severity == Severity.MEDIUM
    assert unknown.confidence == Confidence.LOW
    assert "tool severity was unrecognized" in unknown.explanation
    plain = finding_from_semgrep(
        _result(check_id="python.security.example", metadata={"category": "security"}),
        root=root,
        rule_pack=None,
    )[0]
    docker = finding_from_semgrep(
        _result(
            check_id="python.dockerfile.security.example",
            metadata={"category": "security"},
        ),
        root=root,
        rule_pack=None,
    )[0]
    kube = finding_from_semgrep(
        _result(
            check_id="yaml.kubernetes.security.example",
            metadata={"category": "security"},
        ),
        root=root,
        rule_pack=None,
    )[0]
    assert plain is not None and plain.kind == FindingKind.POTENTIAL
    assert docker is not None and docker.kind == FindingKind.MISCONFIGURATION
    assert kube is not None and kube.kind == FindingKind.MISCONFIGURATION


def test_exit_1_json_maps_one_potential_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("def sentinel_fixture_marker():\n    return 1\n", encoding="utf-8")
    payload = _document([_result(path=str(root / "app.py"))])
    script = _install_fake(tmp_path, help_text=_HELP_READY, stdout=payload, code=1)
    _use_fake(monkeypatch, script)
    report = _run(_context(tmp_path, config=FIXTURE, target=root))
    assert len(report.findings) == 1
    item = report.findings[0]
    assert item.kind == FindingKind.POTENTIAL
    assert item.location.path == "app.py"
    assert item.location.line == 4
    assert item.title == "sentinel.fixture.marker"
    assert item.cve is None
    assert item.false_positive_notes == PATTERN_DISCLAIMER
    assert item.remediation.what_is_wrong == "marker reached"
    assert item.remediation.recommended_fix == "marker reached"
    assert item.remediation.why_dangerous == PATTERN_DISCLAIMER
    assert item.remediation.where == "app.py:4"
    assert item.remediation.secure_sketch is None
    assert "sentinel.fixture.marker is absent for app.py:4." in item.remediation.how_to_verify
    assert item.evidence.rule_pack_version is None
    assert item.scanner == "semgrep"
    assert item.scanner_version == __version__
    executed = report.scanners.executed
    assert len(executed) == 1
    assert executed[0].name == "semgrep"
    assert executed[0].status == "executed"
    assert executed[0].tool_version == "semgrep 1.2.3"
    argv = _scan_rows(script)[0]["argv"]
    assert isinstance(argv, list)
    assert argv[:6] == ["scan", "--metrics=off", "--quiet", "--json", "--config", str(FIXTURE)]
    assert "--error" not in argv
    assert "--strict" not in argv
    assert "auto" not in argv


def test_missing_check_id_is_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    payload = _document([_result(check_id=None), _result(check_id="kept.rule", message="kept")])
    script = _install_fake(tmp_path, help_text=_HELP_READY, stdout=payload, code=1)
    _use_fake(monkeypatch, script)
    report = _run(_context(tmp_path, config=FIXTURE, target=root))
    assert [item.evidence.rule_id for item in report.findings] == ["kept.rule"]
    assert report.limitations.count(MISSING_CHECK_REASON) == 1


def test_cwe_references_and_rule_pack_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    token = "a" * 32
    config = tmp_path / "pack.yml"
    config.write_text(f"# sentinel-rule-pack: {token}\nrules: []\n", encoding="utf-8")
    payload = _document(
        [
            _result(
                metadata={
                    "cwe": ["not-a-cwe", "CWE-79: xss"],
                    "references": [
                        "https://example.com/a",
                        "http://example.com/b",
                        "notaurl",
                        "ftp://example.com/c",
                    ],
                }
            )
        ]
    )
    script = _install_fake(tmp_path, help_text=_HELP_READY, stdout=payload, code=0)
    _use_fake(monkeypatch, script)
    report = _run(_context(tmp_path, config=config, target=root))
    assert len(report.findings) == 1
    item = report.findings[0]
    assert item.cwe == "CWE-79"
    assert item.cve is None
    assert item.references == ["https://example.com/a"]
    assert item.evidence.rule_pack_version == token
    assert report.scanners.executed[0].rule_pack_version == token
    wide = tmp_path / "wide.yml"
    wide.write_text(f"# sentinel-rule-pack: {'b' * 33}\nrules: []\n", encoding="utf-8")
    two = tmp_path / "two.yml"
    two.write_text("# sentinel-rule-pack: one two\nrules: []\n", encoding="utf-8")
    assert _rule_pack_token(wide) is None
    assert _rule_pack_token(two) is None


def test_https_references_fit_the_shipped_finding_model(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    finding, limitation = finding_from_semgrep(
        _result(metadata={"references": ["http://example.com/only", "https://example.com/ok"]}),
        root=root,
        rule_pack=None,
    )
    assert limitation is None
    assert finding is not None
    assert finding.references == ["https://example.com/ok"]


def test_empty_message_is_dropped_without_calling_fallback(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    finding, limitation = finding_from_semgrep(
        _result(message="   "),
        root=root,
        rule_pack=None,
    )
    assert finding is None
    assert limitation == EMPTY_REMEDIATION_REASON


def test_non_json_is_a_failed_skip_with_zero_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _install_fake(tmp_path, help_text=_HELP_READY, stdout=b"not-json", code=2)
    _use_fake(monkeypatch, script)
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    report = _run(_context(tmp_path, config=config))
    assert report.findings == []
    assert [(item.name, item.reason, item.failed) for item in report.scanners.skipped] == [
        ("semgrep", NON_JSON_REASON, True)
    ]
    assert GITIGNORE_LIMITATION not in report.limitations


def test_semgrepignore_skip_meets_the_engine_conditions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".semgrepignore").write_text("*\n", encoding="utf-8")
    (root / "app.py").write_text("def sentinel_fixture_marker():\n    return 1\n", encoding="utf-8")
    omitted = _document([_result(check_id="other.rule", message="omitted marker")])
    script = _install_fake(tmp_path, help_text=_HELP_NO_SEMGREPIGNORE, stdout=omitted, code=0)
    _use_fake(monkeypatch, script)
    report = _run(_context(tmp_path, config=FIXTURE, target=root))
    assert report.scanners.executed == []
    assert [(item.reason, item.failed) for item in report.scanners.skipped] == [
        (SEMGREPIGNORE_REASON, False)
    ]
    assert report.limitations.count(SEMGREPIGNORE_REASON) == 1
    assert GITIGNORE_LIMITATION not in report.limitations
    assert "sentinel_fixture_marker" not in report.model_dump_json()
    assert _scan_rows(script) == []
    linked = tmp_path / "linked"
    linked.mkdir()
    secret = linked / "secret.txt"
    secret.write_text(f"{_CANARY}\n", encoding="utf-8")
    (linked / ".semgrepignore").symlink_to(secret)
    (linked / "app.py").write_text("def sentinel_fixture_marker():\n    return 1\n", encoding="utf-8")
    again = _run(_context(tmp_path, config=FIXTURE, target=linked))
    assert again.scanners.executed == []
    assert again.scanners.skipped[0].reason == SEMGREPIGNORE_REASON
    assert again.scanners.skipped[0].failed is False
    assert _CANARY not in again.model_dump_json()


def test_semgrepignore_disable_flag_is_taken_from_help(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".semgrepignore").write_text("*\n", encoding="utf-8")
    (root / "app.py").write_text("def sentinel_fixture_marker():\n    return 1\n", encoding="utf-8")
    payload = _document([_result()])
    script = _install_fake(tmp_path, help_text=_HELP_READY, stdout=payload, code=1)
    _use_fake(monkeypatch, script)
    report = _run(_context(tmp_path, config=FIXTURE, target=root))
    assert [item.evidence.rule_id for item in report.findings] == ["sentinel.fixture.marker"]
    argv = _scan_rows(script)[0]["argv"]
    assert isinstance(argv, list)
    assert "--first-token" in argv
    assert "--second-token" not in argv
    assert "sentinel_fixture_marker" in report.findings[0].evidence.snippet


def test_gitignore_limitation_still_runs_semgrep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text("app.py\n", encoding="utf-8")
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    payload = _document([_result(message="still scanned")])
    script = _install_fake(tmp_path, help_text=_HELP_NO_GITIGNORE, stdout=payload, code=0)
    _use_fake(monkeypatch, script)
    report = _run(_context(tmp_path, config=FIXTURE, target=root))
    assert report.limitations.count(GITIGNORE_LIMITATION) == 1
    assert report.scanners.executed[0].status == "executed"
    assert report.findings[0].remediation.what_is_wrong == "still scanned"


def test_outside_symlink_without_nofollow_skips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path.parent / f"sentinel-outside-{uuid.uuid4().hex}"
    outside.write_text(f"{_CANARY}\n", encoding="utf-8")
    script = _install_fake(tmp_path, help_text=_HELP_NO_GITIGNORE, stdout=_document([_result()]))
    _use_fake(monkeypatch, script)
    try:
        (root / "linked").symlink_to(outside)
        report = _run(_context(tmp_path, config=FIXTURE, target=root))
    finally:
        outside.unlink(missing_ok=True)
    assert report.findings == []
    assert report.scanners.executed == []
    assert [(item.reason, item.failed) for item in report.scanners.skipped] == [
        (NOFOLLOW_REASON, False)
    ]
    assert _CANARY not in report.model_dump_json()
    assert NOFOLLOW_REASON not in report.limitations
    assert _scan_rows(script) == []


def test_nofollow_token_from_help_is_passed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path.parent / f"sentinel-outside-{uuid.uuid4().hex}"
    outside.write_text(f"{_CANARY}\n", encoding="utf-8")
    script = _install_fake(tmp_path, help_text=_HELP_NOFOLLOW, stdout=_document([]))
    _use_fake(monkeypatch, script)
    try:
        (root / "linked").symlink_to(outside)
        report = _run(_context(tmp_path, config=FIXTURE, target=root))
    finally:
        outside.unlink(missing_ok=True)
    assert report.scanners.executed[0].status == "executed"
    argv = _scan_rows(script)[0]["argv"]
    assert isinstance(argv, list)
    assert "--follow-token" in argv
    assert _CANARY not in report.model_dump_json()


def test_escaping_path_fails_the_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    payload = _document(
        [
            _result(check_id="kept.rule", path="app.py"),
            _result(check_id="escaped.rule", path="../../etc/passwd"),
        ]
    )
    script = _install_fake(tmp_path, help_text=_HELP_READY, stdout=payload, code=0)
    _use_fake(monkeypatch, script)
    report = _run(_context(tmp_path, config=FIXTURE, target=root))
    assert report.findings == []
    assert [(item.reason, item.failed) for item in report.scanners.skipped] == [
        (OUTSIDE_TARGET_REASON, True)
    ]
    assert "dropped 1 tool paths outside target" in report.limitations


def test_timeout_is_300_and_reraises_after_killpg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list[str], dict[str, object], int | None]] = []
    killed: list[tuple[int, int]] = []

    class _Process:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            self.argv = list(argv)
            self.kwargs = kwargs
            self.pid = 424242
            self.returncode = 0

        def communicate(self, timeout: int | None = None) -> tuple[bytes, bytes]:
            calls.append((self.argv, self.kwargs, timeout))
            if "--version" in self.argv:
                return b"semgrep 1.2.3\n", b""
            if "--help" in self.argv:
                return _HELP_READY.encode(), b""
            raise subprocess.TimeoutExpired(self.argv, timeout)

        def wait(self, timeout: int | None = None) -> int:
            del timeout
            self.returncode = -9
            return -9

        def kill(self) -> None:
            self.returncode = -9

    monkeypatch.setattr("sentinel.scanners.semgrep.subprocess.Popen", _Process)
    monkeypatch.setattr("sentinel.scanners.semgrep.shutil.which", lambda _name: "/usr/bin/semgrep")
    monkeypatch.setattr(
        "sentinel.scanners.semgrep.os.killpg",
        lambda pid, sig: killed.append((pid, sig)),
    )
    monkeypatch.setenv("SEMGREP_SENTINEL_SECRET", "should-not-leak")
    config = tmp_path / "rules.yml"
    config.write_text("rules: []\n", encoding="utf-8")
    scanner = SemgrepScanner()
    report = _run(_context(tmp_path, config=config), scanner)
    assert scanner.timeout_s == 300
    scan_calls = [item for item in calls if "--json" in item[0]]
    assert len(scan_calls) == 1
    argv, kwargs, timeout = scan_calls[0]
    assert timeout == 300
    assert kwargs["start_new_session"] is True
    assert kwargs["cwd"] == tmp_path / "work"
    env = kwargs["env"]
    assert isinstance(env, dict)
    assert env["HOME"] == str(tmp_path / "work")
    assert "SEMGREP_SENTINEL_SECRET" not in env
    assert "--error" not in argv
    assert "--strict" not in argv
    assert "auto" not in argv
    assert killed == [(424242, signal.SIGKILL)]
    assert report.findings == []
    assert report.scanners.skipped[0].reason == "timeout after 300s"
    assert report.scanners.skipped[0].failed is True
    assert "semgrep timed out after 300s" not in report.model_dump_json()


def test_tool_env_cwd_and_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    script = _install_fake(tmp_path, help_text=_HELP_READY, stdout=_document([_result()]), code=1)
    _use_fake(monkeypatch, script)
    monkeypatch.setenv("SEMGREP_SENTINEL_SECRET", "should-not-leak")
    monkeypatch.setenv("LANG", "C")
    report = _run(_context(tmp_path, config=FIXTURE, target=root))
    assert report.findings
    row = _scan_rows(script)[0]
    assert row["cwd"] == str(tmp_path / "work")
    env = row["env"]
    assert isinstance(env, dict)
    assert env["HOME"] == str(tmp_path / "work")
    assert env.get("LANG") == "C"
    assert "SEMGREP_SENTINEL_SECRET" not in env
    argv = row["argv"]
    assert isinstance(argv, list)
    assert "--metrics=off" in argv
    assert "--quiet" in argv
    assert "--json" in argv
    assert "--error" not in argv
    assert "--strict" not in argv
    assert "auto" not in argv
    assert argv[argv.index("--config") + 1] == str(FIXTURE)


def test_adapter_source_does_not_import_semgrep_or_docker() -> None:
    source = Path(__file__).resolve().parents[1] / "src" / "sentinel" / "scanners" / "semgrep.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    banned = {"docker", "semgrep", "socket"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in banned
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned
    text = source.read_text(encoding="utf-8")
    assert "shell=True" not in text
    assert "--config auto" not in text
    assert "semgrep timed out after 300s" not in text
