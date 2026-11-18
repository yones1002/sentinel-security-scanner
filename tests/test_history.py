"""SQLite history. No network, no Docker, and no real home-directory database."""

from __future__ import annotations

import ast
import json
import os
import sqlite3
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.config import (
    Authorization,
    ComponentOverride,
    DetectLimits,
    IgnoreRule,
    ScanConfig,
)
from sentinel.engine import BANDIT_DISABLED_REASON, run_scan
from sentinel.errors import ScanFailure, UsageError
from sentinel.history.store import (
    CURRENT_VERSION,
    REPORT_SCHEMA_VERSION,
    HistoryStore,
    default_history_path,
    open_history,
)
from sentinel.models import (
    ComponentKind,
    DynamicRequests,
    Evidence,
    ExecutedScanner,
    Finding,
    FindingKind,
    Framework,
    Location,
    Recommendation,
    ReportComponent,
    ScannerSection,
    ScanReport,
    Severity,
    SkippedScanner,
    Totals,
)
from sentinel.protocols import ScanContext, ScanMode
from sentinel.redact import redact_snippet
from sentinel.registry import builtin_scanners
from sentinel.sandbox.unavailable import UnavailableDynamicRuntime

runner = CliRunner()

_ROOT = Path(__file__).resolve().parents[1]
_STORE = _ROOT / "src" / "sentinel" / "history" / "store.py"
_FINGERPRINT_A = "ab" * 32
_FINGERPRINT_B = "cd" * 32
_CANARY = "canary-env-value-not-for-history"


def _config(**kwargs: object) -> ScanConfig:
    values: dict[str, object] = {
        "detect": DetectLimits(max_files=12, max_directories=7),
        "strict_tools": False,
        "fail_on": "high",
        "history": True,
        "semgrep_config": Path("/opt/sentinel/rules"),
        "component_overrides": (
            ComponentOverride(path="api", frameworks=(Framework.LARAVEL,), suppress=False),
        ),
        "ignores": (
            IgnoreRule(fingerprint=_FINGERPRINT_A, reason="password = hunter2"),
        ),
        "confirm_ambiguous_reads": False,
    }
    values.update(kwargs)
    return ScanConfig(**values)  # type: ignore[arg-type]


def _finding(
    *,
    fingerprint: str = _FINGERPRINT_A,
    severity: Severity = Severity.LOW,
    title: str = "A pattern matched",
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        fingerprint=fingerprint,
        title=title,
        severity=severity,
        confidence="high",
        kind=FindingKind.POTENTIAL,
        location=Location(path="api/main.go", line=4),
        explanation="The scanner reported this pattern.",
        evidence=Evidence(
            scanner="surface",
            scanner_version="0.0.1",
            summary="Pattern text without a secret.",
            rule_id="rule.one",
        ),
        remediation=Recommendation(
            what_is_wrong="A pattern matched in the tree.",
            why_dangerous="The match can still be a false positive.",
            where="api/main.go",
            recommended_fix="Review the match and remove it if it is real.",
            how_to_verify="Re-run the scan and confirm the rule is absent.",
        ),
        references=[],
        scanner="surface",
        scanner_version="0.0.1",
        false_positive_notes="A fixture match is still a match.",
        component_id=".",
    )


def _report(
    *findings: Finding,
    scan_id: str | None = None,
    skipped: list[SkippedScanner] | None = None,
    executed: list[ExecutedScanner] | None = None,
    strict_failure: bool = False,
    limitations: list[str] | None = None,
) -> ScanReport:
    now = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
    rows = list(findings)
    counts = {item.value: 0 for item in Severity}
    for finding in rows:
        counts[finding.severity.value] += 1
    return ScanReport(
        sentinel_version="0.0.1",
        scan_id=scan_id or str(uuid.uuid4()),
        target="/work/tree",
        url=None,
        mode="static",
        started_at=now,
        finished_at=now,
        duration_ms=15,
        components=[
            ReportComponent(
                component_id=".",
                languages=[],
                frameworks=[],
                evidence=["go.mod"],
                kind=ComponentKind.REPOSITORY,
            )
        ],
        scanners=ScannerSection(
            executed=executed
            if executed is not None
            else [
                ExecutedScanner(
                    name="surface",
                    version="0.0.1",
                    tool_version="surface-tool",
                    duration_ms=10,
                    status="executed",
                    finding_count=len(rows),
                )
            ],
            skipped=skipped
            if skipped is not None
            else [SkippedScanner(name="semgrep", reason="no local semgrep config", failed=False)],
        ),
        dynamic_requests=DynamicRequests(),
        totals=Totals(**counts),
        strict_failure=strict_failure,
        limitations=["detection note"] if limitations is None else limitations,
        findings=rows,
        comparison=None,
    )


def _open(tmp_path: Path) -> HistoryStore:
    return open_history(tmp_path / "sentinel" / "history.db")


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")]


def _version0(path: Path, report: ScanReport) -> None:
    path.parent.mkdir(parents=True, mode=0o700)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE schema_migrations (
              version INTEGER PRIMARY KEY,
              applied_at TEXT NOT NULL
            );
            CREATE TABLE scans (
              scan_id TEXT PRIMARY KEY,
              schema_version TEXT NOT NULL,
              target TEXT NOT NULL,
              mode TEXT NOT NULL,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              duration_ms INTEGER,
              sentinel_version TEXT NOT NULL,
              tool_versions_json TEXT NOT NULL,
              components_json TEXT NOT NULL,
              scanners_executed_json TEXT NOT NULL,
              scanners_skipped_json TEXT NOT NULL,
              limitations_json TEXT NOT NULL,
              config_json TEXT NOT NULL
            );
            CREATE TABLE findings (
              scan_id TEXT NOT NULL,
              fingerprint TEXT NOT NULL,
              severity TEXT NOT NULL,
              kind TEXT NOT NULL,
              finding_json TEXT NOT NULL,
              PRIMARY KEY (scan_id, fingerprint)
            );
            """
        )
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (0, ?)",
            ("2020-01-01T00:00:00+00:00",),
        )
        conn.execute(
            """
            INSERT INTO scans (
                scan_id, schema_version, target, mode, started_at, finished_at,
                duration_ms, sentinel_version, tool_versions_json, components_json,
                scanners_executed_json, scanners_skipped_json, limitations_json,
                config_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.scan_id,
                report.schema_version,
                report.target,
                report.mode,
                report.started_at.isoformat(),
                report.finished_at.isoformat(),
                report.duration_ms,
                report.sentinel_version,
                "[]",
                json.dumps([item.model_dump(mode="json") for item in report.components]),
                json.dumps(
                    [item.model_dump(mode="json") for item in report.scanners.executed]
                ),
                json.dumps([item.model_dump(mode="json") for item in report.scanners.skipped]),
                json.dumps(report.limitations),
                json.dumps({"strict_tools": False}),
            ),
        )
        for finding in report.findings:
            conn.execute(
                """
                INSERT INTO findings (
                    scan_id, fingerprint, severity, kind, finding_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    report.scan_id,
                    finding.fingerprint,
                    finding.severity.value,
                    finding.kind.value,
                    finding.model_dump_json(),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def test_store_module_does_not_import_the_engine() -> None:
    tree = ast.parse(_STORE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert "sentinel.engine" not in imported
    assert not (_ROOT / "src" / "sentinel" / "history" / "compare.py").exists()


def test_schema_version_1_has_the_documented_columns(tmp_path: Path) -> None:
    store = _open(tmp_path)
    conn = store.connect()
    try:
        assert _columns(conn, "schema_migrations") == ["version", "applied_at"]
        assert _columns(conn, "scans") == [
            "scan_id",
            "schema_version",
            "target",
            "mode",
            "started_at",
            "finished_at",
            "duration_ms",
            "sentinel_version",
            "tool_versions_json",
            "components_json",
            "scanners_executed_json",
            "scanners_skipped_json",
            "limitations_json",
            "config_json",
        ]
        assert _columns(conn, "findings") == [
            "scan_id",
            "fingerprint",
            "severity",
            "kind",
            "finding_json",
        ]
        indexes = {
            str(row[0])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
        assert "idx_findings_fingerprint" in indexes
        assert "idx_findings_scan_severity" in indexes
        finding_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'findings'"
        ).fetchone()
        assert finding_sql is not None
        assert "ON DELETE CASCADE" in str(finding_sql[0])
        versions = conn.execute("SELECT version FROM schema_migrations").fetchall()
        assert [row[0] for row in versions] == [CURRENT_VERSION]
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    finally:
        conn.close()
    raw = sqlite3.connect(store.path)
    try:
        assert raw.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    finally:
        raw.close()
    assert not store.path.with_name(store.path.name + "-wal").exists()


def test_permissions_are_0700_for_the_sentinel_directory_only(tmp_path: Path) -> None:
    parent = tmp_path / "data"
    parent.mkdir(mode=0o755)
    sentinel = parent / "sentinel"
    sentinel.mkdir(mode=0o755)
    previous = os.umask(0)
    try:
        store = open_history(sentinel / "history.db")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    os.chmod(store.path, 0o644)
    os.chmod(sentinel, 0o755)
    open_history(store.path)
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o700
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_default_path_uses_xdg_and_ignores_an_empty_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "xdg"
    home.mkdir(mode=0o755)
    monkeypatch.setenv("XDG_DATA_HOME", str(home))
    assert default_history_path() == home / "sentinel" / "history.db"
    store = open_history()
    assert store.path == home / "sentinel" / "history.db"
    assert stat.S_IMODE(home.stat().st_mode) == 0o755
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    monkeypatch.setenv("XDG_DATA_HOME", "  ")
    assert default_history_path() == Path.home() / ".local" / "share" / "sentinel" / "history.db"
    monkeypatch.delenv("XDG_DATA_HOME")
    assert default_history_path() == Path.home() / ".local" / "share" / "sentinel" / "history.db"


def test_two_scans_round_trip_and_revalidate_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SENTINEL_HISTORY_CANARY", _CANARY)
    monkeypatch.setenv("SENTINEL_ACCOUNT_A", "Bearer super-secret-token")
    store = _open(tmp_path)
    config = _config()
    first = _report(
        _finding(severity=Severity.HIGH, title="Higher"),
        _finding(fingerprint=_FINGERPRINT_B, title="Lower"),
    )
    second = _report(_finding(title="Other scan"))
    store.save(first, config)
    store.save(second, config)
    loaded = store.load(first.scan_id)
    assert loaded.scan_id == first.scan_id
    assert [item.title for item in loaded.findings] == ["Higher", "Lower"]
    assert all(isinstance(item, Finding) for item in loaded.findings)
    assert loaded.findings[0].fingerprint == _FINGERPRINT_A
    assert loaded.components == first.components
    assert loaded.limitations == ["detection note"]
    assert loaded.totals == first.totals
    assert loaded.url is None
    assert loaded.comparison is None
    assert loaded.dynamic_requests == DynamicRequests()
    assert loaded.started_at == first.started_at
    assert loaded.finished_at == first.finished_at
    assert loaded.schema_version == REPORT_SCHEMA_VERSION
    assert store.load(second.scan_id).findings[0].title == "Other scan"
    conn = store.connect()
    try:
        row = conn.execute(
            "SELECT schema_version, tool_versions_json, config_json FROM scans WHERE scan_id = ?",
            (first.scan_id,),
        ).fetchone()
        assert row is not None
        assert row["schema_version"] == "1.0"
        assert json.loads(row["tool_versions_json"]) == [
            {"name": "surface", "tool_version": "surface-tool"}
        ]
        stored = json.loads(row["config_json"])
        reason = stored["ignores"][0]["reason"]
        assert reason == redact_snippet("password = hunter2", limit=500)
        assert "hunter2" not in reason
        assert stored["semgrep_config"] == "/opt/sentinel/rules"
        assert stored["history"] is True
        assert stored["fail_on"] == "high"
        assert stored["detect"] == {"max_directories": 7, "max_files": 12}
        assert stored["component_overrides"] == [
            {"frameworks": ["laravel"], "path": "api", "suppress": False}
        ]
        assert "attested" not in stored
        assert "Authorization" not in row["config_json"]
        blob = store.path.read_bytes()
        assert _CANARY.encode() not in blob
        assert b"super-secret-token" not in blob
        assert b"hunter2" not in blob
    finally:
        conn.close()


def test_duplicate_scan_id_and_corrupt_finding_are_refused(tmp_path: Path) -> None:
    store = _open(tmp_path)
    report = _report(_finding())
    store.save(report, _config())
    with pytest.raises(ScanFailure, match="scan_id already stored"):
        store.save(report, _config())
    conn = sqlite3.connect(store.path)
    try:
        conn.execute(
            "UPDATE findings SET finding_json = ? WHERE scan_id = ?",
            ("{", report.scan_id),
        )
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(ScanFailure, match="stored finding failed validation"):
        store.load(report.scan_id)


def test_unknown_scan_id_is_a_usage_error_without_creating_a_file(tmp_path: Path) -> None:
    missing = tmp_path / "sentinel" / "history.db"
    store = open_history(missing, create=False)
    with pytest.raises(UsageError, match="unknown scan_id: missing"):
        store.load("missing")
    assert not missing.exists()
    assert not missing.parent.exists()
    created = _open(tmp_path)
    with pytest.raises(UsageError, match="unknown scan_id: absent"):
        created.load("absent")


def test_foreign_keys_cascade_on_the_store_connection(tmp_path: Path) -> None:
    store = _open(tmp_path)
    report = _report(_finding())
    store.save(report, _config())
    conn = store.connect()
    try:
        conn.execute("DELETE FROM scans WHERE scan_id = ?", (report.scan_id,))
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()
        assert count is not None
        assert count[0] == 0
    finally:
        conn.close()


def test_strict_failure_is_recomputed_from_stored_rows(tmp_path: Path) -> None:
    store = _open(tmp_path)
    bandit = _report(
        skipped=[SkippedScanner(name="bandit", reason=BANDIT_DISABLED_REASON, failed=False)],
        strict_failure=True,
    )
    store.save(bandit, _config(strict_tools=True))
    assert store.load(bandit.scan_id).strict_failure is False
    other = _report(
        scan_id=str(uuid.uuid4()),
        skipped=[SkippedScanner(name="semgrep", reason="binary missing", failed=False)],
        strict_failure=False,
    )
    store.save(other, _config(strict_tools=True))
    assert store.load(other.scan_id).strict_failure is True
    failed = _report(
        scan_id=str(uuid.uuid4()),
        executed=[
            ExecutedScanner(
                name="surface",
                version="0.0.1",
                duration_ms=1,
                status="failed",
                finding_count=0,
                reason="tool reported a path outside the target",
            )
        ],
        skipped=[SkippedScanner(name="bandit", reason=BANDIT_DISABLED_REASON, failed=False)],
        strict_failure=False,
    )
    store.save(failed, _config(strict_tools=True))
    assert store.load(failed.scan_id).strict_failure is True
    quiet = _report(scan_id=str(uuid.uuid4()), strict_failure=True)
    store.save(quiet, _config(strict_tools=False))
    assert store.load(quiet.scan_id).strict_failure is False


def test_newer_migration_is_refused_and_a_leftover_next_file_is_not_applied(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sentinel" / "history.db"
    path.parent.mkdir(mode=0o700)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (2, ?)",
            ("2026-01-01T00:00:00+00:00",),
        )
        conn.commit()
    finally:
        conn.close()
    original = path.read_bytes()
    mode = path.stat().st_mode
    leftover = path.with_name(path.name + ".next")
    leftover.write_bytes(b"do not apply this database")
    with pytest.raises(ScanFailure, match="migration version 2 is newer than this build"):
        open_history(path)
    assert path.read_bytes() == original
    assert path.stat().st_mode == mode
    assert not leftover.exists()


def test_version_0_migrates_by_copy_and_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "sentinel" / "history.db"
    report = _report(_finding(title="Kept from version 0"))
    _version0(path, report)
    replaced: list[tuple[str, str]] = []
    real_replace = os.replace

    def spy(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        replaced.append((os.fspath(src), os.fspath(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy)
    store = open_history(path)
    assert replaced
    assert replaced[-1][0].endswith("history.db.next")
    assert replaced[-1][1].endswith("history.db")
    assert not store.next_path.exists()
    loaded = store.load(report.scan_id)
    assert loaded.findings[0].title == "Kept from version 0"
    conn = store.connect()
    try:
        versions = [row[0] for row in conn.execute("SELECT version FROM schema_migrations")]
        assert versions == [1]
        assert _columns(conn, "findings")[-1] == "finding_json"
    finally:
        conn.close()


def test_failed_replace_keeps_the_original_and_the_next_open_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "sentinel" / "history.db"
    report = _report(_finding(title="Still on version 0"))
    _version0(path, report)
    original = path.read_bytes()

    def boom(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        del src, dst
        raise OSError("replace refused")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(ScanFailure, match="could not be replaced"):
        open_history(path)
    assert path.read_bytes() == original
    assert path.with_name(path.name + ".next").exists()
    monkeypatch.undo()
    path.with_name(path.name + ".next").write_bytes(b"garbage-next-file")
    store = open_history(path)
    assert not store.next_path.exists()
    assert store.load(report.scan_id).findings[0].title == "Still on version 0"
    conn = store.connect()
    try:
        assert [row[0] for row in conn.execute("SELECT version FROM schema_migrations")] == [1]
    finally:
        conn.close()


def test_a_leftover_next_file_on_a_current_database_is_deleted(tmp_path: Path) -> None:
    store = _open(tmp_path)
    report = _report(_finding(title="Original scan"))
    store.save(report, _config())
    store.next_path.write_bytes(b"not-the-database")
    reopened = open_history(store.path)
    assert not reopened.next_path.exists()
    assert reopened.load(report.scan_id).findings[0].title == "Original scan"


def test_run_scan_persists_before_it_returns(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "go.mod").write_text("module example.com/tree\n\ngo 1.22\n", encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()
    store = open_history(tmp_path / "sentinel" / "history.db")
    context = ScanContext(
        scan_id=str(uuid.uuid4()),
        mode=ScanMode.STATIC,
        target=target,
        url=None,
        url_host=None,
        pinned_address=None,
        started_at=datetime.now(UTC),
        components=(),
        config=_config(
            history=True,
            semgrep_config=None,
            component_overrides=(),
            ignores=(),
        ),
        authorization=Authorization(attested=False),
        work_dir=work,
    )
    report = run_scan(
        context,
        builtin_scanners(),
        dynamic=UnavailableDynamicRuntime(),
        store=store,
        extra_limitations=("config note",),
    )
    loaded = store.load(report.scan_id)
    assert loaded.scan_id == report.scan_id
    assert loaded.findings == report.findings
    assert loaded.limitations[-1] == "config note"
    assert loaded.strict_failure is report.strict_failure
    assert loaded.totals == report.totals


def test_cli_history_round_trip_and_refuses_compare_html_and_maintenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    monkeypatch.setenv("SENTINEL_HISTORY_CANARY", _CANARY)
    target = tmp_path / "tree"
    target.mkdir()
    (target / "wp-config.php").write_text("<?php\n", encoding="utf-8")
    (target / "sentinel.toml").write_text(
        'authorized = true\n\n[[components]]\npath = "."\nframeworks = ["laravel"]\n',
        encoding="utf-8",
    )
    scanned = runner.invoke(
        app,
        [
            "scan",
            "--history",
            "--format",
            "json",
            "--config",
            str(target / "sentinel.toml"),
            str(target),
        ],
    )
    assert scanned.exit_code == 0
    original = ScanReport.model_validate_json(scanned.stdout)
    scan_id = original.scan_id
    assert any(
        item.evidence.rule_id == "sentinel.surface.wp-config-in-tree" for item in original.findings
    )
    assert "in-repo sentinel.toml attempted to set authorized, components; ignored" in (
        original.limitations
    )
    assert _CANARY not in scanned.stdout
    db = (xdg / "sentinel" / "history.db").read_bytes()
    assert _CANARY.encode() not in db
    conn = sqlite3.connect(xdg / "sentinel" / "history.db")
    try:
        row = conn.execute("SELECT config_json FROM scans").fetchone()
    finally:
        conn.close()
    assert row is not None
    stored = json.loads(row[0])
    assert stored["history"] is True
    reported = runner.invoke(app, ["report", "--scan-id", scan_id, "--format", "json"])
    assert reported.exit_code == 0
    assert ScanReport.model_validate_json(reported.stdout) == original
    markdown = runner.invoke(app, ["report", "--scan-id", scan_id])
    assert markdown.exit_code == 0
    assert f"Scan: {scan_id}" in markdown.stdout
    output = tmp_path / "saved.md"
    written = runner.invoke(
        app,
        ["report", "--scan-id", scan_id, "--output", str(output)],
    )
    assert written.exit_code == 0
    assert written.stdout == ""
    assert scan_id in output.read_text(encoding="utf-8")
    compared = runner.invoke(app, ["report", "--scan-id", scan_id, "--compare", scan_id])
    assert compared.exit_code == 1
    assert "compare is not in this build (milestone 3)" in compared.stderr
    html = runner.invoke(app, ["report", "--scan-id", scan_id, "--format", "html"])
    assert html.exit_code == 1
    assert "html format is not in this build (milestone 3)" in html.stderr
    listed = runner.invoke(app, ["history", "list"])
    assert listed.exit_code == 1
    assert "history maintenance is not in this build (milestone 6)" in listed.stderr
    pruned = runner.invoke(app, ["history", "prune", "--older-than", "30"])
    assert pruned.exit_code == 1
    assert "history maintenance is not in this build (milestone 6)" in pruned.stderr


def test_history_off_does_not_create_a_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    target = tmp_path / "tree"
    target.mkdir()
    result = runner.invoke(app, ["scan", str(target)])
    assert result.exit_code == 0
    assert not xdg.exists()


def test_html_with_history_does_not_create_a_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    target = tmp_path / "tree"
    target.mkdir()
    result = runner.invoke(app, ["scan", "--history", "--format", "html", str(target)])
    assert result.exit_code == 1
    assert "html format is not in this build (milestone 3)" in result.stderr
    assert not xdg.exists()


def test_history_write_failure_exits_2_without_a_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    target = tmp_path / "tree"
    target.mkdir()

    def boom(self: HistoryStore, report: ScanReport, config: ScanConfig) -> None:
        del self, report, config
        raise ScanFailure("history database could not be written")

    monkeypatch.setattr(HistoryStore, "save", boom)
    failed = runner.invoke(app, ["scan", "--history", str(target)])
    assert failed.exit_code == 2
    assert failed.stdout == ""
    assert "history database could not be written" in failed.stderr


def test_a_newer_database_exits_2_before_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    target = tmp_path / "tree"
    target.mkdir()
    (target / "wp-config.php").write_text("<?php\n", encoding="utf-8")
    path = xdg / "sentinel" / "history.db"
    path.parent.mkdir(parents=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (2, ?)",
            ("2026-01-01T00:00:00+00:00",),
        )
        conn.commit()
    finally:
        conn.close()
    newer = runner.invoke(app, ["scan", "--history", str(target)])
    assert newer.exit_code == 2
    assert newer.stdout == ""
    assert "migration version 2 is newer than this build" in newer.stderr
    assert "wp-config" not in newer.stdout
