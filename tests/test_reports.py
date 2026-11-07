"""JSON and Markdown report rendering. Renderers do not scan."""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.models import (
    Comparison,
    ComponentKind,
    Evidence,
    ExecutedScanner,
    Finding,
    FindingKind,
    Framework,
    Language,
    Location,
    Recommendation,
    ReportComponent,
    ScannerSection,
    ScanReport,
    Severity,
    SkippedScanner,
)
from sentinel.reports.json_report import JsonReportRenderer

HOST_MARKER = "HOST-MARKER-SHOULD-NOT-APPEAR"
ABSOLUTE_TARGET = "/var/sentinel-target/app"
WORK_MARKER = "/var/sentinel-work"


def _recommendation() -> Recommendation:
    return Recommendation(
        what_is_wrong="A dotenv file is inside the scanned tree.",
        why_dangerous="These files often hold credentials.",
        where="apps/api/.env",
        recommended_fix="Keep real environment files out of the tree.",
        how_to_verify="Re-run the scan and confirm the rule is absent.",
    )


def _finding() -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        fingerprint="ab" * 32,
        title="Environment file is present in the tree",
        severity=Severity.HIGH,
        confidence="high",
        kind=FindingKind.MISCONFIGURATION,
        location=Location(path="apps/api/.env"),
        explanation="A file named .env was found. Contents were not read.",
        evidence=Evidence(
            scanner="surface",
            scanner_version="0.0.1",
            rule_pack_version="surface-1",
            summary="Filename matched the .env rule.",
            rule_id="sentinel.surface.env-file",
        ),
        remediation=_recommendation(),
        references=["https://owasp.org/www-project-secrets-management/"],
        scanner="surface",
        scanner_version="0.0.1",
        false_positive_notes="A fixture file is still a match.",
        component_id="apps/api",
    )


def _report(**overrides: object) -> ScanReport:
    now = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
    payload: dict[str, object] = {
        "sentinel_version": "0.0.1",
        "scan_id": "00000000-0000-4000-8000-000000000001",
        "target": "scans/api",
        "mode": "static",
        "started_at": now,
        "finished_at": now,
        "duration_ms": 5,
        "components": [
            ReportComponent(
                component_id="apps/api",
                languages=[Language.PHP],
                frameworks=[Framework.LARAVEL],
                evidence=["apps/api/artisan"],
                kind=ComponentKind.APPLICATION,
            )
        ],
        "scanners": ScannerSection(
            executed=[
                ExecutedScanner(
                    name="surface",
                    version="0.0.1",
                    rule_pack_version="surface-1",
                    tool_version=None,
                    duration_ms=4,
                    status="executed",
                    finding_count=1,
                )
            ],
            skipped=[SkippedScanner(name="semgrep", reason="no local semgrep config", failed=False)],
        ),
        "dynamic_requests": {
            "sent": [{"method": "GET", "path": "/health"}],
            "withheld": [{"class": "ambiguous", "method": "GET", "path": "/admin"}],
        },
        "totals": {"high": 1},
        "limitations": ["detection stopped: file cap 1 reached; results are incomplete"],
        "findings": [_finding()],
    }
    payload.update(overrides)
    return ScanReport.model_validate(payload)


def _comparison(scan_id: str, fingerprint: str = "cd" * 32) -> Comparison:
    return Comparison(
        baseline_scan_id=scan_id,
        new=[fingerprint],
        resolved=[],
        persisting=[],
        changed=[],
        resolved_findings=[],
    )


def test_json_renderer_does_not_read_the_host() -> None:
    text = Path("src/sentinel/reports/json_report.py").read_text(encoding="utf-8")
    for banned in ("getcwd", "environ", "resolve(", "work_dir"):
        assert banned not in text


def test_json_round_trip_keeps_the_report_document() -> None:
    report = _report()
    rendered = JsonReportRenderer().render(report)
    assert rendered.endswith("\n")
    assert JsonReportRenderer().render(report) == rendered
    parsed = json.loads(rendered)
    assert list(parsed) == list(ScanReport.model_fields)
    assert parsed["dynamic_requests"]["withheld"][0]["class"] == "ambiguous"
    assert "request_class" not in parsed["dynamic_requests"]["withheld"][0]
    assert ScanReport.model_validate_json(rendered) == report


def test_json_target_is_the_model_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_HOST_MARKER", HOST_MARKER)
    rendered = JsonReportRenderer().render(_report())
    absolute = JsonReportRenderer().render(_report(target=ABSOLUTE_TARGET))
    assert json.loads(rendered)["target"] == "scans/api"
    assert json.loads(absolute)["target"] == ABSOLUTE_TARGET
    for blob in (rendered, absolute):
        assert HOST_MARKER not in blob
        assert os.getcwd() not in blob
        assert WORK_MARKER not in blob


def test_json_compare_fills_a_missing_comparison_without_computing_it() -> None:
    report = _report()
    comparison = _comparison("00000000-0000-4000-8000-000000000099")
    rendered = JsonReportRenderer().render(report, comparison)
    parsed = json.loads(rendered)
    assert parsed["comparison"]["baseline_scan_id"] == comparison.baseline_scan_id
    assert parsed["comparison"]["new"] == ["cd" * 32]
    assert parsed["findings"] == json.loads(JsonReportRenderer().render(report))["findings"]


def test_json_compare_must_match_the_report() -> None:
    stored = _comparison("00000000-0000-4000-8000-000000000099")
    other = _comparison("00000000-0000-4000-8000-000000000098", "ef" * 32)
    report = _report(comparison=stored)
    renderer = JsonReportRenderer()
    assert json.loads(renderer.render(report, stored))["comparison"]["new"] == ["cd" * 32]
    with pytest.raises(ValueError, match="comparison argument does not match report.comparison"):
        renderer.render(report, other)
    with pytest.raises(TypeError, match="report must be a ScanReport"):
        renderer.render(object(), None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="compare must be a Comparison or None"):
        renderer.render(report, object())  # type: ignore[arg-type]
