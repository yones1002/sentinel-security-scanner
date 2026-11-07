"""JSON and Markdown report rendering. Renderers do not scan."""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.models import (
    ChangedFinding,
    Comparison,
    ComponentKind,
    CookieFlag,
    Evidence,
    ExecutedScanner,
    Finding,
    FindingKind,
    Framework,
    HttpEvidence,
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
from sentinel.reports.markdown_report import MarkdownReportRenderer

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


_PAYLOAD = "```<script>alert(1)</script> [click](https://evil.example)"
_BROKEN = _PAYLOAD + "\n## Pwned"
_INVISIBLE = "\u200b\u202e"


def _longest_run(value: str) -> int:
    longest = 0
    current = 0
    for char in value:
        if char == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _outside_code(markdown: str) -> str:
    normalized = markdown.replace("\r\n", "\n").replace("\r", "\n")
    normalized = normalized.replace("\u2028", "\n").replace("\u2029", "\n")
    outside: list[str] = []
    fence: str | None = None
    for line in normalized.split("\n"):
        if fence is None:
            if len(line) >= 3 and set(line) == {"`"}:
                fence = line
                continue
            outside.append(_strip_spans(line))
            continue
        if line == fence:
            fence = None
    return "\n".join(outside)


def _strip_spans(line: str) -> str:
    kept: list[str] = []
    index = 0
    while index < len(line):
        if line[index] != "`":
            kept.append(line[index])
            index += 1
            continue
        end = index
        while end < len(line) and line[end] == "`":
            end += 1
        run = line[index:end]
        cursor = end
        closed = False
        while cursor < len(line):
            if line[cursor] != "`":
                cursor += 1
                continue
            finish = cursor
            while finish < len(line) and line[finish] == "`":
                finish += 1
            if line[cursor:finish] == run:
                index = finish
                closed = True
                break
            cursor = finish
        if not closed:
            kept.append(run)
            index = end
    return "".join(kept)


def _fence_blocks(markdown: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    fence: str | None = None
    body: list[str] = []
    for line in markdown.split("\n"):
        if fence is None:
            if len(line) >= 3 and set(line) == {"`"}:
                fence = line
                body = []
            continue
        if line == fence:
            blocks.append((fence, "\n".join(body)))
            fence = None
            continue
        body.append(line)
    return blocks


def _poisoned_finding() -> Finding:
    snippet = "SNIP-" + ("`" * 5) + _BROKEN
    base = _finding()
    return base.model_copy(
        update={
            "title": _PAYLOAD + _INVISIBLE,
            "explanation": _BROKEN,
            "location": Location(path=_PAYLOAD, line=None, endpoint=_PAYLOAD),
            "false_positive_notes": _BROKEN,
            "evidence": base.evidence.model_copy(
                update={"summary": _PAYLOAD, "snippet": snippet}
            ),
            "remediation": Recommendation(
                what_is_wrong=_PAYLOAD,
                why_dangerous=_BROKEN,
                where=_PAYLOAD,
                recommended_fix=_PAYLOAD,
                secure_sketch=_BROKEN,
                sketch_language=_PAYLOAD,
                how_to_verify=_PAYLOAD,
            ),
        }
    )


def test_markdown_renderer_does_not_read_the_host() -> None:
    text = Path("src/sentinel/reports/markdown_report.py").read_text(encoding="utf-8")
    for banned in ("getcwd", "environ", "resolve(", "work_dir"):
        assert banned not in text


def test_markdown_scan_line_precedes_totals_and_keeps_rows() -> None:
    report = _report()
    rendered = MarkdownReportRenderer().render(report)
    assert rendered == MarkdownReportRenderer().render(report)
    scan_line = f"Scan: {report.scan_id}"
    assert scan_line in rendered.splitlines()
    assert rendered.index(scan_line) < rendered.index("## Totals")
    assert "no local semgrep config" in rendered
    assert "detection stopped: file cap 1 reached; results are incomplete" in rendered
    assert "Line: not recorded" in rendered
    findings = rendered.split("## Findings", 1)[1]
    assert "### Finding 1" in findings
    assert "/admin" not in findings
    assert "ambiguous" not in findings
    withheld = rendered.split("### Withheld", 1)[1].split("## Findings", 1)[0]
    assert "ambiguous" in withheld
    assert "/admin" in withheld
    assert "Withheld requests are not findings." in withheld


def test_markdown_uses_stored_totals_and_both_failed_rows() -> None:
    report = _report(
        totals={"high": 5},
        scanners=ScannerSection(
            executed=[
                ExecutedScanner(
                    name="surface",
                    version="0.0.1",
                    rule_pack_version="surface-1",
                    tool_version=None,
                    duration_ms=4,
                    status="failed",
                    finding_count=0,
                    reason="scanner surface failed: boom",
                )
            ],
            skipped=[
                SkippedScanner(
                    name="surface",
                    reason="scanner surface failed: boom",
                    failed=True,
                )
            ],
        ),
        limitations=[],
    )
    rendered = MarkdownReportRenderer().render(report)
    assert "| high | 5 |" in rendered
    assert "| total | 5 |" in rendered
    executed = rendered.split("## Executed scanners", 1)[1].split("## Skipped scanners", 1)[0]
    skipped = rendered.split("## Skipped scanners", 1)[1].split("## Limitations", 1)[0]
    assert "Status: `failed`" in executed
    assert "scanner surface failed: boom" in executed
    assert "scanner surface failed: boom" in skipped
    assert "Failed: true" in skipped
    limitations = rendered.split("## Limitations", 1)[1].split("## Dynamic requests", 1)[0]
    assert "None." in limitations
    assert "file cap" not in limitations
    numbered = report.model_copy(
        update={"findings": [_finding().model_copy(update={"location": Location(path="a", line=4)})]}
    )
    assert "Line: 4" in MarkdownReportRenderer().render(numbered)
    assert "## Comparison" not in rendered


def test_markdown_target_is_the_model_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_HOST_MARKER", HOST_MARKER)
    rendered = MarkdownReportRenderer().render(_report())
    absolute = MarkdownReportRenderer().render(_report(target=ABSOLUTE_TARGET))
    assert "scans/api" in rendered
    assert ABSOLUTE_TARGET in absolute
    for blob in (rendered, absolute):
        assert HOST_MARKER not in blob
        assert os.getcwd() not in blob
        assert WORK_MARKER not in blob


def test_markdown_compare_fills_without_changing_findings() -> None:
    report = _report()
    comparison = _comparison("00000000-0000-4000-8000-000000000099")
    plain = MarkdownReportRenderer().render(report)
    rendered = MarkdownReportRenderer().render(report, comparison)
    assert rendered.split("## Comparison", 1)[0].rstrip() == plain.rstrip()
    section = rendered.split("## Comparison", 1)[1]
    assert "00000000-0000-4000-8000-000000000099" in section
    assert "cd" * 32 in section
    stored = _report(comparison=comparison)
    assert "cd" * 32 in MarkdownReportRenderer().render(stored)
    other = _comparison("00000000-0000-4000-8000-000000000098", "ef" * 32)
    renderer = MarkdownReportRenderer()
    with pytest.raises(ValueError, match="comparison argument does not match report.comparison"):
        renderer.render(stored, other)
    with pytest.raises(TypeError, match="report must be a ScanReport"):
        renderer.render(object(), None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="compare must be a Comparison or None"):
        renderer.render(stored, object())  # type: ignore[arg-type]


def test_markdown_keeps_untrusted_text_inside_code() -> None:
    finding = _poisoned_finding()
    changed = ChangedFinding(
        fingerprint="ab" * 32,
        baseline_severity=Severity.LOW,
        severity=Severity.HIGH,
        baseline_kind=FindingKind.POTENTIAL,
        kind=FindingKind.MISCONFIGURATION,
    )
    comparison = _comparison("00000000-0000-4000-8000-000000000099")
    comparison = comparison.model_copy(
        update={"changed": [changed], "resolved_findings": [finding]}
    )
    report = _report(
        findings=[finding],
        limitations=[_BROKEN],
        scanners=ScannerSection(
            executed=[
                ExecutedScanner(
                    name="surface",
                    version="0.0.1",
                    rule_pack_version="surface-1",
                    tool_version=None,
                    duration_ms=4,
                    status="executed",
                    finding_count=1,
                    reason=_BROKEN,
                )
            ],
            skipped=[SkippedScanner(name="semgrep", reason=_BROKEN, failed=False)],
        ),
        dynamic_requests={
            "sent": [{"method": "GET", "path": _BROKEN}],
            "withheld": [{"class": "ambiguous", "method": "GET", "path": _PAYLOAD}],
        },
        comparison=comparison,
    )
    request = HttpEvidence(
        method="GET",
        url_path="/health",
        status_code=204,
        selected_headers={"content-type": "text/plain"},
        cookies=[CookieFlag(name=_PAYLOAD, secure=True, http_only=True, samesite="Lax")],
    )
    with_request = finding.model_copy(
        update={"evidence": finding.evidence.model_copy(update={"request": request})}
    )
    report = report.model_copy(update={"findings": [with_request]})
    rendered = MarkdownReportRenderer().render(report)
    for needle in (
        "<script>alert(1)</script>",
        "[click](https://evil.example)",
        "## Pwned",
        "```",
        _INVISIBLE,
    ):
        assert needle in rendered
    assert "&lt;" not in rendered
    outside = _outside_code(rendered)
    assert "## Pwned" not in outside
    assert "<script" not in outside
    assert "](https://evil.example)" not in outside
    assert not any(line.startswith("## Pwned") for line in outside.splitlines())
    snippet = with_request.evidence.snippet
    assert snippet is not None
    matches = [block for block in _fence_blocks(rendered) if block[1] == snippet]
    assert matches
    for fence, _body in matches:
        assert len(fence) > _longest_run(snippet)
        assert all(line != fence for line in snippet.split("\n"))
    assert "text/plain" in rendered
    assert "/health" in rendered
