"""Markdown rendering for one scan report.

Model text is copied into a span or a fence. The fence is longer than any
backtick run in that text, so the text cannot close it or become a heading.
"""

from __future__ import annotations

from sentinel.models import Comparison, Finding, HttpEvidence, ScanReport

_LINE_BREAKS = ("\n", "\r", "\u2028", "\u2029")


class MarkdownReportRenderer:
    """Deterministic Markdown document for a ``ScanReport``."""

    format_id = "markdown"

    def render(self, report: ScanReport, compare: Comparison | None = None) -> str:
        document = _selected_report(report, compare)
        return _document(document)


def _selected_report(report: ScanReport, compare: Comparison | None) -> ScanReport:
    if not isinstance(report, ScanReport):
        raise TypeError("report must be a ScanReport")
    if compare is None:
        return report
    if not isinstance(compare, Comparison):
        raise TypeError("compare must be a Comparison or None")
    if report.comparison is None:
        return report.model_copy(update={"comparison": compare})
    if report.comparison != compare:
        raise ValueError("comparison argument does not match report.comparison")
    return report


def literal(value: str, *, block: bool = False) -> str:
    """Show one model string without letting it change the document structure."""
    longest = _longest_backtick_run(value)
    broken = block or any(mark in value for mark in _LINE_BREAKS)
    if broken:
        fence = "`" * max(3, longest + 1)
        return f"{fence}\n{value}\n{fence}"
    ticks = "`" * (longest + 1)
    body = f" {value} " if value.startswith("`") or value.endswith("`") else value
    return f"{ticks}{body}{ticks}"


def _longest_backtick_run(value: str) -> int:
    longest = 0
    current = 0
    for char in value:
        if char == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _document(report: ScanReport) -> str:
    lines = [
        "# Sentinel scan",
        "",
        f"Scan: {report.scan_id}",
        "",
        *_summary(report),
        "",
        *_totals(report),
        "",
        *_components(report),
        "",
        *_executed(report),
        "",
        *_skipped(report),
        "",
        *_limitations(report),
        "",
        *_requests(report),
        "",
        *_findings(report),
    ]
    if report.comparison is not None:
        lines.extend(["", *_comparison(report.comparison)])
    return "\n".join(lines) + "\n"


def _field(label: str, value: str | None) -> str:
    if value is None:
        return f"{label}: None."
    rendered = literal(value)
    if "\n" in rendered:
        return f"{label}:\n{rendered}"
    return f"{label}: {rendered}"


def _flag(label: str, value: bool) -> str:
    return f"{label}: {'true' if value else 'false'}"


def _numbered(label: str, value: int | None) -> str:
    if value is None:
        return f"{label}: not recorded"
    return f"{label}: {value}"


def _summary(report: ScanReport) -> list[str]:
    return [
        "## Summary",
        "",
        _field("Target", report.target),
        _field("URL", report.url),
        _field("Mode", report.mode),
        _field("Started", report.started_at.isoformat()),
        _field("Finished", report.finished_at.isoformat()),
        f"Duration: {report.duration_ms} ms",
        _flag("Strict failure", report.strict_failure),
        _field("Schema", report.schema_version),
        _field("Sentinel", report.sentinel_version),
        _field("Fingerprint version", report.fingerprint_version),
    ]


def _totals(report: ScanReport) -> list[str]:
    totals = report.totals
    rows = (
        ("critical", totals.critical),
        ("high", totals.high),
        ("medium", totals.medium),
        ("low", totals.low),
        ("informational", totals.informational),
    )
    stored = sum(count for _, count in rows)
    lines = [
        "## Totals",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    lines.extend(f"| {name} | {count} |" for name, count in rows)
    lines.append(f"| total | {stored} |")
    return lines


def _components(report: ScanReport) -> list[str]:
    lines = ["## Components", ""]
    if not report.components:
        lines.append("None.")
        return lines
    for index, component in enumerate(report.components, start=1):
        lines.extend(
            [
                f"### Component {index}",
                "",
                _field("Component id", component.component_id),
                _field("Kind", component.kind.value),
            ]
        )
        lines.extend(_items("Languages", [item.value for item in component.languages]))
        lines.extend(_items("Frameworks", [item.value for item in component.frameworks]))
        lines.extend(_items("Evidence", list(component.evidence)))
        lines.append("")
    return lines


def _executed(report: ScanReport) -> list[str]:
    lines = ["## Executed scanners", ""]
    executed = report.scanners.executed
    if not executed:
        lines.append("None.")
        return lines
    for index, item in enumerate(executed, start=1):
        lines.extend(
            [
                f"### Executed {index}",
                "",
                _field("Name", item.name),
                _field("Version", item.version),
                _field("Rule pack", item.rule_pack_version),
                _field("Tool version", item.tool_version),
                f"Duration: {item.duration_ms} ms",
                _field("Status", item.status),
                f"Finding count: {item.finding_count}",
                _field("Reason", item.reason),
                "",
            ]
        )
    return lines


def _skipped(report: ScanReport) -> list[str]:
    lines = ["## Skipped scanners", ""]
    skipped = report.scanners.skipped
    if not skipped:
        lines.append("None.")
        return lines
    for index, item in enumerate(skipped, start=1):
        lines.extend(
            [
                f"### Skipped {index}",
                "",
                _field("Name", item.name),
                _field("Reason", item.reason),
                _flag("Failed", item.failed),
                "",
            ]
        )
    return lines


def _limitations(report: ScanReport) -> list[str]:
    lines = ["## Limitations", ""]
    if not report.limitations:
        lines.append("None.")
        return lines
    for item in report.limitations:
        rendered = literal(item)
        lines.append(rendered if "\n" in rendered else f"- {rendered}")
    return lines


def _requests(report: ScanReport) -> list[str]:
    dynamic = report.dynamic_requests
    lines = [
        "## Dynamic requests",
        "",
        "### Sent",
        "",
    ]
    if not dynamic.sent:
        lines.append("None.")
    for item in dynamic.sent:
        lines.extend([_field("Method", item.method), _field("Path", item.path), ""])
    lines.extend(["### Withheld", "", "Withheld requests are not findings.", ""])
    if not dynamic.withheld:
        lines.append("None.")
    for item in dynamic.withheld:
        lines.extend(
            [
                _field("Class", item.request_class),
                _field("Method", item.method),
                _field("Path", item.path),
                "",
            ]
        )
    return lines


def _findings(report: ScanReport) -> list[str]:
    lines = ["## Findings", ""]
    if not report.findings:
        lines.append("None.")
        return lines
    for index, finding in enumerate(report.findings, start=1):
        lines.extend(_finding(finding, f"### Finding {index}"))
    return lines


def _comparison(comparison: Comparison) -> list[str]:
    lines = [
        "## Comparison",
        "",
        _field("Baseline", comparison.baseline_scan_id),
        "",
    ]
    lines.extend(_items("New", list(comparison.new)))
    lines.extend(_items("Resolved", list(comparison.resolved)))
    lines.extend(_items("Persisting", list(comparison.persisting)))
    lines.append("Changed:")
    if not comparison.changed:
        lines.append("None.")
    for item in comparison.changed:
        parts = (
            literal(item.fingerprint),
            literal(item.baseline_severity.value),
            literal(item.severity.value),
            literal(item.baseline_kind.value),
            literal(item.kind.value),
        )
        lines.append("- " + " ".join(parts))
    lines.extend(["", "Resolved findings:", ""])
    if not comparison.resolved_findings:
        lines.append("None.")
    for index, finding in enumerate(comparison.resolved_findings, start=1):
        lines.extend(_finding(finding, f"### Resolved finding {index}"))
    return lines


def _finding(finding: Finding, heading: str) -> list[str]:
    location = finding.location
    evidence = finding.evidence
    remediation = finding.remediation
    lines = [
        heading,
        "",
        _field("Title", finding.title),
        _field("Severity", finding.severity.value),
        _field("Confidence", finding.confidence.value),
        _field("Kind", finding.kind.value),
        _field("Id", finding.id),
        _field("Fingerprint", finding.fingerprint),
        _field("Component id", finding.component_id),
        _field("CWE", finding.cwe),
        _field("CVE", finding.cve),
        _field("Path", location.path),
        _numbered("Line", location.line),
        _numbered("End line", location.end_line),
        _field("Endpoint", location.endpoint),
        _field("Explanation", finding.explanation),
        _field("Evidence scanner", evidence.scanner),
        _field("Evidence version", evidence.scanner_version),
        _field("Rule pack", evidence.rule_pack_version),
        _field("Rule id", evidence.rule_id),
        _field("Summary", evidence.summary),
    ]
    if evidence.snippet is None:
        lines.append("Snippet: None.")
    else:
        lines.extend(["Snippet:", literal(evidence.snippet, block=True)])
    if evidence.request is None:
        lines.append("Request: None.")
    else:
        lines.extend(_http(evidence.request))
    lines.extend(
        [
            _field("What is wrong", remediation.what_is_wrong),
            _field("Why dangerous", remediation.why_dangerous),
            _field("Where", remediation.where),
            _field("Recommended fix", remediation.recommended_fix),
            _field("Secure sketch", remediation.secure_sketch),
            _field("Sketch language", remediation.sketch_language),
            _field("How to verify", remediation.how_to_verify),
        ]
    )
    lines.extend(_items("References", list(finding.references)))
    lines.extend(
        [
            _field("Scanner", finding.scanner),
            _field("Scanner version", finding.scanner_version),
            _field("Fingerprint version", finding.fingerprint_version),
            _field("False positive notes", finding.false_positive_notes),
            "",
        ]
    )
    return lines


def _http(request: HttpEvidence) -> list[str]:
    lines = [
        _field("Request method", request.method),
        _field("Request path", request.url_path),
        f"Status: {request.status_code}",
        _flag("Body stored", request.body_stored),
        _field("Body sha256", request.body_sha256),
    ]
    if request.body_length is None:
        lines.append("Body length: None.")
    else:
        lines.append(f"Body length: {request.body_length}")
    if not request.selected_headers:
        lines.append("Headers: None.")
    else:
        lines.append("Headers:")
        for name, value in request.selected_headers.items():
            lines.append(_field("Header", name))
            lines.append(_field("Header value", value))
    if not request.cookies:
        lines.append("Cookies: None.")
        return lines
    lines.append("Cookies:")
    for cookie in request.cookies:
        lines.extend(
            [
                _field("Cookie", cookie.name),
                _flag("Secure", cookie.secure),
                _flag("Http only", cookie.http_only),
                _field("SameSite", cookie.samesite),
            ]
        )
    return lines


def _items(label: str, values: list[str]) -> list[str]:
    lines = [f"{label}:"]
    if not values:
        lines.append("None.")
        return lines
    for value in values:
        rendered = literal(value)
        lines.append(rendered if "\n" in rendered else f"- {rendered}")
    return lines
