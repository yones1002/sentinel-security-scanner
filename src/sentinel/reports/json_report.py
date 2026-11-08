"""JSON rendering for one scan report.

The renderer serializes the model it is given. It does not scan, sort
findings, or inspect the process.
"""

from __future__ import annotations

from sentinel.models import Comparison, ScanReport


class JsonReportRenderer:
    """Deterministic JSON document for a ``ScanReport``."""

    format_id = "json"

    def render(self, report: ScanReport, compare: Comparison | None = None) -> str:
        document = _selected_report(report, compare)
        return document.model_dump_json(indent=2, by_alias=True) + "\n"


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
