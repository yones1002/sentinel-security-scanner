"""Fingerprint v1 tests. The canonical string is not stored."""

from __future__ import annotations

import hashlib
import uuid

import pytest

from sentinel.fingerprint import (
    canonical_fingerprint_input,
    fingerprint,
    fingerprint_versions_differ,
    line_bucket,
    normalize_endpoint,
    normalize_path,
)
from sentinel.models import Evidence, Finding, FindingKind, Location, Recommendation, Severity

SURFACE_CANONICAL = "v1|surface|sentinel.surface.env-file|apps/api|.env|0|"


def _finding(
    *,
    scanner: str = "surface",
    rule_id: str = "sentinel.surface.env-file",
    component_id: str = "apps/api",
    path: str | None = "apps/api/.env",
    line: int | None = None,
    endpoint: str | None = None,
    snippet: str | None = None,
    title: str = "Environment file is present in the tree",
) -> Finding:
    version = "0.0.1"
    return Finding(
        id=str(uuid.uuid4()),
        fingerprint="cd" * 32,
        title=title,
        severity=Severity.HIGH,
        confidence="high",
        kind=FindingKind.MISCONFIGURATION,
        location=Location(path=path, line=line, endpoint=endpoint),
        explanation="A file named .env was found. Contents were not read.",
        evidence=Evidence(
            scanner=scanner,
            scanner_version=version,
            summary="Filename matched the .env rule.",
            snippet=snippet,
            rule_id=rule_id,
        ),
        remediation=Recommendation(
            what_is_wrong="A dotenv file is inside the scanned tree.",
            why_dangerous="These files often hold credentials.",
            where=path or "endpoint",
            recommended_fix="Keep real environment files out of the tree.",
            how_to_verify="Re-run the scan and confirm the rule is absent.",
        ),
        references=[],
        scanner=scanner,
        scanner_version=version,
        false_positive_notes="A fixture file is still a match.",
        component_id=component_id,
    )


def test_line_buckets_and_endpoint_normalization() -> None:
    assert line_bucket(None) == ""
    assert line_bucket(1) == "0"
    assert line_bucket(10) == "0"
    assert line_bucket(11) == "1"
    with pytest.raises(ValueError, match="line < 1"):
        line_bucket(0)
    assert normalize_endpoint(None) == ""
    assert normalize_endpoint("GET /health?x=1") == "GET /health"
    assert normalize_endpoint("get /health") == "GET /health"


def test_windows_path_matches_the_posix_digest() -> None:
    worked = _finding(path=".env", line=1)
    posix = _finding(path="apps/api/.env", line=1)
    windows = _finding(path=r"apps\api\.env", line=1)
    assert normalize_path(r"apps\api\.env") == "apps/api/.env"
    assert canonical_fingerprint_input(worked) == SURFACE_CANONICAL
    assert fingerprint(worked) == hashlib.sha256(SURFACE_CANONICAL.encode("utf-8")).hexdigest()
    assert len(fingerprint(worked)) == 64
    assert fingerprint(posix) == fingerprint(windows)
    assert fingerprint(posix) != fingerprint(worked)


def test_identity_fields_change_the_digest_and_display_fields_do_not() -> None:
    base = _finding(line=10)
    assert fingerprint(base) == fingerprint(_finding(line=1, title="other title", snippet="token"))
    assert fingerprint(base) != fingerprint(_finding(line=11))
    assert fingerprint(base) != fingerprint(_finding(line=10, scanner="semgrep"))
    assert fingerprint(base) != fingerprint(_finding(line=10, component_id="apps/web"))
    without_endpoint = _finding()
    with_endpoint = _finding(endpoint="GET /health?x=1")
    assert fingerprint(without_endpoint) != fingerprint(with_endpoint)
    again = _finding()
    again_id = _finding()
    assert again.id != again_id.id
    assert fingerprint(again) == fingerprint(again_id)


def test_absolute_path_and_parent_segment_are_not_hashed() -> None:
    with pytest.raises(ValueError, match="unassigned path dropped"):
        fingerprint(_finding(path="/etc/passwd"))
    with pytest.raises(ValueError, match="unassigned path dropped"):
        fingerprint(_finding(path="apps/../../.ssh/id_rsa"))
    with pytest.raises(ValueError, match="line < 1"):
        fingerprint(_finding(line=0))


def test_cross_version_compare_sentence() -> None:
    assert (
        fingerprint_versions_differ("v1", "v2")
        == "fingerprint versions differ: v1 vs v2"
    )
