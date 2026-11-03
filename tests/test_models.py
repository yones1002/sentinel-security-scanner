"""Schema tests for the PR 2 finding model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.errors import AuthorizationError, ExitCode, ScanFailure, ScannerError, UsageError
from sentinel.models import (
    HEADER_ALLOWLIST,
    Component,
    ComponentKind,
    Evidence,
    Finding,
    FindingKind,
    Framework,
    Language,
    Location,
    Recommendation,
    ScanReport,
    Severity,
    WithheldRequest,
)

DIGEST = "ab" * 32


def recommendation() -> Recommendation:
    return Recommendation(
        what_is_wrong="A dotenv file is inside the scanned tree.",
        why_dangerous="These files often hold credentials.",
        where="apps/api/.env",
        recommended_fix="Keep real environment files out of the tree.",
        how_to_verify="Re-run the scan and confirm the rule is absent.",
    )


def finding(**overrides: object) -> Finding:
    payload: dict[str, object] = {
        "id": str(uuid.uuid4()),
        "fingerprint": DIGEST,
        "title": "Environment file is present in the tree",
        "severity": Severity.HIGH,
        "confidence": "high",
        "kind": FindingKind.MISCONFIGURATION,
        "location": Location(path="apps/api/.env"),
        "explanation": "A file named .env was found. Contents were not read.",
        "evidence": Evidence(
            scanner="surface",
            scanner_version="0.0.1",
            rule_pack_version="surface-1",
            summary="Filename matched the .env rule.",
            rule_id="sentinel.surface.env-file",
        ),
        "remediation": recommendation(),
        "references": ["https://owasp.org/www-project-secrets-management/"],
        "scanner": "surface",
        "scanner_version": "0.0.1",
        "false_positive_notes": "A fixture file is still a match.",
        "component_id": "apps/api",
    }
    payload.update(overrides)
    return Finding.model_validate(payload)


def test_header_allowlist_matches_the_passive_contract() -> None:
    assert HEADER_ALLOWLIST == {
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "content-type",
        "server",
        "access-control-allow-origin",
        "access-control-allow-credentials",
    }


def test_finding_rejects_unknown_fields_and_blank_evidence() -> None:
    with pytest.raises(ValidationError):
        finding(unexpected=True)
    with pytest.raises(ValidationError):
        finding(
            evidence=Evidence(
                scanner="surface",
                scanner_version="0.0.1",
                summary="",
                rule_id="sentinel.surface.env-file",
            )
        )


def test_evidence_identity_must_match_the_finding() -> None:
    with pytest.raises(ValidationError, match="evidence.scanner"):
        finding(
            evidence=Evidence(
                scanner="semgrep",
                scanner_version="0.0.1",
                summary="A pattern matched.",
                rule_id="rule.one",
            )
        )


def test_fingerprint_version_and_cve_contract() -> None:
    created = finding()
    assert created.fingerprint_version == "v1"
    assert created.cve is None
    copied = finding(cve="GHSA-0000-0000-0000")
    assert copied.cve == "GHSA-0000-0000-0000"
    with pytest.raises(ValidationError):
        finding(fingerprint_version="v2")
    with pytest.raises(ValidationError):
        finding(cwe="not-a-cwe")


def test_snippet_references_and_headers_are_bounded() -> None:
    with pytest.raises(ValidationError):
        finding(
            evidence=Evidence(
                scanner="surface",
                scanner_version="0.0.1",
                summary="Filename matched.",
                snippet="x" * 201,
                rule_id="sentinel.surface.env-file",
            )
        )
    with pytest.raises(ValidationError):
        finding(references=["http://example.test/plain"])
    with pytest.raises(ValidationError, match="allowlist"):
        Evidence(
            scanner="surface",
            scanner_version="0.0.1",
            summary="Filename matched.",
            rule_id="sentinel.surface.env-file",
            request={
                "method": "GET",
                "url_path": "/health",
                "status_code": 200,
                "selected_headers": {"authorization": "***"},
            },
        )


def test_report_round_trip_keeps_only_declared_fields() -> None:
    now = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
    report = ScanReport(
        sentinel_version="0.0.1",
        scan_id=str(uuid.uuid4()),
        target="apps/api",
        mode="static",
        started_at=now,
        finished_at=now,
        duration_ms=1,
        components=[],
        scanners={"executed": [], "skipped": []},
        dynamic_requests={"sent": [], "withheld": []},
        totals={},
        limitations=[],
        findings=[finding()],
    )
    assert report.dynamic_requests.sent == []
    withheld = WithheldRequest.model_validate(
        {"class": "read_candidate", "method": "GET", "path": "/health"}
    )
    assert withheld.model_dump() == {
        "class": "read_candidate",
        "method": "GET",
        "path": "/health",
    }
    with pytest.raises(ValidationError):
        ScanReport.model_validate(report.model_dump() | {"extra": True})


def test_component_is_frozen() -> None:
    component = Component(
        component_id="apps/api",
        root=Path("apps/api"),
        languages=(Language.PHP,),
        frameworks=(Framework.LARAVEL,),
        evidence=("apps/api/artisan",),
        kind=ComponentKind.APPLICATION,
    )
    with pytest.raises(AttributeError):
        component.component_id = "other"  # type: ignore[misc]


def test_exit_codes_match_the_cli_contract() -> None:
    assert ExitCode.SUCCESS == 0
    assert ExitCode.USAGE == 1
    assert ExitCode.SCAN_FAILURE == 2
    assert ExitCode.THRESHOLD == 3
    assert ExitCode.AUTHORIZATION == 4
    assert issubclass(UsageError, Exception)
    assert issubclass(ScannerError, Exception)
    assert issubclass(ScanFailure, Exception)
    assert issubclass(AuthorizationError, Exception)
