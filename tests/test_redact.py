"""Redaction of snippets, headers, and stored findings."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from sentinel.models import (
    Evidence,
    Finding,
    FindingKind,
    HttpEvidence,
    Location,
    Recommendation,
    Severity,
)
from sentinel.redact import (
    HEADER_VALUE_LIMIT,
    SNIPPET_LIMIT,
    redact_finding,
    redact_header_value,
    redact_headers,
    redact_snippet,
)

DIGEST = "ab" * 32
SECRET = "SUPERSECRET"


def _recommendation(**overrides: object) -> Recommendation:
    payload: dict[str, object] = {
        "what_is_wrong": "A dotenv file is inside the scanned tree.",
        "why_dangerous": "These files often hold credentials.",
        "where": "apps/api/.env",
        "recommended_fix": "Keep real environment files out of the tree.",
        "how_to_verify": "Re-run the scan and confirm the rule is absent.",
    }
    payload.update(overrides)
    return Recommendation.model_validate(payload)


def _finding(**overrides: object) -> Finding:
    payload: dict[str, object] = {
        "id": str(uuid.uuid4()),
        "fingerprint": DIGEST,
        "title": "Environment file is present in the tree",
        "severity": Severity.HIGH,
        "confidence": "high",
        "kind": FindingKind.MISCONFIGURATION,
        "location": Location(path="apps/api/.env", line=4),
        "explanation": "A file named .env was found. Contents were not read.",
        "evidence": Evidence(
            scanner="surface",
            scanner_version="0.0.1",
            summary="Filename matched the .env rule.",
            snippet=None,
            rule_id="sentinel.surface.env-file",
        ),
        "remediation": _recommendation(),
        "references": [],
        "scanner": "surface",
        "scanner_version": "0.0.1",
        "false_positive_notes": "Pattern match only.",
        "component_id": "apps/api",
    }
    payload.update(overrides)
    return Finding.model_validate(payload)


def test_snippet_cap_is_a_hard_200_characters() -> None:
    body = "a" * 250
    redacted = redact_snippet(body)
    assert redacted == "a" * SNIPPET_LIMIT
    assert redacted is not None
    assert len(redacted) == 200
    assert len(redact_snippet("s" * 800, limit=500) or "") == 500
    assert len(redact_snippet("e" * 2500, limit=2000) or "") == 2000


def test_mask_runs_before_the_cap() -> None:
    body = f'password = "{SECRET}" ' + ("a" * 250)
    redacted = redact_snippet(body)
    assert redacted is not None
    assert SECRET not in redacted
    assert redacted.startswith('password = "***"')
    assert len(redacted) == 200


def test_assignment_mask_keeps_ordinary_words() -> None:
    assert redact_snippet('password = "hunter2"') == 'password = "***"'
    assert redact_snippet("api_token=raw-value") == "api_token=***"
    assert redact_snippet('user-secret: "abc"') == 'user-secret: "***"'
    ordinary = 'tokenize = "safe-word"'
    assert redact_snippet(ordinary) == ordinary


def test_structural_secrets_are_masked() -> None:
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "QUJDRA==\n"
        "-----END PRIVATE KEY-----"
    )
    url = f"postgres://app:{SECRET}@localhost/db"
    bearer = f"Authorization: Bearer {SECRET}"
    assert redact_snippet(pem) == "***"
    assert SECRET not in (redact_snippet(url) or "")
    assert redact_snippet(url) == "postgres://***@localhost/db"
    assert redact_snippet(bearer) == "Authorization: Bearer ***"
    assert SECRET not in (redact_snippet(bearer) or "")


def test_empty_and_none_snippets_stay_distinct() -> None:
    assert redact_snippet(None) is None
    assert redact_snippet("") == ""
    with pytest.raises(ValueError, match="limit"):
        redact_snippet("abc", limit=0)


def test_header_values_follow_the_allowlist_rule() -> None:
    long_server = "n" * (HEADER_VALUE_LIMIT + 40)
    headers = redact_headers(
        {
            "Content-Type": "text/plain",
            "Server": long_server,
            "X-Frame-Options": f"DENY {SECRET} token",
            "Authorization": f"Bearer {SECRET}",
            "Set-Cookie": f"session={SECRET}; HttpOnly",
        }
    )
    assert headers["content-type"] == "text/plain"
    assert headers["server"] == "n" * HEADER_VALUE_LIMIT
    assert headers["x-frame-options"] == "***"
    assert "authorization" not in headers
    assert "set-cookie" not in headers
    assert SECRET not in str(headers)
    assert "Bearer" not in str(headers)
    assert redact_header_value("nginx") == "nginx"


def test_redact_finding_caps_text_and_keeps_identity() -> None:
    original = _finding(
        title="title stays",
        evidence=Evidence(
            scanner="surface",
            scanner_version="0.0.1",
            summary="Filename matched the .env rule.",
            snippet="line " * 20,
            rule_id="sentinel.surface.env-file",
            request=HttpEvidence(
                method="GET",
                url_path="/health",
                status_code=200,
                selected_headers={"server": f"nginx {SECRET} credential"},
            ),
        ),
        remediation=_recommendation(
            what_is_wrong=f'password = "{SECRET}" ' + ("w" * 300),
        ),
    )
    redacted = redact_finding(original)
    assert redacted.id == original.id
    assert redacted.fingerprint == original.fingerprint
    assert redacted.evidence.snippet == "line " * 20
    assert len(redacted.remediation.what_is_wrong) == 200
    assert redacted.evidence.request is not None
    assert redacted.evidence.request.selected_headers == {"server": "***"}
    assert SECRET not in redacted.model_dump_json()
    assert redact_finding(redacted).model_dump() == redacted.model_dump()


def test_redact_finding_turns_a_blank_snippet_into_none() -> None:
    redacted = redact_finding(_finding())
    assert redacted.evidence.snippet is None


def test_secret_text_is_masked_and_not_echoed() -> None:
    finding = _finding(
        title='password = "ab"',
        explanation=(
            "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n"
            "The rest of the explanation stays."
        ),
        evidence=Evidence(
            scanner="surface",
            scanner_version="0.0.1",
            summary=f'password = "{SECRET}"',
            rule_id="sentinel.surface.env-file",
        ),
    )
    redacted = redact_finding(finding)
    assert redacted.title == 'password = "***"'
    assert redacted.evidence.summary == 'password = "***"'
    assert "QUJD" not in redacted.explanation
    assert "The rest of the explanation stays." in redacted.explanation
    assert SECRET not in redacted.model_dump_json()


def test_redacted_finding_still_validates() -> None:
    redacted = redact_finding(
        _finding(
            evidence=Evidence(
                scanner="surface",
                scanner_version="0.0.1",
                summary="Filename matched.",
                snippet=f'const token = "{SECRET}";',
                rule_id="sentinel.surface.env-file",
            )
        )
    )
    Finding.model_validate(redacted.model_dump())
    assert redacted.evidence.snippet == 'const token = "***";'
    with pytest.raises(ValidationError):
        Evidence(
            scanner="surface",
            scanner_version="0.0.1",
            summary="Filename matched.",
            snippet="x" * 201,
            rule_id="sentinel.surface.env-file",
        )
