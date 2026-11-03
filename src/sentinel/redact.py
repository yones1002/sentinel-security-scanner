"""Mask secrets and cap text before it is stored.

Header values use a whole-value rule. Snippets keep the surrounding text and
replace only the secret-shaped part. The canonical fingerprint is not touched.
"""

from __future__ import annotations

import re

from sentinel.models import HEADER_ALLOWLIST, Finding

SNIPPET_LIMIT = 200
SUMMARY_LIMIT = 500
EXPLANATION_LIMIT = 2000
HEADER_VALUE_LIMIT = 200

_HEADER_SECRET = re.compile(r"password|secret|token|credential", re.IGNORECASE)
_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    r".*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_URL_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@")
_BEARER = re.compile(r"(?i)\bBearer\s+\S+")
_SENSITIVE_NAME = (
    r"(?<![A-Za-z0-9])"
    r"(?:[A-Za-z0-9]+[_.-])*"
    r"(?:password|secret|token|credential)"
    r"(?:[_.-][A-Za-z0-9]+)*"
    r"(?![A-Za-z0-9])"
)
_ASSIGNMENT = re.compile(
    rf"(?P<prefix>{_SENSITIVE_NAME}\s*[:=]\s*)"
    rf"(?P<value>\"[^\"]*\"|'[^']*'|\S+)",
    re.IGNORECASE,
)


def redact_snippet(text: str | None, *, limit: int = SNIPPET_LIMIT) -> str | None:
    """Mask secrets, then keep at most ``limit`` characters.

    ``None`` stays ``None``. An empty string stays empty. The cut is a hard
    cap with no suffix, so the result always fits the finding field.
    """
    if text is None:
        return None
    if limit < 1:
        raise ValueError("redaction limit must be at least 1")
    masked = _mask_secrets(text)
    if len(masked) <= limit:
        return masked
    return masked[:limit]


def redact_header_value(value: str) -> str:
    """Replace a whole header value that names a secret, else cap it."""
    if _HEADER_SECRET.search(value):
        return "***"
    if len(value) <= HEADER_VALUE_LIMIT:
        return value
    return value[:HEADER_VALUE_LIMIT]


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Keep allowlisted names, lowercase, and redact each value.

    ``Authorization`` and ``Set-Cookie`` are not on the allowlist, so their
    values are dropped rather than stored in a masked form.
    """
    kept: dict[str, str] = {}
    for name, value in headers.items():
        key = name.lower()
        if key not in HEADER_ALLOWLIST:
            continue
        kept[key] = redact_header_value(value)
    return kept


def redact_finding(finding: Finding) -> Finding:
    """Return a new finding with stored text and headers redacted.

    The id and fingerprint are copied unchanged. The engine overwrites the
    fingerprint after ownership is known.
    """
    snippet = redact_snippet(finding.evidence.snippet)
    if snippet == "":
        snippet = None
    request = finding.evidence.request
    if request is not None:
        request = request.model_copy(
            update={"selected_headers": redact_headers(request.selected_headers)}
        )
    evidence = finding.evidence.model_copy(
        update={
            "summary": _required(finding.evidence.summary, SUMMARY_LIMIT),
            "snippet": snippet,
            "request": request,
        }
    )
    remediation = finding.remediation.model_copy(
        update={
            "what_is_wrong": _required(finding.remediation.what_is_wrong, SNIPPET_LIMIT),
            "recommended_fix": _required(
                finding.remediation.recommended_fix, SNIPPET_LIMIT
            ),
            "why_dangerous": _mask_secrets(finding.remediation.why_dangerous),
            "where": finding.remediation.where,
            "how_to_verify": _mask_secrets(finding.remediation.how_to_verify),
        }
    )
    return finding.model_copy(
        update={
            "title": _mask_required(finding.title),
            "explanation": _required(finding.explanation, EXPLANATION_LIMIT),
            "evidence": evidence,
            "remediation": remediation,
            "false_positive_notes": _mask_secrets(finding.false_positive_notes),
        }
    )


def _required(value: str, limit: int) -> str:
    redacted = redact_snippet(value, limit=limit)
    if redacted is None or redacted == "":
        raise ValueError("redaction removed required text")
    return redacted


def _mask_required(value: str) -> str:
    redacted = _mask_secrets(value)
    if redacted == "":
        raise ValueError("redaction removed required text")
    return redacted


def _mask_secrets(text: str) -> str:
    masked = _PEM.sub("***", text)
    masked = _URL_USERINFO.sub(r"\1***@", masked)
    masked = _BEARER.sub("Bearer ***", masked)
    return _ASSIGNMENT.sub(_mask_assignment, masked)


def _mask_assignment(match: re.Match[str]) -> str:
    prefix = match.group("prefix")
    value = match.group("value")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return f"{prefix}{value[0]}***{value[0]}"
    return f"{prefix}***"
