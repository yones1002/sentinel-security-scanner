"""Version ``v1`` finding fingerprints.

The canonical string is hashed and then discarded. It is not stored on the
finding. There is no second hash.
"""

from __future__ import annotations

import hashlib
import unicodedata

from sentinel.models import Finding

FINGERPRINT_VERSION = "v1"


def line_bucket(line: int | None) -> str:
    """Return the 10-line bucket, or an empty string when the line is absent.

    Lines 1–10 share ``"0"``. Lines 11–20 share ``"1"``. A missing line is
    not bucket 0. A line below 1 is not hashed.
    """
    if line is None:
        return ""
    if line < 1:
        raise ValueError("line < 1 is not hashed")
    return str((line - 1) // 10)


def normalize_path(path: str | None) -> str:
    """Return an NFC posix path, or reject a path that must not be hashed.

    Backslashes become slashes and a leading ``./`` is stripped. An absolute
    path, a NUL, or a ``..`` segment is rejected. The engine treats that
    rejection as ``unassigned path dropped`` and does not hash the finding.
    """
    if path is None:
        return ""
    if "\x00" in path:
        raise ValueError(f"unassigned path dropped: {path}")
    text = unicodedata.normalize("NFC", path.replace("\\", "/"))
    while text.startswith("./"):
        text = text[2:]
    if text.startswith("/") or _is_drive_path(text):
        raise ValueError(f"unassigned path dropped: {path}")
    if any(segment == ".." for segment in text.split("/")):
        raise ValueError(f"unassigned path dropped: {path}")
    return text


def normalize_endpoint(endpoint: str | None) -> str:
    """Return ``METHOD /path`` with the query string removed.

    The method is uppercased. ``None`` and an empty value become an empty
    string. ``GET /health?x=1`` becomes ``GET /health``.
    """
    if endpoint is None:
        return ""
    text = unicodedata.normalize("NFC", endpoint).strip()
    if not text:
        return ""
    method, separator, remainder = text.partition(" ")
    if not separator:
        return method.upper()
    path = remainder.split("?", 1)[0]
    return f"{method.upper()} {path}"


def canonical_fingerprint_input(finding: Finding) -> str:
    """Build the ``v1`` string. Callers hash it and do not store it."""
    path = normalize_path(finding.location.path)
    endpoint = normalize_endpoint(finding.location.endpoint)
    bucket = line_bucket(finding.location.line)
    rule_id = unicodedata.normalize("NFC", finding.evidence.rule_id)
    scanner = unicodedata.normalize("NFC", finding.scanner)
    component = unicodedata.normalize("NFC", finding.component_id)
    return f"v1|{scanner}|{rule_id}|{component}|{path}|{bucket}|{endpoint}"


def fingerprint(finding: Finding) -> str:
    """Return the 64-character lowercase SHA-256 of the canonical string."""
    digest = hashlib.sha256(
        canonical_fingerprint_input(finding).encode("utf-8")
    ).hexdigest()
    return digest


def fingerprint_versions_differ(baseline: str, current: str) -> str:
    """Sentence used when two scans do not share a fingerprint version.

    Compare sets stay empty. The digests are not treated as one issue.
    """
    return f"fingerprint versions differ: {baseline} vs {current}"


def _is_drive_path(path: str) -> bool:
    return len(path) >= 2 and path[0].isalpha() and path[1] == ":"
