"""Milestone-1 remediation text.

Catalog sketches are a later pull request. Until a row exists, scanners use
``fallback_remediation`` and do not invent a second sentence.
"""

from __future__ import annotations

from sentinel.models import Recommendation
from sentinel.redact import redact_snippet

PATTERN_DISCLAIMER = (
    "Pattern match only. The scanner did not execute the application. "
    "A match can be in a test double, a migration, or dead code."
)


def fallback_remediation(
    message: str,
    path: str,
    line: int | None,
    rule_id: str,
) -> Recommendation:
    """Build the milestone-1 template. The message is not split."""
    text = redact_snippet(message)
    if text is None or text == "":
        raise ValueError("remediation message is empty")
    where = path if line is None else f"{path}:{line}"
    return Recommendation(
        what_is_wrong=text,
        why_dangerous=PATTERN_DISCLAIMER,
        where=where,
        recommended_fix=text,
        secure_sketch=None,
        sketch_language=None,
        how_to_verify=(
            "Re-run sentinel scan on this path and confirm rule "
            f"{rule_id} is absent for {where}."
        ),
    )
