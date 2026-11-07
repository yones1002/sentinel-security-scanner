"""Milestone-1 remediation text.

Surface rule ids have catalog rows. Every other rule id uses
``fallback_remediation``. Catalog sketches are a later pull request.
"""

from __future__ import annotations

from sentinel.models import Recommendation
from sentinel.redact import redact_snippet

PATTERN_DISCLAIMER = (
    "Pattern match only. The scanner did not execute the application. "
    "A match can be in a test double, a migration, or dead code."
)

_SURFACE_ROWS: dict[str, tuple[str, str, str]] = {
    "sentinel.surface.env-file": (
        "A dotenv file is inside the scanned tree.",
        "These files often hold credentials and are easy to commit or to publish into an image.",
        (
            "Keep real environment files out of the tree and out of images. "
            "Commit only a template with placeholder keys."
        ),
    ),
    "sentinel.surface.private-key-filename": (
        "A private-key filename is inside the scanned tree.",
        "A private key file in the tree can be committed or copied into an image.",
        "Remove private keys from the tree and keep them outside the project.",
    ),
    "sentinel.surface.vcs-metadata": (
        "Git metadata is present below the scan root.",
        "Nested Git metadata can publish repository history inside the scanned tree.",
        (
            "Remove nested Git metadata from the tree. The scan root's own .git directory "
            "is not this finding."
        ),
    ),
    "sentinel.surface.wp-config-in-tree": (
        "wp-config.php is inside the scanned tree.",
        "This file often holds database credentials and is easy to publish.",
        "Keep wp-config.php out of published trees and images.",
    ),
    "sentinel.surface.compose-docker-sock": (
        "A compose file contains the literal docker.sock.",
        "The literal docker.sock appears in a compose file.",
        "Remove the docker.sock literal from the compose file.",
    ),
    "sentinel.surface.compose-privileged": (
        "A compose file contains the literal privileged: true.",
        "The literal privileged: true appears in a compose file.",
        "Remove the privileged: true literal from the compose file.",
    ),
    "sentinel.surface.k8s-host-network": (
        "A manifest contains the literal hostNetwork: true.",
        "The literal hostNetwork: true appears under a deployment directory.",
        "Remove the hostNetwork: true literal from the manifest.",
    ),
    "sentinel.surface.world-writable": (
        "A candidate file is world-writable.",
        (
            "A workstation umask is weak evidence. The other-write bit was set on the "
            "candidate itself."
        ),
        "Remove the other-write bit from the candidate file.",
    ),
}


def recommendation_for(rule_id: str, framework: str | None) -> Recommendation | None:
    """Catalog text for a known surface rule id, or None.

    ``framework`` is ignored. Milestone 1 has no framework-specific rows.
    The scanner replaces ``where`` and ``how_to_verify`` with the finding path.
    """

    del framework
    row = _SURFACE_ROWS.get(rule_id)
    if row is None:
        return None
    what_is_wrong, why_dangerous, recommended_fix = row
    return Recommendation(
        what_is_wrong=what_is_wrong,
        why_dangerous=why_dangerous,
        where="path",
        recommended_fix=recommended_fix,
        secure_sketch=None,
        sketch_language=None,
        how_to_verify=(
            "Re-run sentinel scan on this path and confirm rule "
            f"{rule_id} is absent for path."
        ),
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
