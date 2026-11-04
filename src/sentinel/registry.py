"""Explicit scanner registration.

Milestone 1 does not read entry points. Surface, Semgrep, and the renderers
are registered by later pull requests. ``builtin_scanners`` still applies the
timeout ceiling so a later registration cannot skip it. The engine does not
clamp a timeout that reaches ``run_scan`` directly.
"""

from __future__ import annotations

from collections.abc import Sequence

from sentinel.errors import UsageError
from sentinel.protocols import ReportRenderer, Scanner

_STATIC_TIMEOUT_S = 600
_DYNAMIC_TIMEOUT_S = 180


def builtin_scanners() -> tuple[Scanner, ...]:
    """Return the scanners this build runs. PR 5 registers none."""
    selected: tuple[Scanner, ...] = ()
    enforce_registration(selected)
    return selected


def renderers() -> tuple[ReportRenderer, ...]:
    """Return report renderers. JSON and Markdown arrive in a later PR."""
    selected: tuple[ReportRenderer, ...] = ()
    enforce_renderer_ids(selected)
    return selected


def enforce_registration(scanners: Sequence[Scanner]) -> None:
    """Reject duplicate names and timeouts above the mode ceiling.

    A scanner whose modes include ``dynamic`` uses the 180 second ceiling,
    including when it also lists ``static``. A static-only scanner uses 600.
    """
    names: list[str] = []
    for scanner in scanners:
        if scanner.name in names:
            raise UsageError(f"duplicate scanner name {scanner.name}")
        names.append(scanner.name)
    for scanner in scanners:
        _reject_timeout(scanner)


def enforce_renderer_ids(renderers_to_check: Sequence[ReportRenderer]) -> None:
    """Reject two renderers that share a format id."""
    names = [item.format_id for item in renderers_to_check]
    if len(names) != len(set(names)):
        raise UsageError("duplicate renderer format_id")


def _reject_timeout(scanner: Scanner) -> None:
    dynamic = "dynamic" in scanner.modes
    ceiling = _DYNAMIC_TIMEOUT_S if dynamic else _STATIC_TIMEOUT_S
    if scanner.timeout_s > ceiling:
        kind = "dynamic" if dynamic else "static"
        raise UsageError(
            f"{kind} scanner {scanner.name} timeout_s {scanner.timeout_s} exceeds {ceiling}"
        )
