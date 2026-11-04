"""Second line of defense for dynamic scans in this build.

The CLI refuses dynamic modes before ``run_scan``. If a caller reaches
``prepare`` anyway, this runtime raises ``UsageError`` and does not attach a
session or start the target on the host.
"""

from __future__ import annotations

from sentinel.errors import UsageError
from sentinel.protocols import DynamicSession, ScanContext

DYNAMIC_UNAVAILABLE = (
    "dynamic scanning is not in this build (milestone 4); "
    "refusing rather than running the target on the host"
)


class UnavailableDynamicRuntime:
    """Refuse dynamic preparation. This class does not import Docker."""

    def prepare(self, ctx: ScanContext) -> DynamicSession | None:
        del ctx
        raise UsageError(DYNAMIC_UNAVAILABLE)
