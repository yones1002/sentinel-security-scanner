"""Scanner, renderer, sandbox, and runtime protocols.

This module is a leaf. It may import models and scan configuration. It does
not import scanners, the registry, or Docker. ``StartPlan`` and
``ContainerSpec`` stay names only until the sandbox allowlist exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from sentinel.config import Authorization, ScanConfig
from sentinel.models import Comparison, Component, Finding, ScanReport


class ScanMode(StrEnum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    ALL = "all"


class ScannerScope(StrEnum):
    ROOT = "root"
    COMPONENT = "component"


@dataclass(frozen=True)
class ProbeResult:
    """One probe. ``reason`` is required when the scanner is unavailable."""

    available: bool
    version: str | None
    reason: str | None
    failed: bool = False

    def __post_init__(self) -> None:
        if not self.available and not self.reason:
            raise ValueError("probe reason is required when unavailable")


class ScannerRunStatus(StrEnum):
    EXECUTED = "executed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True)
class ScannerSkip:
    """A skip. ``failed`` is true only when a scan run was attempted and failed."""

    name: str
    reason: str
    failed: bool


@dataclass(frozen=True)
class ScannerRun:
    """One invocation. The report stores the same fields on ``ExecutedScanner``."""

    name: str
    version: str
    rule_pack_version: str | None
    tool_version: str | None
    duration_ms: int
    status: ScannerRunStatus
    finding_count: int
    reason: str | None = None


@dataclass(frozen=True)
class ComponentScanTarget:
    """The component a scanner is invoked for, plus nested roots to exclude."""

    component: Component
    exclude_roots: tuple[Path, ...]


@dataclass(frozen=True)
class RequestRecord:
    """One admission decision already made by a scanner.

    ``sent=True`` records a request the scanner says was already admitted.
    It is not permission for the engine to open a socket. No body is stored.
    """

    request_class: str
    method: str
    path: str
    sent: bool


@dataclass(frozen=True)
class ScanPluginResult:
    """What ``Scanner.scan`` returns. The engine writes the report."""

    findings: tuple[Finding, ...]
    skips: tuple[ScannerSkip, ...] = ()
    limitations: tuple[str, ...] = ()
    requests: tuple[RequestRecord, ...] = ()


@dataclass(frozen=True)
class SandboxHandle:
    """A started sandbox. URL mode does not create one."""

    base_url: str
    scan_id: str

    def stop(self) -> None: ...


@dataclass(frozen=True)
class DynamicSession:
    """The session scanners read. ``handle`` is None for URL mode."""

    base_url: str
    limitations: tuple[str, ...]
    handle: SandboxHandle | None


@dataclass(frozen=True)
class ScanContext:
    """One frozen context. The engine replaces it; it does not mutate it.

    The CLI builds this with ``components=()`` and ``dynamic_session=None``.
    Scanners see the replaced value. ``url_host`` is set only by the URL gate.
    """

    scan_id: str
    mode: ScanMode
    target: Path | None
    url: str | None
    url_host: str | None
    pinned_address: str | None
    started_at: datetime
    components: tuple[Component, ...]
    config: ScanConfig
    authorization: Authorization
    work_dir: Path
    dynamic_session: DynamicSession | None = None


@runtime_checkable
class Scanner(Protocol):
    """One scanner. ``scan`` returns a result and does not touch the report."""

    name: str
    version: str
    rule_pack_version: str | None
    timeout_s: int
    modes: frozenset[str]
    scope: ScannerScope

    def probe(self, ctx: ScanContext) -> ProbeResult: ...

    def supports(self, component: Component) -> bool: ...

    def scan(self, ctx: ScanContext, target: ComponentScanTarget) -> ScanPluginResult: ...


@runtime_checkable
class ReportRenderer(Protocol):
    """Render a report. Comparison is the PR 2 model."""

    format_id: str

    def render(self, report: ScanReport, compare: Comparison | None = None) -> str: ...


@runtime_checkable
class Sandbox(Protocol):
    """Container lifecycle. The spec types arrive with the allowlist."""

    def build_spec(self, ctx: ScanContext, plan: StartPlan) -> ContainerSpec: ...  # noqa: F821

    def run(self, spec: ContainerSpec) -> SandboxHandle: ...  # noqa: F821


@runtime_checkable
class DynamicRuntime(Protocol):
    """What the engine calls before dynamic probes. Milestone 1 refuses."""

    def prepare(self, ctx: ScanContext) -> DynamicSession | None: ...


@runtime_checkable
class Explainer(Protocol):
    """Optional seam. Not registered in milestone 1 through 5.

    Must not create findings or change severity, kind, evidence, CVE, CWE,
    or fingerprint. Output is labeled non-evidence.
    """

    def explain(self, finding: Finding) -> str | None: ...
