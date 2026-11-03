"""Finding schema and the component values a report stores.

Runtime scanner protocols stay out of this module. The engine, not a scanner,
writes a ``ScanReport``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HEADER_ALLOWLIST: frozenset[str] = frozenset(
    {
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
)

_SEMVER = (
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_UUID4 = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_SHA256 = r"^[0-9a-f]{64}$"
_CWE = r"^CWE-[0-9]+$"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingKind(StrEnum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    MISCONFIGURATION = "misconfiguration"
    INFORMATIONAL = "informational"


class Language(StrEnum):
    PHP = "php"
    GO = "go"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    RUBY = "ruby"


class Framework(StrEnum):
    LARAVEL = "laravel"
    WORDPRESS = "wordpress"
    DJANGO = "django"
    FLASK = "flask"
    FASTAPI = "fastapi"
    EXPRESS = "express"
    NESTJS = "nestjs"
    SPRING_BOOT = "spring-boot"
    ASPNET_CORE = "aspnet-core"
    RAILS = "rails"
    REACT = "react"
    VUE = "vue"
    ANGULAR = "angular"


class ComponentKind(StrEnum):
    APPLICATION = "application"
    FRONTEND = "frontend"
    REPOSITORY = "repository"


@dataclass(frozen=True)
class Component:
    """One detected directory. ``root`` is not stored in the report row."""

    component_id: str
    root: Path
    languages: tuple[Language, ...]
    frameworks: tuple[Framework, ...]
    evidence: tuple[str, ...]
    kind: ComponentKind


class Location(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str | None = Field(default=None, max_length=1024)
    line: int | None = None
    end_line: int | None = None
    endpoint: str | None = Field(default=None, max_length=512)


class CookieFlag(BaseModel):
    """Cookie attributes only. The cookie value is never stored."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    secure: bool
    http_only: bool
    samesite: Literal["Strict", "Lax", "None"] | None = None


class HttpEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "HEAD"]
    url_path: str = Field(min_length=1)
    status_code: int
    selected_headers: dict[str, str]
    cookies: list[CookieFlag] = Field(default_factory=list)
    body_sha256: str | None = Field(default=None, pattern=_SHA256)
    body_length: int | None = Field(default=None, ge=0)
    body_stored: Literal[False] = False

    @field_validator("url_path")
    @classmethod
    def path_has_no_query(cls, value: str) -> str:
        if "?" in value or "\\" in value:
            raise ValueError("url_path is the path only")
        return value

    @field_validator("selected_headers")
    @classmethod
    def headers_stay_on_the_allowlist(cls, value: dict[str, str]) -> dict[str, str]:
        unknown = sorted(set(value) - HEADER_ALLOWLIST)
        if unknown:
            raise ValueError(f"header not on the allowlist: {', '.join(unknown)}")
        for header_value in value.values():
            if len(header_value) > 200:
                raise ValueError("header value exceeds 200 characters")
        return value


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scanner: str = Field(min_length=1, max_length=64)
    scanner_version: str = Field(min_length=1, max_length=32, pattern=_SEMVER)
    rule_pack_version: str | None = Field(default=None, min_length=1, max_length=32)
    summary: str = Field(min_length=1, max_length=500)
    snippet: str | None = Field(default=None, min_length=1, max_length=200)
    rule_id: str = Field(min_length=1, max_length=200)
    request: HttpEvidence | None = None


class Recommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    what_is_wrong: str = Field(min_length=1)
    why_dangerous: str = Field(min_length=1)
    where: str = Field(min_length=1)
    recommended_fix: str = Field(min_length=1)
    secure_sketch: str | None = None
    sketch_language: str | None = None
    how_to_verify: str = Field(min_length=1)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    id: str = Field(pattern=_UUID4)
    fingerprint: str = Field(pattern=_SHA256)
    title: str = Field(min_length=1)
    severity: Severity
    confidence: Confidence
    kind: FindingKind
    cwe: str | None = Field(default=None, pattern=_CWE)
    # Copied from an OSV group id. Sentinel does not invent this value.
    cve: str | None = None
    location: Location
    explanation: str = Field(min_length=1, max_length=2000)
    evidence: Evidence
    remediation: Recommendation
    references: list[str] = Field(max_length=20)
    scanner: str = Field(min_length=1, max_length=64)
    scanner_version: str = Field(min_length=1, max_length=32, pattern=_SEMVER)
    fingerprint_version: Literal["v1"] = "v1"
    false_positive_notes: str
    component_id: str = Field(min_length=1)

    @field_validator("references")
    @classmethod
    def references_are_https(cls, value: list[str]) -> list[str]:
        for item in value:
            if len(item) > 500 or not item.startswith("https://"):
                raise ValueError("references are https URLs of at most 500 characters")
        return value

    @model_validator(mode="after")
    def evidence_names_this_scanner(self) -> Finding:
        if self.evidence.scanner != self.scanner:
            raise ValueError("evidence.scanner must match scanner")
        if self.evidence.scanner_version != self.scanner_version:
            raise ValueError("evidence.scanner_version must match scanner_version")
        return self


class ReportComponent(BaseModel):
    """Component fields stored on a report. This row has no filesystem root."""

    model_config = ConfigDict(extra="forbid")

    component_id: str = Field(min_length=1)
    languages: list[Language]
    frameworks: list[Framework]
    evidence: list[str]
    kind: ComponentKind


class ExecutedScanner(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    version: str = Field(min_length=1, max_length=32, pattern=_SEMVER)
    rule_pack_version: str | None = None
    tool_version: str | None = None
    duration_ms: int = Field(ge=0)
    status: Literal["executed", "skipped", "failed"]
    finding_count: int = Field(ge=0)
    reason: str | None = None


class SkippedScanner(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    failed: bool


class ScannerSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executed: list[ExecutedScanner] = Field(default_factory=list)
    skipped: list[SkippedScanner] = Field(default_factory=list)


class SentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "HEAD"]
    path: str = Field(min_length=1)


class WithheldRequest(BaseModel):
    """A withheld row. JSON uses ``class`` because that is the report field."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        serialize_by_alias=True,
    )

    request_class: Literal["read_candidate", "ambiguous", "state_changing"] = Field(
        alias="class"
    )
    method: str = Field(min_length=1)
    path: str = Field(min_length=1)


class DynamicRequests(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sent: list[SentRequest] = Field(default_factory=list)
    withheld: list[WithheldRequest] = Field(default_factory=list)


class Totals(BaseModel):
    model_config = ConfigDict(extra="forbid")

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    informational: int = Field(default=0, ge=0)


class ChangedFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str = Field(pattern=_SHA256)
    baseline_severity: Severity
    severity: Severity
    baseline_kind: FindingKind
    kind: FindingKind


class Comparison(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_scan_id: str = Field(pattern=_UUID4)
    new: list[str]
    resolved: list[str]
    persisting: list[str]
    changed: list[ChangedFinding]
    resolved_findings: list[Finding]


class ScanReport(BaseModel):
    """The document the engine writes. Scanners do not construct it."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    sentinel_version: str = Field(min_length=1)
    scan_id: str = Field(pattern=_UUID4)
    target: str = Field(min_length=1)
    url: str | None = None
    mode: Literal["static", "dynamic", "all"]
    started_at: datetime
    finished_at: datetime
    duration_ms: int = Field(ge=0)
    components: list[ReportComponent]
    fingerprint_version: Literal["v1"] = "v1"
    scanners: ScannerSection
    dynamic_requests: DynamicRequests
    totals: Totals
    strict_failure: bool = False
    limitations: list[str]
    findings: list[Finding]
    comparison: Comparison | None = None

    @field_validator("started_at", "finished_at")
    @classmethod
    def timestamps_are_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return value
