"""Sentinel command line.

Static scans call the engine and the registered renderers. Dynamic mode,
URL mode, history, and HTML stop here, before any socket.
"""

from __future__ import annotations

import ipaddress
import tempfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
from typer import _click

from sentinel import __version__
from sentinel.config import load_scan_config
from sentinel.detect import apply_external_components, detect
from sentinel.engine import run_scan
from sentinel.errors import AuthorizationError, ExitCode, ScanFailure, UsageError
from sentinel.models import Finding, ScanReport
from sentinel.protocols import ScanContext, ScanMode
from sentinel.registry import builtin_scanners, renderers
from sentinel.sandbox.unavailable import DYNAMIC_UNAVAILABLE, UnavailableDynamicRuntime

# Vendored Click uses exit 2 for a bad flag. This CLI maps that mistake to exit 1.
_click.exceptions.UsageError.exit_code = 1

app = typer.Typer(
    name="sentinel",
    help="Defensive scanner for projects you own.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
)
plugins_app = typer.Typer(
    name="plugins",
    help="Show the scanners this build can run.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
)
history_app = typer.Typer(
    name="history",
    help="History maintenance is a later milestone.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
)
app.add_typer(plugins_app, name="plugins")
app.add_typer(history_app, name="history")

_FORMATS = frozenset({"json", "markdown", "html"})
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
_DEFAULT_ALLOW_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_NESTED_PREFIXES = (
    "unreadable directory: ",
    "permission denied: ",
    "refused directory inode mismatch: ",
    "directory listing refused, no confined descriptor: ",
)
_AUTH_REQUIRED = (
    "dynamic scanning requires --authorized; "
    "refusing before any network or container operation"
)
_HISTORY_UNAVAILABLE = "history store is not in this build (milestone 2)"
_HISTORY_MAINTENANCE = "history maintenance is not in this build (milestone 6)"
_HTML_UNAVAILABLE = "html format is not in this build (milestone 3)"
_REPORT_UNAVAILABLE = "report is not in this build (milestone 2)"
_URL_USERINFO = "URL must not contain a backslash or userinfo"
_URL_SCHEME = "URL scheme must be http or https"
_URL_HOSTNAME = "URL hostname is missing or has a trailing dot"


def parse_scan_url(raw: str, allow_hosts: frozenset[str] | set[str]) -> str:
    """Return the normalized host. Raise before any name lookup.

    A malformed URL is ``UsageError``. A host outside ``allow_hosts`` is
    ``AuthorizationError``. This function does not open a socket.
    """

    host = _url_host(raw)
    allowed = {_normalize_host(item) for item in allow_hosts}
    if host not in allowed:
        raise AuthorizationError(
            f"host {host} is not on the allowlist; refusing before any network operation"
        )
    return host


@app.callback()
def main() -> None:
    """Defensive scanner for projects you own."""


@app.command(name="version")
def version_command() -> None:
    """Print the Sentinel package version."""
    typer.echo(__version__)


@app.command(name="detect")
def detect_command(
    path: Annotated[Path, typer.Argument(help="Directory to inspect.")],
    config: Annotated[Path | None, typer.Option("--config")] = None,
) -> None:
    """Print detected components. This command does not scan for findings."""
    _finish(lambda: _detect(path, config))


@plugins_app.command(name="list")
def plugins_list_command() -> None:
    """Print the registered scanners and their probe results."""
    _finish(_plugins)


@app.command(name="scan")
def scan_command(
    path: Annotated[Path | None, typer.Argument(help="Directory to scan.")] = None,
    static: Annotated[bool, typer.Option("--static")] = False,
    dynamic: Annotated[bool, typer.Option("--dynamic")] = False,
    scan_all: Annotated[bool, typer.Option("--all")] = False,
    url: Annotated[str | None, typer.Option("--url")] = None,
    report_format: Annotated[str, typer.Option("--format")] = "markdown",
    output: Annotated[Path | None, typer.Option("--output")] = None,
    fail_on: Annotated[str, typer.Option("--fail-on")] = "none",
    strict_tools: Annotated[bool, typer.Option("--strict-tools")] = False,
    config: Annotated[Path | None, typer.Option("--config")] = None,
    history: Annotated[bool, typer.Option("--history")] = False,
    authorized: Annotated[bool, typer.Option("--authorized")] = False,
    allow_host: Annotated[list[str] | None, typer.Option("--allow-host")] = None,
) -> None:
    """Scan a tree you own. This build runs static mode only."""
    _finish(
        lambda: _scan(
            path,
            static=static,
            dynamic=dynamic,
            scan_all=scan_all,
            url=url,
            report_format=report_format,
            output=output,
            fail_on=fail_on,
            strict_tools=strict_tools,
            config=config,
            history=history,
            authorized=authorized,
            allow_host=allow_host,
        )
    )


@app.command(name="report")
def report_command(
    scan_id: Annotated[str | None, typer.Option("--scan-id")] = None,
    report_format: Annotated[str, typer.Option("--format")] = "markdown",
    output: Annotated[Path | None, typer.Option("--output")] = None,
    compare: Annotated[str | None, typer.Option("--compare")] = None,
) -> None:
    """Report lookup arrives with the history store."""
    del scan_id, report_format, output, compare
    _finish(lambda: (_refuse(_REPORT_UNAVAILABLE)))


@history_app.command(name="list")
def history_list_command() -> None:
    """List stored scans. Maintenance is a later milestone."""
    _finish(lambda: (_refuse(_HISTORY_MAINTENANCE)))


@history_app.command(name="prune")
def history_prune_command(
    older_than: Annotated[int | None, typer.Option("--older-than")] = None,
) -> None:
    """Delete old scans. Maintenance is a later milestone."""
    del older_than
    _finish(lambda: (_refuse(_HISTORY_MAINTENANCE)))


def _finish(action: Callable[[], int]) -> None:
    try:
        code = action()
    except UsageError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(int(ExitCode.USAGE)) from exc
    except AuthorizationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(int(ExitCode.AUTHORIZATION)) from exc
    except ScanFailure as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(int(ExitCode.SCAN_FAILURE)) from exc
    raise typer.Exit(int(code))


def _refuse(message: str) -> int:
    raise UsageError(message)


def _detect(path: Path, config: Path | None) -> int:
    loaded = load_scan_config(config, target=path, attested=False)
    found = detect(path, loaded.config.detect)
    components = apply_external_components(found.components, loaded.config.component_overrides)
    lines = ["component_id\tkind\tlanguages\tframeworks\tevidence"]
    for component in components:
        lines.append(
            "\t".join(
                (
                    component.component_id,
                    component.kind.value,
                    _joined(component.languages),
                    _joined(component.frameworks),
                    _joined(component.evidence),
                )
            )
        )
    typer.echo("\n".join(lines))
    if found.nested_unreadable:
        return int(ExitCode.SCAN_FAILURE)
    return int(ExitCode.SUCCESS)


def _plugins() -> int:
    loaded = load_scan_config(None, target=None, attested=False)
    context = ScanContext(
        scan_id=str(uuid.uuid4()),
        mode=ScanMode.STATIC,
        target=None,
        url=None,
        url_host=None,
        pinned_address=None,
        started_at=datetime.now(UTC),
        components=(),
        config=loaded.config,
        authorization=loaded.authorization,
        work_dir=Path("."),
    )
    lines = ["name\tversion\trule_pack_version\tmodes\tscope\tprobe"]
    for scanner in builtin_scanners():
        probe = scanner.probe(context)
        pack = scanner.rule_pack_version or ""
        modes = ",".join(sorted(scanner.modes))
        lines.append(
            "\t".join(
                (
                    scanner.name,
                    scanner.version,
                    pack,
                    modes,
                    scanner.scope.value,
                    _probe_cell(probe.available, probe.failed, probe.reason),
                )
            )
        )
    typer.echo("\n".join(lines))
    return int(ExitCode.SUCCESS)


def _scan(
    path: Path | None,
    *,
    static: bool,
    dynamic: bool,
    scan_all: bool,
    url: str | None,
    report_format: str,
    output: Path | None,
    fail_on: str,
    strict_tools: bool,
    config: Path | None,
    history: bool,
    authorized: bool,
    allow_host: list[str] | None,
) -> int:
    chosen = [
        name
        for name, flag in (("--static", static), ("--dynamic", dynamic), ("--all", scan_all))
        if flag
    ]
    if len(chosen) > 1:
        raise UsageError("choose one of --static, --dynamic, or --all")
    if path is not None and url is not None:
        raise UsageError("pass a path or --url, not both")
    if path is None and url is None:
        raise UsageError("a path or --url is required")
    if url is not None and static:
        raise UsageError("URL mode cannot be combined with --static")
    if report_format not in _FORMATS:
        raise UsageError(f"unknown format: {report_format}")
    if path is not None and not path.is_dir():
        raise UsageError("path does not exist or is not a directory")
    loaded = load_scan_config(
        config,
        target=path,
        attested=authorized,
        fail_on=fail_on,
        strict_tools=strict_tools,
        history=False,
    )
    dynamic_request = dynamic or scan_all or url is not None
    if dynamic_request:
        _refuse_dynamic(url, authorized=authorized, allow_host=allow_host)
    if history:
        raise UsageError(_HISTORY_UNAVAILABLE)
    if report_format == "html":
        raise UsageError(_HTML_UNAVAILABLE)
    if path is None:
        raise UsageError("a path or --url is required")
    with tempfile.TemporaryDirectory(prefix="sentinel-work-") as work:
        context = ScanContext(
            scan_id=str(uuid.uuid4()),
            mode=ScanMode.STATIC,
            target=path.resolve(),
            url=None,
            url_host=None,
            pinned_address=None,
            started_at=datetime.now(UTC),
            components=(),
            config=loaded.config,
            authorization=loaded.authorization,
            work_dir=Path(work),
        )
        report = run_scan(
            context,
            builtin_scanners(),
            dynamic=UnavailableDynamicRuntime(),
            store=None,
        )
        for note in loaded.limitations:
            if note not in report.limitations:
                report.limitations.append(note)
        rendered = _render(report, report_format)
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            output.write_text(rendered, encoding="utf-8")
    if _nested_unreadable(report.limitations):
        return int(ExitCode.SCAN_FAILURE)
    if report.strict_failure:
        return int(ExitCode.SCAN_FAILURE)
    if _meets_threshold(report.findings, fail_on):
        return int(ExitCode.THRESHOLD)
    return int(ExitCode.SUCCESS)


def _refuse_dynamic(url: str | None, *, authorized: bool, allow_host: list[str] | None) -> None:
    """Refuse before ``run_scan``. A bad host wins over a missing attestation.

    Malformed URLs raise ``UsageError`` from ``parse_scan_url`` and stay exit 1.
    """

    if url is not None:
        hosts = set(_DEFAULT_ALLOW_HOSTS)
        hosts.update(allow_host or ())
        parse_scan_url(url, hosts)
    if not authorized:
        raise AuthorizationError(_AUTH_REQUIRED)
    raise UsageError(DYNAMIC_UNAVAILABLE)


def _render(report: ScanReport, report_format: str) -> str:
    for renderer in renderers():
        if renderer.format_id == report_format:
            return renderer.render(report)
    raise UsageError(f"unknown format: {report_format}")


def _meets_threshold(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    ceiling = _SEVERITY_ORDER.index(fail_on)
    return any(_SEVERITY_ORDER.index(finding.severity.value) <= ceiling for finding in findings)


def _nested_unreadable(limitations: list[str]) -> bool:
    return any(item.startswith(_NESTED_PREFIXES) for item in limitations)


def _joined(values: tuple[object, ...] | list[object]) -> str:
    cells: list[str] = []
    for item in values:
        value = getattr(item, "value", item)
        cells.append(str(value))
    return ",".join(cells)


def _probe_cell(available: bool, failed: bool, reason: str | None) -> str:
    if available:
        return "available"
    kind = "failed" if failed else "missing"
    return f"{kind}: {reason}"


def _url_host(raw: str) -> str:
    if "\\" in raw:
        raise UsageError(_URL_USERINFO)
    marker = "://"
    start = raw.find(marker)
    if start != -1:
        rest = raw[start + len(marker) :]
        slash = rest.find("/")
        authority = rest if slash == -1 else rest[:slash]
        if "@" in authority:
            raise UsageError(_URL_USERINFO)
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"}:
        raise UsageError(_URL_SCHEME)
    hostname = parts.hostname
    if hostname is None or hostname == "" or hostname.endswith("."):
        raise UsageError(_URL_HOSTNAME)
    return _normalize_host(hostname)


def _normalize_host(hostname: str) -> str:
    try:
        return ipaddress.ip_address(hostname).compressed
    except ValueError:
        try:
            return hostname.encode("idna").decode("ascii").casefold()
        except UnicodeError as exc:
            raise UsageError(_URL_HOSTNAME) from exc
