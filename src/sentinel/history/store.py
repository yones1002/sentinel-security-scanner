"""SQLite history store.

Schema migration number 1. The report document schema stored on each scan is
``1.0``. Migrations are forward-only: write ``history.db.next`` in the same
directory, flush it, then ``os.replace`` it over ``history.db``. A leftover
``.next`` file is deleted on the next open and is not applied.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from sentinel.config import ScanConfig
from sentinel.errors import ScanFailure, UsageError
from sentinel.models import (
    DynamicRequests,
    ExecutedScanner,
    Finding,
    ReportComponent,
    ScannerSection,
    ScanReport,
    Severity,
    SkippedScanner,
    Totals,
)
from sentinel.redact import redact_snippet

CURRENT_VERSION = 1
REPORT_SCHEMA_VERSION = "1.0"
# Same sentence as the engine. This module does not import the engine.
_BANDIT_DISABLED_REASON = "bandit disabled because semgrep ran"

_SCHEMA = """
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE scans (
  scan_id TEXT PRIMARY KEY,
  schema_version TEXT NOT NULL,
  target TEXT NOT NULL,
  mode TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  duration_ms INTEGER,
  sentinel_version TEXT NOT NULL,
  tool_versions_json TEXT NOT NULL,
  components_json TEXT NOT NULL,
  scanners_executed_json TEXT NOT NULL,
  scanners_skipped_json TEXT NOT NULL,
  limitations_json TEXT NOT NULL,
  config_json TEXT NOT NULL
);

CREATE TABLE findings (
  scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  severity TEXT NOT NULL,
  kind TEXT NOT NULL,
  finding_json TEXT NOT NULL,
  PRIMARY KEY (scan_id, fingerprint)
);

CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_scan_severity ON findings(scan_id, severity);
"""

_SCAN_COLUMNS = (
    "scan_id",
    "schema_version",
    "target",
    "mode",
    "started_at",
    "finished_at",
    "duration_ms",
    "sentinel_version",
    "tool_versions_json",
    "components_json",
    "scanners_executed_json",
    "scanners_skipped_json",
    "limitations_json",
    "config_json",
)
_FINDING_COLUMNS = (
    "scan_id",
    "fingerprint",
    "severity",
    "kind",
    "finding_json",
)
_TABLE_COLUMNS = {
    "schema_migrations": ("version", "applied_at"),
    "scans": _SCAN_COLUMNS,
    "findings": _FINDING_COLUMNS,
}
_INDEXES = ("idx_findings_fingerprint", "idx_findings_scan_severity")
_CONFIG_KEYS = (
    "confirm_ambiguous_reads",
    "component_overrides",
    "detect",
    "fail_on",
    "history",
    "ignores",
    "semgrep_config",
    "strict_tools",
)


def default_history_path() -> Path:
    """Return ``$XDG_DATA_HOME/sentinel/history.db`` or the home fallback.

    An empty or whitespace ``XDG_DATA_HOME`` is treated as unset. This does
    not create the directory.
    """

    raw = os.environ.get("XDG_DATA_HOME")
    if raw is None or raw.strip() == "":
        base = Path.home() / ".local" / "share"
    else:
        base = Path(raw)
    return base / "sentinel" / "history.db"


def open_history(path: Path | None = None, *, create: bool = True) -> HistoryStore:
    """Open the history database, migrating it forward when needed.

    ``create=False`` does not create a missing file. Callers that only look
    up a scan use that so a typo does not leave an empty database behind.
    """

    location = default_history_path() if path is None else path
    return HistoryStore(location, create=create)


class HistoryStore:
    """One SQLite file. Each method opens its own connection."""

    def __init__(self, path: Path, *, create: bool = True) -> None:
        self.path = path
        self._create = create
        self._prepare()

    @property
    def next_path(self) -> Path:
        return self.path.with_name(self.path.name + ".next")

    def connect(self) -> sqlite3.Connection:
        """Open the database with foreign keys on and the rollback journal.

        ``foreign_keys`` is per connection. ``journal_mode`` is stored in the
        file and is forced off WAL on every connection this store opens.
        """

        if not self.path.exists():
            raise ScanFailure("history database cannot be read")
        return _connect(self.path)

    def save(self, report: ScanReport, config: ScanConfig) -> None:
        """Persist one finished scan. A duplicate ``scan_id`` is refused."""

        if not isinstance(report, ScanReport) or not isinstance(config, ScanConfig):
            raise ScanFailure("history database could not be written")
        conn = self.connect()
        try:
            try:
                _insert_scan(conn, report, config)
                conn.commit()
            except ScanFailure:
                conn.rollback()
                raise
            except sqlite3.Error as exc:
                conn.rollback()
                raise ScanFailure("history database could not be written") from exc
        finally:
            conn.close()
        _fsync_file(self.path)

    def load(self, scan_id: str) -> ScanReport:
        """Return one stored scan. ``finding_json`` is re-validated."""

        if not self.path.exists():
            raise UsageError(f"unknown scan_id: {scan_id}")
        conn = self.connect()
        try:
            try:
                row = conn.execute(
                    "SELECT * FROM scans WHERE scan_id = ?",
                    (scan_id,),
                ).fetchone()
                if row is None:
                    raise UsageError(f"unknown scan_id: {scan_id}")
                findings = conn.execute(
                    """
                    SELECT finding_json FROM findings
                    WHERE scan_id = ?
                    ORDER BY rowid
                    """,
                    (scan_id,),
                ).fetchall()
            except UsageError:
                raise
            except sqlite3.Error as exc:
                raise ScanFailure("history database cannot be read") from exc
        finally:
            conn.close()
        return _report_from_row(row, findings)

    def _prepare(self) -> None:
        if self.path.exists() or self._create:
            _ensure_directory(self.path.parent)
        _delete_file(self.next_path)
        if not self.path.exists():
            if not self._create:
                return
            self._replace_with_next(None)
            _chmod_file(self.path)
            return
        source = _open_readonly(self.path)
        try:
            version = _migration_version(source)
            if version > CURRENT_VERSION:
                raise ScanFailure(
                    f"history database migration version {version} "
                    "is newer than this build"
                )
            if version < CURRENT_VERSION:
                self._replace_with_next(source)
            else:
                _require_current_schema(source)
        finally:
            source.close()
        _chmod_file(self.path)

    def _replace_with_next(self, source: sqlite3.Connection | None) -> None:
        _delete_file(self.next_path)
        _create_private(self.next_path)
        dest = _connect(self.next_path)
        try:
            try:
                dest.executescript(_SCHEMA)
                if source is not None:
                    _copy_rows(source, dest)
                dest.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (CURRENT_VERSION, datetime.now(UTC).isoformat()),
                )
                dest.commit()
            except sqlite3.Error as exc:
                raise ScanFailure("history database could not be written") from exc
        finally:
            dest.close()
        _fsync_file(self.next_path)
        try:
            os.replace(self.next_path, self.path)
        except OSError as exc:
            raise ScanFailure("history database could not be replaced") from exc
        _fsync_dir(self.path.parent)


def config_document(config: ScanConfig) -> dict[str, object]:
    """Effective config after redaction.

    Environment values and authorization header values are not fields on
    ``ScanConfig`` and are not read here. Ignore reasons are masked. Paths
    and account-free override rows are kept.
    """

    document: dict[str, object] = {
        "detect": {
            "max_directories": config.detect.max_directories,
            "max_files": config.detect.max_files,
        },
        "strict_tools": config.strict_tools,
        "fail_on": config.fail_on,
        "history": config.history,
        "semgrep_config": None
        if config.semgrep_config is None
        else str(config.semgrep_config),
        "component_overrides": [
            {
                "frameworks": [item.value for item in row.frameworks],
                "path": row.path,
                "suppress": row.suppress,
            }
            for row in config.component_overrides
        ],
        "ignores": [
            {
                "fingerprint": row.fingerprint,
                "reason": redact_snippet(row.reason, limit=500) or "",
            }
            for row in config.ignores
        ],
        "confirm_ambiguous_reads": config.confirm_ambiguous_reads,
    }
    if set(document) != set(_CONFIG_KEYS):
        raise ScanFailure("history database could not be written")
    return document


def _connect(path: Path) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(path)
    except sqlite3.Error as exc:
        raise ScanFailure("history database cannot be read") from exc
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        journal = conn.execute("PRAGMA journal_mode=DELETE").fetchone()
        foreign_keys = conn.execute("PRAGMA foreign_keys").fetchone()
    except sqlite3.Error as exc:
        conn.close()
        raise ScanFailure("history database cannot be read") from exc
    journal_mode = "" if journal is None else str(journal[0]).lower()
    foreign_key_flag = 0 if foreign_keys is None else int(foreign_keys[0])
    if journal_mode != "delete" or foreign_key_flag != 1:
        conn.close()
        raise ScanFailure("history database journal mode is not the rollback journal")
    return conn


def _open_readonly(path: Path) -> sqlite3.Connection:
    uri = path.resolve().as_uri() + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise ScanFailure("history database cannot be read") from exc
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_directory(directory: Path) -> None:
    """Create the sentinel directory and set mode ``0700`` on that directory only."""

    try:
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if os.name == "posix":
            os.chmod(directory, 0o700)
    except OSError as exc:
        raise ScanFailure("history database could not be written") from exc


def _chmod_file(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        raise ScanFailure("history database could not be written") from exc


def _create_private(path: Path) -> None:
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    except OSError as exc:
        raise ScanFailure("history database could not be written") from exc
    os.close(fd)


def _delete_file(path: Path) -> None:
    if not path.exists():
        return
    try:
        path.unlink()
    except OSError as exc:
        raise ScanFailure("history database could not be written") from exc


def _fsync_file(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        raise ScanFailure("history database could not be written") from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise ScanFailure("history database could not be written") from exc
    finally:
        os.close(fd)


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError as exc:
        raise ScanFailure("history database could not be written") from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise ScanFailure("history database could not be written") from exc
    finally:
        os.close(fd)


def _migration_version(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return 0
        raise ScanFailure("history database cannot be read") from exc
    except sqlite3.DatabaseError as exc:
        raise ScanFailure("history database cannot be read") from exc
    if row is None or row[0] is None:
        return 0
    try:
        return int(row[0])
    except (TypeError, ValueError) as exc:
        raise ScanFailure("history database cannot be read") from exc


def _require_current_schema(conn: sqlite3.Connection) -> None:
    for table, columns in _TABLE_COLUMNS.items():
        if _column_names(conn, table) != list(columns):
            raise ScanFailure("history database schema does not match this build")
    for index in _INDEXES:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?",
            (index,),
        ).fetchone()
        if row is None:
            raise ScanFailure("history database schema does not match this build")


def _column_names(conn: sqlite3.Connection, table: str) -> list[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.Error as exc:
        raise ScanFailure("history database cannot be read") from exc
    return [str(row[1]) for row in rows]


def _copy_rows(source: sqlite3.Connection, dest: sqlite3.Connection) -> None:
    _copy_table(source, dest, "scans", _SCAN_COLUMNS)
    _copy_table(source, dest, "findings", _FINDING_COLUMNS)


def _copy_table(
    source: sqlite3.Connection,
    dest: sqlite3.Connection,
    table: str,
    columns: tuple[str, ...],
) -> None:
    present = _column_names(source, table)
    if not present:
        return
    selected = [name for name in columns if name in present]
    if not selected:
        return
    quoted = ", ".join(selected)
    try:
        rows = source.execute(f"SELECT {quoted} FROM {table}").fetchall()
    except sqlite3.Error as exc:
        raise ScanFailure("history database cannot be read") from exc
    placeholders = ", ".join("?" for _ in selected)
    dest.executemany(
        f"INSERT INTO {table} ({quoted}) VALUES ({placeholders})",
        [tuple(row[name] for name in selected) for row in rows],
    )


def _insert_scan(conn: sqlite3.Connection, report: ScanReport, config: ScanConfig) -> None:
    existing = conn.execute(
        "SELECT 1 FROM scans WHERE scan_id = ?",
        (report.scan_id,),
    ).fetchone()
    if existing is not None:
        raise ScanFailure(f"scan_id already stored: {report.scan_id}")
    conn.execute(
        """
        INSERT INTO scans (
            scan_id, schema_version, target, mode, started_at, finished_at,
            duration_ms, sentinel_version, tool_versions_json, components_json,
            scanners_executed_json, scanners_skipped_json, limitations_json,
            config_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report.scan_id,
            report.schema_version,
            report.target,
            report.mode,
            report.started_at.isoformat(),
            report.finished_at.isoformat(),
            report.duration_ms,
            report.sentinel_version,
            _dump(_tool_versions(report)),
            _dump_models(report.components),
            _dump_models(report.scanners.executed),
            _dump_models(report.scanners.skipped),
            _dump(list(report.limitations)),
            _dump(config_document(config)),
        ),
    )
    conn.executemany(
        """
        INSERT INTO findings (
            scan_id, fingerprint, severity, kind, finding_json
        ) VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                report.scan_id,
                finding.fingerprint,
                finding.severity.value,
                finding.kind.value,
                finding.model_dump_json(),
            )
            for finding in report.findings
        ],
    )


def _tool_versions(report: ScanReport) -> list[dict[str, str | None]]:
    return [
        {"name": row.name, "tool_version": row.tool_version}
        for row in report.scanners.executed
    ]


def _dump(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _dump_models(items: list[BaseModel]) -> str:
    return _dump([item.model_dump(mode="json") for item in items])


def _report_from_row(row: sqlite3.Row, finding_rows: list[sqlite3.Row]) -> ScanReport:
    findings = _findings(finding_rows)
    try:
        components = _models(str(row["components_json"]), ReportComponent)
        executed = _models(str(row["scanners_executed_json"]), ExecutedScanner)
        skipped = _models(str(row["scanners_skipped_json"]), SkippedScanner)
        limitations = _strings(str(row["limitations_json"]))
        config = _object(str(row["config_json"]))
        finished = row["finished_at"]
        duration = row["duration_ms"]
        if finished is None or duration is None:
            raise ScanFailure("stored scan failed validation")
        target = str(row["target"])
        mode = str(row["mode"])
        if mode not in {"static", "dynamic", "all"}:
            raise ScanFailure("stored scan failed validation")
        return ScanReport(
            schema_version=row["schema_version"],
            sentinel_version=str(row["sentinel_version"]),
            scan_id=str(row["scan_id"]),
            target=target,
            url=_restored_url(mode, target),
            mode=mode,
            started_at=row["started_at"],
            finished_at=finished,
            duration_ms=duration,
            components=components,
            scanners=ScannerSection(executed=executed, skipped=skipped),
            dynamic_requests=DynamicRequests(),
            totals=_totals(findings),
            strict_failure=_strict_failure(config.get("strict_tools") is True, executed, skipped),
            limitations=limitations,
            findings=findings,
            comparison=None,
        )
    except ValidationError as exc:
        raise ScanFailure("stored scan failed validation") from exc


def _findings(rows: list[sqlite3.Row]) -> list[Finding]:
    findings: list[Finding] = []
    for row in rows:
        try:
            findings.append(Finding.model_validate_json(str(row["finding_json"])))
        except ValidationError as exc:
            raise ScanFailure("stored finding failed validation") from exc
    return findings


def _models[ModelT: BaseModel](payload: str, model: type[ModelT]) -> list[ModelT]:
    raw = _json_list(payload)
    try:
        return [model.model_validate(item) for item in raw]
    except ValidationError as exc:
        raise ScanFailure("stored scan failed validation") from exc


def _strings(payload: str) -> list[str]:
    raw = _json_list(payload)
    texts: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise ScanFailure("stored scan failed validation")
        texts.append(item)
    return texts


def _json_list(payload: str) -> list[object]:
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ScanFailure("stored scan failed validation") from exc
    if not isinstance(raw, list):
        raise ScanFailure("stored scan failed validation")
    return raw


def _object(payload: str) -> dict[str, object]:
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ScanFailure("stored scan failed validation") from exc
    if not isinstance(raw, dict):
        raise ScanFailure("stored scan failed validation")
    return raw


def _totals(findings: list[Finding]) -> Totals:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return Totals(**counts)


def _strict_failure(
    strict_tools: bool,
    executed: list[ExecutedScanner],
    skipped: list[SkippedScanner],
) -> bool:
    """Rebuild the flag. Schema version 1 does not store ``strict_failure``."""

    if not strict_tools:
        return False
    if any(row.status == "failed" for row in executed):
        return True
    return any(skip.failed or skip.reason != _BANDIT_DISABLED_REASON for skip in skipped)


def _restored_url(mode: str, target: str) -> str | None:
    """Path scans have no stored URL. Schema version 1 has no URL column."""

    if mode == "static":
        return None
    if target.startswith(("http://", "https://")):
        return target
    return None
