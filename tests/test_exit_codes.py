"""CLI exit codes. Refusals happen before a scan and before any socket."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel.cli import _nested_unreadable, app, parse_scan_url
from sentinel.detect import Detection
from sentinel.errors import AuthorizationError, UsageError
from sentinel.fs import open_confined_directory
from sentinel.models import Component, ComponentKind
from sentinel.sandbox.unavailable import DYNAMIC_UNAVAILABLE

runner = CliRunner()
AUTH = (
    "dynamic scanning requires --authorized; "
    "refusing before any network or container operation"
)


def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network operation")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "socket", refuse)


def _block_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("run_scan")

    monkeypatch.setattr("sentinel.cli.run_scan", refuse)


def test_dynamic_without_authorization_exits_4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    result = runner.invoke(app, ["scan", "--dynamic", str(tmp_path)])
    assert result.exit_code == 4
    assert AUTH in result.stderr


def test_dynamic_with_authorization_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    result = runner.invoke(app, ["scan", "--dynamic", "--authorized", str(tmp_path)])
    assert result.exit_code == 1
    assert DYNAMIC_UNAVAILABLE in result.stderr


def test_authorized_loopback_url_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    result = runner.invoke(app, ["scan", "--url", "http://127.0.0.1", "--authorized"])
    assert result.exit_code == 1
    assert DYNAMIC_UNAVAILABLE in result.stderr
    assert parse_scan_url("http://[::1]/health", {"localhost", "127.0.0.1", "::1"}) == "::1"


def test_malformed_url_exits_1(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    result = runner.invoke(app, ["scan", "--url", r"http://127.0.0.1@evil.example/"])
    assert result.exit_code == 1
    assert "URL must not contain a backslash or userinfo" in result.stderr
    with pytest.raises(UsageError, match="URL scheme must be http or https"):
        parse_scan_url("ftp://127.0.0.1", {"127.0.0.1"})


def test_host_outside_the_allowlist_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    result = runner.invoke(app, ["scan", "--url", "http://evil.example", "--authorized"])
    assert result.exit_code == 4
    assert "host evil.example is not on the allowlist" in result.stderr
    with pytest.raises(AuthorizationError, match="not on the allowlist"):
        parse_scan_url("http://evil.example", {"localhost", "127.0.0.1", "::1"})


def test_duplicate_component_id_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    component = Component(
        component_id=".",
        root=target,
        languages=(),
        frameworks=(),
        evidence=(),
        kind=ComponentKind.REPOSITORY,
    )

    def duplicate(_path: Path, _limits: object = None) -> Detection:
        return Detection((component, component), (), False)

    monkeypatch.setattr("sentinel.engine.detect", duplicate)
    result = runner.invoke(app, ["scan", str(target)])
    assert result.exit_code == 2
    assert "duplicate component_id ." in result.stderr


def test_threshold_and_fail_on_none(tmp_path: Path) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    canary = "CANARY-CLI-SHOULD-NOT-APPEAR"
    (target / ".env").write_text(canary + "\n", encoding="utf-8")
    high = runner.invoke(app, ["scan", "--fail-on", "high", str(target)])
    assert high.exit_code == 3
    assert "Scan:" in high.stdout
    assert canary not in high.stdout
    none = runner.invoke(app, ["scan", "--fail-on", "none", str(target)])
    assert none.exit_code == 0
    assert "sentinel.surface.env-file" in none.stdout
    critical = runner.invoke(app, ["scan", "--fail-on", "critical", str(target)])
    assert critical.exit_code == 0


def test_static_scan_writes_markdown_and_json(tmp_path: Path) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    (target / "go.mod").write_text("module example.com/tree\n\ngo 1.22\n", encoding="utf-8")
    output = tmp_path / "report.md"
    result = runner.invoke(app, ["scan", "--output", str(output), str(target)])
    assert result.exit_code == 0
    assert result.stdout == ""
    text = output.read_text(encoding="utf-8")
    assert text.startswith("# Sentinel scan\n")
    assert "\nScan: " in text
    rendered = runner.invoke(app, ["scan", "--format", "json", str(target)])
    assert rendered.exit_code == 0
    assert rendered.stdout.startswith("{\n")
    assert '"scan_id"' in rendered.stdout


def test_html_history_and_report_exit_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _block_scan(monkeypatch)
    html = runner.invoke(app, ["scan", "--format", "html", str(tmp_path)])
    assert html.exit_code == 1
    assert "html format is not in this build (milestone 3)" in html.stderr
    history = runner.invoke(app, ["scan", "--history", str(tmp_path)])
    assert history.exit_code == 1
    assert "history store is not in this build (milestone 2)" in history.stderr
    report = runner.invoke(app, ["report", "--scan-id", "00000000-0000-4000-8000-000000000001"])
    assert report.exit_code == 1
    assert "report is not in this build (milestone 2)" in report.stderr
    listed = runner.invoke(app, ["history", "list"])
    assert listed.exit_code == 1
    assert "history maintenance is not in this build (milestone 6)" in listed.stderr
    unknown = runner.invoke(app, ["scan", "--format", "xml", str(tmp_path)])
    assert unknown.exit_code == 1
    assert "unknown format: xml" in unknown.stderr


def test_html_does_not_override_a_missing_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    result = runner.invoke(app, ["scan", "--dynamic", "--format", "html", str(tmp_path)])
    assert result.exit_code == 4
    assert AUTH in result.stderr
    assert "html format" not in result.stderr


def test_url_without_authorization_exits_4(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    loopback = runner.invoke(app, ["scan", "--url", "http://127.0.0.1"])
    assert loopback.exit_code == 4
    assert AUTH in loopback.stderr
    assert "not on the allowlist" not in loopback.stderr
    outside = runner.invoke(app, ["scan", "--url", "http://example.com"])
    assert outside.exit_code == 4
    assert "host example.com is not on the allowlist" in outside.stderr
    assert AUTH not in outside.stderr


def test_allow_host_still_requires_authorization(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    refused = runner.invoke(
        app,
        ["scan", "--url", "http://example.com", "--allow-host", "Example.COM"],
    )
    assert refused.exit_code == 4
    assert AUTH in refused.stderr
    allowed = runner.invoke(
        app,
        [
            "scan",
            "--url",
            "http://example.com",
            "--allow-host",
            "Example.COM",
            "--authorized",
        ],
    )
    assert allowed.exit_code == 1
    assert DYNAMIC_UNAVAILABLE in allowed.stderr
    suffix = runner.invoke(
        app,
        [
            "scan",
            "--url",
            "http://evil.example.com",
            "--allow-host",
            "example.com",
            "--authorized",
        ],
    )
    assert suffix.exit_code == 4
    assert "host evil.example.com is not on the allowlist" in suffix.stderr


def test_all_mode_follows_the_dynamic_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    refused = runner.invoke(app, ["scan", "--all", str(tmp_path)])
    assert refused.exit_code == 4
    assert AUTH in refused.stderr
    blocked = runner.invoke(app, ["scan", "--all", "--authorized", str(tmp_path)])
    assert blocked.exit_code == 1
    assert DYNAMIC_UNAVAILABLE in blocked.stderr
    assert "docker" not in sys.modules


def test_malformed_urls_exit_1_before_authorization(monkeypatch: pytest.MonkeyPatch) -> None:
    _block_network(monkeypatch)
    _block_scan(monkeypatch)
    userinfo = runner.invoke(
        app,
        ["scan", "--url", "http://127.0.0.1@evil.example/", "--authorized"],
    )
    assert userinfo.exit_code == 1
    assert "URL must not contain a backslash or userinfo" in userinfo.stderr
    file_url = runner.invoke(app, ["scan", "--url", "file:///tmp/tree"])
    assert file_url.exit_code == 1
    assert "URL scheme must be http or https" in file_url.stderr
    slash = runner.invoke(app, ["scan", "--url", r"http://127.0.0.1\evil"])
    assert slash.exit_code == 1
    assert "URL must not contain a backslash or userinfo" in slash.stderr
    dotted = runner.invoke(app, ["scan", "--url", "http://localhost./"])
    assert dotted.exit_code == 1
    assert "URL hostname is missing or has a trailing dot" in dotted.stderr


def test_parse_scan_url_normalizes_without_a_socket() -> None:
    allowed = {"localhost", "127.0.0.1", "::1"}
    assert parse_scan_url("http://LOCALHOST/health", allowed) == "localhost"
    assert parse_scan_url("http://[0:0:0:0:0:0:0:1]/", allowed) == "::1"
    punycode = "exämple.com".encode("idna").decode("ascii")
    assert parse_scan_url("http://exämple.com/a", {punycode}) == punycode
    with pytest.raises(AuthorizationError, match="host 127.0.0.2 is not on the allowlist"):
        parse_scan_url("http://127.0.0.2", allowed)
    with pytest.raises(UsageError, match="URL hostname is missing or has a trailing dot"):
        parse_scan_url("http://", allowed)


def test_missing_path_and_bad_arguments_exit_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _block_scan(monkeypatch)
    absent = runner.invoke(app, ["scan"])
    assert absent.exit_code == 1
    assert "a path or --url is required" in absent.stderr
    missing = runner.invoke(app, ["scan", "--dynamic", str(tmp_path / "missing")])
    assert missing.exit_code == 1
    assert "path does not exist or is not a directory" in missing.stderr
    both = runner.invoke(app, ["scan", "--static", "--dynamic", str(tmp_path)])
    assert both.exit_code == 1
    assert "choose one of --static, --dynamic, or --all" in both.stderr
    mixed = runner.invoke(app, ["scan", str(tmp_path), "--url", "http://127.0.0.1"])
    assert mixed.exit_code == 1
    assert "pass a path or --url, not both" in mixed.stderr
    static_url = runner.invoke(
        app,
        ["scan", "--static", "--url", "http://127.0.0.1", "--authorized"],
    )
    assert static_url.exit_code == 1
    assert "URL mode cannot be combined with --static" in static_url.stderr
    unknown = runner.invoke(app, ["scan", "--fail-on", "weird", str(tmp_path)])
    assert unknown.exit_code == 1
    assert "unknown fail_on value: weird" in unknown.stderr
    for flag in (
        "--confirm-ambiguous-reads",
        "--strict-tools",
        "--semgrep-config",
        "--compare",
        "--start-cmd",
    ):
        rejected = runner.invoke(app, ["scan", flag, str(tmp_path)])
        assert rejected.exit_code == 1, flag


def test_unlistable_root_exits_2_without_a_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / ".env").write_text("CANARY-CLI-SHOULD-NOT-APPEAR\n", encoding="utf-8")
    monkeypatch.setattr("sentinel.fs.confined_directory_flags", lambda: None)
    result = runner.invoke(app, ["scan", "--fail-on", "high", str(root)])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "target root cannot be listed" in result.stderr


def test_nested_unreadable_directory_exits_2_before_the_threshold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    blocked = root / "blocked"
    blocked.mkdir(parents=True)
    canary = "CANARY-CLI-SHOULD-NOT-APPEAR"
    (root / ".env").write_text(canary + "\n", encoding="utf-8")

    def refuse_blocked(
        target: Path, relative: str, expected: tuple[int, int]
    ) -> tuple[int | None, str]:
        if relative == "blocked":
            return None, "permission"
        return open_confined_directory(target, relative, expected)

    monkeypatch.setattr("sentinel.detect.open_confined_directory", refuse_blocked)
    monkeypatch.setattr("sentinel.scanners.surface.open_confined_directory", refuse_blocked)
    result = runner.invoke(app, ["scan", "--fail-on", "high", str(root)])
    assert result.exit_code == 2
    assert "Scan:" in result.stdout
    assert "permission denied: blocked" in result.stdout
    assert canary not in result.stdout


def test_medium_finding_does_not_trip_fail_on_high(tmp_path: Path) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    (target / "wp-config.php").write_text("<?php\n", encoding="utf-8")
    high = runner.invoke(app, ["scan", "--fail-on", "high", str(target)])
    assert high.exit_code == 0
    assert "sentinel.surface.wp-config-in-tree" in high.stdout
    medium = runner.invoke(app, ["scan", "--fail-on", "medium", str(target)])
    assert medium.exit_code == 3
    info = runner.invoke(app, ["scan", "--fail-on", "informational", str(target)])
    assert info.exit_code == 3


def test_threshold_still_writes_the_output_file(tmp_path: Path) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    (target / ".env").write_text("CANARY-CLI-SHOULD-NOT-APPEAR\n", encoding="utf-8")
    output = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["scan", "--fail-on", "high", "--output", str(output), str(target)],
    )
    assert result.exit_code == 3
    assert result.stdout == ""
    text = output.read_text(encoding="utf-8")
    assert "\nScan: " in text
    assert "CANARY-CLI-SHOULD-NOT-APPEAR" not in text


def test_in_repo_config_cannot_widen_the_scan(tmp_path: Path) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    (target / "sentinel.toml").write_text(
        'authorized = true\nallow_hosts = ["evil.example"]\n\n'
        '[[components]]\npath = "."\nframeworks = ["laravel"]\n',
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["scan", "--config", str(target / "sentinel.toml"), str(target)],
    )
    assert result.exit_code == 0
    assert "in-repo sentinel.toml attempted to set authorized, allow_hosts, components" in (
        result.stdout
    )
    assert "laravel" not in result.stdout


def test_history_prune_and_cap_limitations() -> None:
    pruned = runner.invoke(app, ["history", "prune"])
    assert pruned.exit_code == 1
    assert "history maintenance is not in this build (milestone 6)" in pruned.stderr
    aged = runner.invoke(app, ["history", "prune", "--older-than", "30"])
    assert aged.exit_code == 1
    assert "history maintenance is not in this build (milestone 6)" in aged.stderr
    assert not _nested_unreadable(
        ["detection stopped: file cap 2 reached; results are incomplete"]
    )
    assert not _nested_unreadable(["skipped symlink outside target: leak"])
    assert not _nested_unreadable(["refused directory symlink: sub"])
    assert _nested_unreadable(["unreadable directory: blocked"])
    assert _nested_unreadable(["permission denied: blocked"])
