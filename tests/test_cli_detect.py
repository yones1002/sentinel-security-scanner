"""CLI tables for detect and plugins list."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel import __version__
from sentinel.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _rows(stdout: str) -> list[list[str]]:
    text = stdout.removesuffix("\n")
    if text == "":
        return []
    return [line.split("\t") for line in text.splitlines()]


def test_detect_prints_the_component_columns(tmp_path: Path) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    (target / "go.mod").write_text("module example.com/tree\n\ngo 1.22\n", encoding="utf-8")
    result = runner.invoke(app, ["detect", str(target)])
    assert result.exit_code == 0
    rows = _rows(result.stdout)
    assert rows[0] == ["component_id", "kind", "languages", "frameworks", "evidence"]
    assert ["." , "application", "go", "", "go.mod"] in rows


def test_detect_fixture_matches_the_stack() -> None:
    result = runner.invoke(app, ["detect", str(FIXTURES / "laravel_tiny")])
    assert result.exit_code == 0
    rows = _rows(result.stdout)
    assert rows[0] == ["component_id", "kind", "languages", "frameworks", "evidence"]
    assert [".", "application", "php", "laravel", "composer.json,artisan"] in rows


def test_detect_missing_path_exits_1(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    result = runner.invoke(app, ["detect", str(missing)])
    assert result.exit_code == 1
    assert "path does not exist or is not a directory" in result.stderr


def test_detect_nested_unreadable_directory_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    blocked = root / "blocked"
    blocked.mkdir(parents=True)
    (root / "seen.txt").write_text("ok", encoding="utf-8")
    blocked_id = (blocked.stat().st_dev, blocked.stat().st_ino)
    real = os.scandir

    def fake(path: object) -> object:
        if isinstance(path, int):
            info = os.fstat(path)
            if (info.st_dev, info.st_ino) == blocked_id:
                raise OSError("denied")
            return real(path)
        if Path(str(path)).name == "blocked":
            raise OSError("denied")
        return real(path)

    monkeypatch.setattr(os, "scandir", fake)
    result = runner.invoke(app, ["detect", str(root)])
    assert result.exit_code == 2
    assert "component_id\tkind\t" in result.stdout
    assert "unreadable directory: blocked" not in result.stdout


def test_detect_empty_repository_exits_0(tmp_path: Path) -> None:
    target = tmp_path / "empty"
    target.mkdir()
    result = runner.invoke(app, ["detect", str(target)])
    assert result.exit_code == 0
    assert _rows(result.stdout) == [
        ["component_id", "kind", "languages", "frameworks", "evidence"],
        [".", "repository", "", "", ""],
    ]


def test_detect_unlistable_root_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    monkeypatch.setattr("sentinel.fs.confined_directory_flags", lambda: None)
    result = runner.invoke(app, ["detect", str(root)])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "target root cannot be listed" in result.stderr


def test_plugins_list_prints_the_surface_scanner() -> None:
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0
    rows = _rows(result.stdout)
    assert rows[0] == ["name", "version", "rule_pack_version", "modes", "scope", "probe"]
    assert ["surface", __version__, "surface-1", "static", "root", "available"] in rows


def test_plugins_list_formats_probe_and_blank_rule_pack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentinel.protocols import ProbeResult, ScannerScope

    class Fake:
        name = "fake"
        version = "1.2.3"
        rule_pack_version = None
        modes = frozenset({"dynamic", "static"})
        scope = ScannerScope.ROOT

        def probe(self, _ctx: object) -> ProbeResult:
            return ProbeResult(False, None, "not found on PATH", failed=False)

    monkeypatch.setattr("sentinel.cli.builtin_scanners", lambda: (Fake(),))
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0
    assert _rows(result.stdout)[1] == [
        "fake",
        "1.2.3",
        "",
        "dynamic,static",
        "root",
        "missing: not found on PATH",
    ]
    failed = Fake()

    def failed_probe(_ctx: object) -> ProbeResult:
        return ProbeResult(False, None, "version check failed", failed=True)

    monkeypatch.setattr(failed, "probe", failed_probe)
    monkeypatch.setattr("sentinel.cli.builtin_scanners", lambda: (failed,))
    again = runner.invoke(app, ["plugins", "list"])
    assert again.exit_code == 0
    assert _rows(again.stdout)[1][5] == "failed: version check failed"
