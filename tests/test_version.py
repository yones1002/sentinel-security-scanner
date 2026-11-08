"""Tests for the PR 1 version command."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from typer.main import get_command
from typer.testing import CliRunner

from sentinel import __version__
from sentinel.cli import app

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def test_version_constant_is_three_part_numeric() -> None:
    parts = __version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_only_version_command_is_registered() -> None:
    click_app = get_command(app)
    assert sorted(click_app.commands) == [
        "detect",
        "history",
        "plugins",
        "report",
        "scan",
        "version",
    ]


def test_version_command_prints_package_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout == f"{__version__}\n"


def test_installed_console_script_prints_package_version() -> None:
    script_name = "sentinel.exe" if sys.platform == "win32" else "sentinel"
    script = Path(sys.executable).parent / script_name
    assert script.is_file(), (
        "install this interpreter with 'pip install -e .' so the console script exists"
    )
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    completed = subprocess.run(
        [str(script), "version"],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert completed.stdout == f"{__version__}\n"
    assert completed.stderr == ""


def test_module_entrypoint_prints_package_version() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "sentinel", "version"],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert completed.stdout == f"{__version__}\n"
    assert completed.stderr == ""
