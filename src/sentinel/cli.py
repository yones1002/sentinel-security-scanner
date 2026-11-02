"""Sentinel command line.

This build registers the version command only. Scan, detect, and report
commands are specified in the architecture and are not implemented here.
"""

from __future__ import annotations

import typer

from sentinel import __version__

app = typer.Typer(
    name="sentinel",
    help=(
        "Defensive scanner for projects you own. "
        "This build implements the version command only. "
        "Scanning is not implemented."
    ),
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
)


@app.callback()
def main() -> None:
    """Defensive scanner for projects you own.

    This build implements the version command only. Scanning is not implemented.
    """
    # A callback forces a command group. Without it, Typer collapses the only
    # command into the program itself and `sentinel version` stops working.


@app.command(name="version")
def version_command() -> None:
    """Print the Sentinel package version."""
    typer.echo(__version__)
