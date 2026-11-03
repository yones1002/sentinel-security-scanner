"""Scan errors and the process exit codes the CLI maps them to.

Scanners do not raise ``UsageError`` for a tool crash, and they do not raise
``AuthorizationError`` at all. A non-zero tool exit that still prints valid
JSON is not one of these errors.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process status defined for the Sentinel CLI."""

    SUCCESS = 0
    USAGE = 1
    SCAN_FAILURE = 2
    THRESHOLD = 3
    AUTHORIZATION = 4


class UsageError(Exception):
    """The operator's mistake: a bad flag, a ceiling, or a malformed config.

    The CLI maps this to exit 1.
    """


class ScannerError(Exception):
    """An adapter bug, or a tool crash after the process had started.

    The engine records a failed skip. The traceback stays in the debug log.
    """


class ScanFailure(Exception):
    """The target cannot be listed, or component ids are duplicated.

    The CLI maps this to exit 2.
    """


class AuthorizationError(Exception):
    """The operator did not attest, or the host is not allowlisted.

    Scanners must not raise this. The CLI maps it to exit 4.
    """
