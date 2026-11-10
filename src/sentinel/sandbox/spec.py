"""Pure container spec and the leftover-reap predicate.

``gateway_mode_ipv4`` and ``gateway_mode_ipv6`` are ``isolated``. Engine
28.0.0 accepts that mode only when the network is also internal, and
docker-py ``networks.create`` can carry it as a driver option.
``MINIMUM_ENGINE_VERSION`` records that floor. This module does not
contact a daemon and does not import Docker.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from sentinel.errors import UsageError
from sentinel.protocols import ScanContext
from sentinel.sandbox.policy import (
    TIMEOUT_S_CEILING,
    checked_root,
    resolve_mem_limit,
    resolve_nano_cpus,
    resolve_pids_limit,
    resolve_timeout_s,
    resolve_tmpfs_size,
    sandbox_env,
    tmpfs_options,
)

# Engine 28.0.0 is the first release that accepts gateway mode "isolated",
# and only together with an internal network.
MINIMUM_ENGINE_VERSION = "28.0.0"
GATEWAY_MODE: Literal["isolated"] = "isolated"

IMAGE_FAMILIES = {
    "python": "python:3.12-slim",
    "php": "php:8.3-cli",
    "node": "node:22",
}

_RUN_USER = "65534:65534"
_REAP_GRACE_S = 60


@dataclass(frozen=True)
class StartPlan:
    """Exec-form start command. Nothing here runs it."""

    argv: tuple[str, ...]
    image_key: str
    tmpfs_exec: bool


@dataclass(frozen=True)
class WorkspaceMount:
    """The one project mount. It is read-only at ``/workspace``."""

    source: str
    target: Literal["/workspace"] = "/workspace"
    read_only: Literal[True] = True


@dataclass(frozen=True)
class ContainerSpec:
    """One sandbox description. A runner is a later milestone."""

    command: tuple[str, ...]
    image: str
    network_name: str
    mounts: tuple[WorkspaceMount, ...]
    env: tuple[tuple[str, str], ...]
    labels: tuple[tuple[str, str], ...]
    mem_limit: str
    memswap_limit: str
    nano_cpus: int
    pids_limit: int
    timeout_s: int
    tmpfs: str
    working_dir: Literal["/workspace"] = "/workspace"
    network_internal: Literal[True] = True
    extra_hosts: tuple[str, ...] = ()
    publish_host: Literal["127.0.0.1"] = "127.0.0.1"
    gateway_mode_ipv4: Literal["isolated"] = GATEWAY_MODE
    gateway_mode_ipv6: Literal["isolated"] = GATEWAY_MODE
    user: str = _RUN_USER
    read_only: Literal[True] = True
    cap_drop: tuple[str, ...] = ("ALL",)
    cap_add: tuple[str, ...] = ()
    security_opt: tuple[str, ...] = ("no-new-privileges:true",)
    privileged: Literal[False] = False


def build_spec(
    ctx: ScanContext,
    plan: StartPlan,
    *,
    root: Path,
    env: Mapping[str, str] | None = None,
    allow_secret_env: bool = False,
    mem_limit: str | None = None,
    nano_cpus: int | None = None,
    pids_limit: int | None = None,
    timeout_s: int | None = None,
    tmpfs_size: str | None = None,
    extra_hosts: tuple[str, ...] = (),
    network_internal: bool = True,
    publish_host: str = "127.0.0.1",
) -> ContainerSpec:
    """Build one spec or raise ``UsageError``.

    ``root`` is the component root. It may differ from ``ctx.target``.
    Resource values above the ceiling are refused and are not clamped.
    """

    if plan.tmpfs_exec:
        raise UsageError("tmpfs_exec is not allowed")
    command = _command(plan.argv)
    try:
        image = IMAGE_FAMILIES[plan.image_key]
    except KeyError as exc:
        raise UsageError(f"unknown image_key: {plan.image_key}") from exc
    if extra_hosts:
        raise UsageError("extra_hosts must stay empty")
    if network_internal is not True:
        raise UsageError("network_internal must stay true")
    if publish_host != "127.0.0.1":
        raise UsageError("publish_host must stay 127.0.0.1")
    source = checked_root(root)
    memory = resolve_mem_limit(mem_limit)
    size = resolve_tmpfs_size(tmpfs_size)
    return ContainerSpec(
        command=command,
        image=image,
        network_name=f"sentinel-{ctx.scan_id}",
        mounts=(WorkspaceMount(source=source.as_posix()),),
        env=sandbox_env(env, allow_secret_env=allow_secret_env),
        labels=(
            ("org.sentinel.managed", "true"),
            ("org.sentinel.scan_id", ctx.scan_id),
            ("org.sentinel.pid", str(os.getpid())),
        ),
        mem_limit=memory,
        memswap_limit=memory,
        nano_cpus=resolve_nano_cpus(nano_cpus),
        pids_limit=resolve_pids_limit(pids_limit),
        timeout_s=resolve_timeout_s(timeout_s),
        tmpfs=tmpfs_options(size),
    )


def pid_is_running(pid: int) -> bool:
    """Return whether ``pid`` exists. ``EPERM`` counts as running.

    Signal 0 is an existence check. A non-positive pid is treated as
    running so this function does not signal a process group.
    """

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OverflowError:
        return True
    except OSError as exc:
        return exc.errno != errno.ESRCH
    return True


def should_reap(labels: dict[str, str], created_at: datetime, *, now: datetime) -> bool:
    """Return true only for a dead Sentinel leftover past the grace window.

    The age ceiling is the scan timeout ceiling plus 60 seconds, not the
    scan's own timeout. The same predicate applies to container labels and
    network labels. A live pid, including this process, is not eligible.
    """

    if labels.get("org.sentinel.managed") != "true":
        return False
    pid_text = labels.get("org.sentinel.pid")
    if pid_text is None or not pid_text.isdigit():
        return False
    if pid_is_running(int(pid_text)):
        return False
    return (now - created_at).total_seconds() > TIMEOUT_S_CEILING + _REAP_GRACE_S


def _command(argv: tuple[str, ...]) -> tuple[str, ...]:
    if not argv:
        raise UsageError("command is empty")
    copied: list[str] = []
    for item in argv:
        if not isinstance(item, str) or "\0" in item:
            raise UsageError("command element contains NUL")
        copied.append(item)
    return tuple(copied)
