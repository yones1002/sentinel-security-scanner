"""Container spec policy. No daemon and no Docker import."""

from __future__ import annotations

import ast
import errno
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.config import Authorization, DetectLimits, ScanConfig
from sentinel.errors import UsageError
from sentinel.protocols import ScanContext, ScanMode
from sentinel.sandbox import policy
from sentinel.sandbox.spec import (
    MINIMUM_ENGINE_VERSION,
    StartPlan,
    build_spec,
    pid_is_running,
    should_reap,
)

_ROOT = Path(__file__).resolve().parents[1]
_MODULES = (
    _ROOT / "src" / "sentinel" / "sandbox" / "spec.py",
    _ROOT / "src" / "sentinel" / "sandbox" / "policy.py",
    _ROOT / "src" / "sentinel" / "sandbox" / "allowlist.py",
)
_ARGV = (
    "python",
    "-m",
    "uvicorn",
    "app:application",
    "--host",
    "0.0.0.0",
    "--port",
    "8080",
)
_CREATED = datetime(2026, 11, 9, tzinfo=UTC)


def _ctx(tmp_path: Path, scan_id: str = "scan-1") -> ScanContext:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    target = tmp_path / "repo"
    target.mkdir(exist_ok=True)
    return ScanContext(
        scan_id=scan_id,
        mode=ScanMode.STATIC,
        target=target,
        url=None,
        url_host=None,
        pinned_address=None,
        started_at=_CREATED,
        components=(),
        config=ScanConfig(
            detect=DetectLimits(),
            strict_tools=False,
            fail_on="none",
            history=False,
            semgrep_config=None,
            component_overrides=(),
            ignores=(),
        ),
        authorization=Authorization(attested=False),
        work_dir=work,
    )


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "component"
    root.mkdir()
    return root


def _plan(
    argv: tuple[str, ...] = _ARGV,
    image_key: str = "python",
    tmpfs_exec: bool = False,
) -> StartPlan:
    return StartPlan(argv=argv, image_key=image_key, tmpfs_exec=tmpfs_exec)


def _labels(pid: str, *, managed: str = "true") -> dict[str, str]:
    return {
        "org.sentinel.managed": managed,
        "org.sentinel.scan_id": "scan-1",
        "org.sentinel.pid": pid,
    }


def test_defaults_lock_the_sandbox_shape(tmp_path: Path) -> None:
    project = _project(tmp_path)
    spec = build_spec(_ctx(tmp_path), _plan(), root=project)
    assert spec.command == _ARGV
    assert spec.image == "python:3.12-slim"
    assert spec.user == "65534:65534"
    assert spec.user not in {"0:0", "root"}
    assert spec.privileged is False
    assert spec.cap_drop == ("ALL",)
    assert spec.cap_add == ()
    assert spec.security_opt == ("no-new-privileges:true",)
    assert spec.read_only is True
    assert spec.working_dir == "/workspace"
    assert len(spec.mounts) == 1
    assert spec.mounts[0].source == project.resolve().as_posix()
    assert spec.mounts[0].target == "/workspace"
    assert spec.mounts[0].read_only is True
    assert spec.mem_limit == "512m"
    assert spec.memswap_limit == spec.mem_limit
    assert spec.nano_cpus == 1_000_000_000
    assert spec.pids_limit == 256
    assert spec.timeout_s == 180
    assert spec.tmpfs == "rw,nosuid,nodev,noexec,size=128m"
    assert "noexec" in spec.tmpfs
    assert spec.gateway_mode_ipv4 == "isolated"
    assert spec.gateway_mode_ipv6 == "isolated"
    assert spec.network_internal is True
    assert spec.extra_hosts == ()
    assert spec.publish_host == "127.0.0.1"
    assert spec.network_name == "sentinel-scan-1"
    assert spec.env == (("HOME", "/tmp"), ("PORT", "8080"))
    labels = dict(spec.labels)
    assert labels["org.sentinel.managed"] == "true"
    assert labels["org.sentinel.scan_id"] == "scan-1"
    assert labels["org.sentinel.pid"] == str(os.getpid())


def test_minimum_engine_version_is_recorded() -> None:
    assert MINIMUM_ENGINE_VERSION == "28.0.0"


@pytest.mark.parametrize(
    ("image_key", "image"),
    [
        ("python", "python:3.12-slim"),
        ("php", "php:8.3-cli"),
        ("node", "node:22"),
    ],
)
def test_image_family_has_no_digest(tmp_path: Path, image_key: str, image: str) -> None:
    spec = build_spec(
        _ctx(tmp_path),
        _plan(argv=("python",), image_key=image_key),
        root=_project(tmp_path),
    )
    assert spec.image == image
    assert "@" not in spec.image


def test_exact_ceilings_are_accepted(tmp_path: Path) -> None:
    spec = build_spec(
        _ctx(tmp_path),
        _plan(),
        root=_project(tmp_path),
        mem_limit="2048m",
        nano_cpus=2_000_000_000,
        pids_limit=512,
        timeout_s=600,
        tmpfs_size="512m",
    )
    assert spec.mem_limit == "2048m"
    assert spec.memswap_limit == "2048m"
    assert spec.nano_cpus == 2_000_000_000
    assert spec.pids_limit == 512
    assert spec.timeout_s == 600
    assert spec.tmpfs == "rw,nosuid,nodev,noexec,size=512m"


def test_positive_values_below_the_default_are_accepted(tmp_path: Path) -> None:
    spec = build_spec(
        _ctx(tmp_path),
        _plan(),
        root=_project(tmp_path),
        mem_limit="1m",
        nano_cpus=1,
        pids_limit=1,
        timeout_s=1,
        tmpfs_size="1m",
    )
    assert spec.mem_limit == "1m"
    assert spec.memswap_limit == "1m"
    assert spec.nano_cpus == 1
    assert spec.pids_limit == 1
    assert spec.timeout_s == 1
    assert spec.tmpfs == "rw,nosuid,nodev,noexec,size=1m"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mem_limit": "2049m"},
        {"nano_cpus": 2_000_000_001},
        {"pids_limit": 513},
        {"timeout_s": 601},
        {"tmpfs_size": "513m"},
    ],
)
def test_one_unit_above_a_ceiling_raises(tmp_path: Path, kwargs: dict[str, object]) -> None:
    with pytest.raises(UsageError, match="outside the ceiling"):
        build_spec(_ctx(tmp_path), _plan(), root=_project(tmp_path), **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mem_limit": "0m"},
        {"mem_limit": "01m"},
        {"mem_limit": "1g"},
        {"mem_limit": "512M"},
        {"tmpfs_size": "0m"},
        {"nano_cpus": 0},
        {"nano_cpus": -1},
        {"nano_cpus": True},
        {"pids_limit": False},
        {"timeout_s": 0},
    ],
)
def test_invalid_resource_units_raise(tmp_path: Path, kwargs: dict[str, object]) -> None:
    with pytest.raises(UsageError):
        build_spec(_ctx(tmp_path), _plan(), root=_project(tmp_path), **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "root",
    [
        Path("/"),
        Path("/etc"),
        Path("/usr"),
        Path("/var"),
        Path("/proc"),
        Path("/sys"),
        Path("/root"),
        Path("/home"),
    ],
)
def test_exact_denied_roots_raise(tmp_path: Path, root: Path) -> None:
    with pytest.raises(UsageError, match="refused mount root"):
        build_spec(_ctx(tmp_path), _plan(), root=root)


def test_home_is_refused_and_a_project_inside_it_is_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(policy.Path, "home", lambda: tmp_path)
    with pytest.raises(UsageError, match="refused mount root"):
        build_spec(_ctx(tmp_path), _plan(), root=tmp_path)
    project = tmp_path / "proj"
    project.mkdir()
    spec = build_spec(_ctx(tmp_path), _plan(), root=project)
    assert spec.mounts[0].source == project.resolve().as_posix()


def test_credential_directories_and_docker_sock_are_refused(tmp_path: Path) -> None:
    for name in (".ssh", ".aws", "docker.sock"):
        root = tmp_path / name
        root.mkdir()
        with pytest.raises(UsageError, match="refused mount root"):
            build_spec(_ctx(tmp_path), _plan(), root=root)
    nested = tmp_path / "docker.sock" / "proj"
    nested.mkdir()
    with pytest.raises(UsageError, match="refused mount root"):
        build_spec(_ctx(tmp_path), _plan(), root=nested)


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        ((), "command is empty"),
        (("python", "a\0b"), "command element contains NUL"),
    ],
)
def test_empty_or_nul_command_raises(
    tmp_path: Path,
    argv: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(UsageError, match=message):
        build_spec(_ctx(tmp_path), _plan(argv=argv), root=_project(tmp_path))


def test_tmpfs_exec_and_unknown_image_raise(tmp_path: Path) -> None:
    project = _project(tmp_path)
    with pytest.raises(UsageError, match="tmpfs_exec is not allowed"):
        build_spec(_ctx(tmp_path), _plan(tmpfs_exec=True), root=project)
    with pytest.raises(UsageError, match="unknown image_key"):
        build_spec(_ctx(tmp_path), _plan(image_key="go"), root=project)


def test_network_overrides_are_refused(tmp_path: Path) -> None:
    project = _project(tmp_path)
    ctx = _ctx(tmp_path)
    plan = _plan()
    with pytest.raises(UsageError, match="extra_hosts must stay empty"):
        build_spec(ctx, plan, root=project, extra_hosts=("db:127.0.0.1",))
    with pytest.raises(UsageError, match="network_internal must stay true"):
        build_spec(ctx, plan, root=project, network_internal=False)
    with pytest.raises(UsageError, match="publish_host must stay 127.0.0.1"):
        build_spec(ctx, plan, root=project, publish_host="0.0.0.0")


def test_secret_env_is_refused_unless_explicitly_allowed(tmp_path: Path) -> None:
    project = _project(tmp_path)
    ctx = _ctx(tmp_path)
    plan = _plan()
    refused = (
        {"DATABASE_URL": "postgres://db/app"},
        {"database_url": "local"},
        {"DSN": "postgres://db/app"},
        {"API_URL": "http://example.test"},
        {"SERVICE_URL": "https://example.test/x"},
    )
    for env in refused:
        with pytest.raises(UsageError, match="refused environment key"):
            build_spec(ctx, plan, root=project, env=env)
    spec = build_spec(ctx, plan, root=project, env={"API_URL": "localhost"})
    assert spec.env == (("HOME", "/tmp"), ("PORT", "8080"), ("API_URL", "localhost"))
    allowed = build_spec(
        ctx,
        plan,
        root=project,
        env={"DATABASE_URL": "postgres://db/app"},
        allow_secret_env=True,
    )
    assert allowed.env[-1] == ("DATABASE_URL", "postgres://db/app")


@pytest.mark.parametrize("shape", ["container", "network"])
def test_should_reap_selects_only_a_dead_leftover(
    shape: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del shape
    labels = _labels("4242")
    dead = _CREATED + timedelta(seconds=661)
    boundary = _CREATED + timedelta(seconds=660)

    def running(pid: int) -> bool:
        return True

    def stopped(pid: int) -> bool:
        return False

    monkeypatch.setattr("sentinel.sandbox.spec.pid_is_running", running)
    assert should_reap(labels, _CREATED, now=dead) is False
    assert should_reap(_labels(str(os.getpid())), _CREATED, now=dead) is False
    monkeypatch.setattr("sentinel.sandbox.spec.pid_is_running", stopped)
    assert should_reap(labels, _CREATED, now=boundary) is False
    assert should_reap(labels, _CREATED, now=dead) is True
    assert should_reap({}, _CREATED, now=dead) is False
    assert should_reap(_labels("4242", managed="false"), _CREATED, now=dead) is False
    assert should_reap(_labels("nope"), _CREATED, now=dead) is False
    assert should_reap({"org.sentinel.managed": "true"}, _CREATED, now=dead) is False


def test_pid_is_running_treats_eperm_as_running_and_esrch_as_dead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def kill(pid: int, signal: int) -> None:
        if signal != 0:
            raise AssertionError("signal 0 is the only check")
        if pid == 10:
            raise PermissionError(errno.EPERM, "operation not permitted")
        raise ProcessLookupError(errno.ESRCH, "no such process")

    monkeypatch.setattr("sentinel.sandbox.spec.os.kill", kill)
    assert pid_is_running(10) is True
    assert pid_is_running(11) is False
    assert pid_is_running(0) is True


def test_new_modules_do_not_import_docker() -> None:
    import sentinel.sandbox.allowlist
    import sentinel.sandbox.policy
    import sentinel.sandbox.spec

    assert sentinel.sandbox.allowlist.plan_start.__module__ == "sentinel.sandbox.allowlist"
    assert sentinel.sandbox.policy.checked_root.__module__ == "sentinel.sandbox.policy"
    assert sentinel.sandbox.spec.build_spec.__module__ == "sentinel.sandbox.spec"
    assert "docker" not in sys.modules
    for path in _MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for name in names:
                assert "docker" not in [part for part in name.split(".") if part]
        text = path.read_text(encoding="utf-8")
        assert "internal network still has a bridge gateway" not in text
