"""Surface scanner tests. No Docker, no sockets, and no target execution."""

from __future__ import annotations

import ast
import os
import shutil
import tracemalloc
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel import __version__
from sentinel.config import Authorization, DetectLimits, load_scan_config
from sentinel.detect import _SKIP_DIRS
from sentinel.engine import run_scan
from sentinel.fingerprint import fingerprint
from sentinel.fs import open_inside
from sentinel.models import Component, ComponentKind
from sentinel.protocols import ComponentScanTarget, ScanContext, ScanMode
from sentinel.recommendations import (
    PATTERN_DISCLAIMER,
    fallback_remediation,
    recommendation_for,
)
from sentinel.registry import builtin_scanners, renderers
from sentinel.sandbox.unavailable import UnavailableDynamicRuntime
from sentinel.scanners.surface import (
    SKIP_DIRECTORY_NAMES,
    SurfaceScanner,
    _plan_entries,
    _Walk,
    _walk,
)

CANARY = "CANARY_SHOULD_NOT_APPEAR_IN_REPORT"
ENV = "sentinel.surface.env-file"
KEY = "sentinel.surface.private-key-filename"
VCS = "sentinel.surface.vcs-metadata"
WP = "sentinel.surface.wp-config-in-tree"
SOCK = "sentinel.surface.compose-docker-sock"
PRIV = "sentinel.surface.compose-privileged"
K8S = "sentinel.surface.k8s-host-network"
WW = "sentinel.surface.world-writable"
POSIX_SKIP = "world-writable check skipped: not a POSIX platform"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SURFACE_RULES = (ENV, KEY, VCS, WP, SOCK, PRIV, K8S, WW)


def _write(root: Path, relative: str, text: str = "x\n", mode: int = 0o644) -> Path:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def _scan(root: Path, *, limits: DetectLimits | None = None):
    work = root.parent / f"{root.name}-work"
    work.mkdir(exist_ok=True)
    loaded = load_scan_config(None, target=root, attested=True, detect=limits)
    ctx = ScanContext(
        scan_id=str(uuid.uuid4()),
        mode=ScanMode.STATIC,
        target=root,
        url=None,
        url_host=None,
        pinned_address=None,
        started_at=datetime.now(UTC),
        components=(),
        config=loaded.config,
        authorization=Authorization(attested=True),
        work_dir=work,
    )
    report = run_scan(ctx, builtin_scanners(), dynamic=UnavailableDynamicRuntime(), store=None)
    return ctx, report


def _ids(report) -> list[str]:
    return [item.evidence.rule_id for item in report.findings]


def _by_rule(report, rule: str):
    return [item for item in report.findings if item.evidence.rule_id == rule]


def _assert_clean(report) -> None:
    assert CANARY not in report.model_dump_json()


def test_skip_names_match_the_detector() -> None:
    assert SKIP_DIRECTORY_NAMES == _SKIP_DIRS


def test_registry_is_surface_only() -> None:
    scanners = builtin_scanners()
    assert [item.name for item in scanners] == ["surface"]
    assert renderers() == ()
    scanner = scanners[0]
    assert scanner.version == __version__
    assert scanner.rule_pack_version == "surface-1"
    assert scanner.timeout_s == 60
    assert scanner.scope.value == "root"
    assert scanner.modes == frozenset({"static"})
    assert scanner.supports(
        Component(
            component_id=".",
            root=Path("."),
            languages=(),
            frameworks=(),
            evidence=(),
            kind=ComponentKind.REPOSITORY,
        )
    )
    probe = scanner.probe(ScanContext(
        scan_id=str(uuid.uuid4()),
        mode=ScanMode.STATIC,
        target=None,
        url=None,
        url_host=None,
        pinned_address=None,
        started_at=datetime.now(UTC),
        components=(),
        config=load_scan_config(None, target=None, attested=True).config,
        authorization=Authorization(attested=True),
        work_dir=Path("."),
    ))
    assert probe.available is True
    assert probe.version == __version__
    assert probe.failed is False


def test_recommendation_rows_have_no_sketches() -> None:
    for rule_id in SURFACE_RULES:
        row = recommendation_for(rule_id, "laravel")
        assert row is not None
        assert row.secure_sketch is None
        assert row.sketch_language is None
        assert row.what_is_wrong
        assert row.recommended_fix
    assert recommendation_for("sentinel.semgrep.example", None) is None
    fallback = fallback_remediation("password=hunter2", "apps/api/.env", None, "sentinel.example")
    assert fallback.what_is_wrong == "password=***"
    assert fallback.recommended_fix == "password=***"
    assert fallback.why_dangerous == PATTERN_DISCLAIMER
    assert fallback.secure_sketch is None
    assert fallback.where == "apps/api/.env"
    root = Path(__file__).resolve().parents[1]
    text = (root / "src/sentinel/recommendations.py").read_text(encoding="utf-8")
    text += (root / "src/sentinel/scanners/surface.py").read_text(encoding="utf-8")
    for banned in ("shell=True", "os.system", "pickle.loads"):
        assert banned not in text


def test_env_names_do_not_read_file_bytes(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for name in (".env", ".env.local", ".env.example", ".env.sample", ".envrc"):
        _write(root, name, f"{CANARY}=placeholder\n")
    _report_ctx, report = _scan(root)
    assert sorted(item.location.path for item in _by_rule(report, ENV)) == [".env", ".env.local"]
    for item in _by_rule(report, ENV):
        assert item.location.line is None
        assert item.evidence.snippet is None
        assert item.severity.value == "high"
        assert item.confidence.value == "high"
        assert item.kind.value == "misconfiguration"
    assert report.findings[0].evidence.summary == "filename matched .env"
    _assert_clean(report)


def test_monorepo_env_is_stamped_by_the_engine(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURES / "monorepo_tiny", root)
    _write(root, "apps/api/.env", f"{CANARY}=placeholder\n")
    ctx, report = _scan(root)
    direct = SurfaceScanner().scan(
        ctx,
        ComponentScanTarget(
            component=Component(
                component_id=".",
                root=root,
                languages=(),
                frameworks=(),
                evidence=(),
                kind=ComponentKind.REPOSITORY,
            ),
            exclude_roots=(),
        ),
    )
    assert [item.component_id for item in direct.findings] == ["."]
    assert [item.location.path for item in direct.findings] == ["apps/api/.env"]
    assert direct.findings[0].fingerprint != fingerprint(
        direct.findings[0].model_copy(update={"component_id": "apps/api"})
    )
    found = _by_rule(report, ENV)
    assert len(found) == 1
    item = found[0]
    assert item.component_id == "apps/api"
    assert item.location.path == "apps/api/.env"
    assert item.location.line is None
    assert item.evidence.snippet is None
    assert item.scanner == "surface"
    assert item.scanner_version == __version__
    assert item.evidence.scanner == "surface"
    assert item.evidence.scanner_version == __version__
    assert item.evidence.rule_pack_version == "surface-1"
    assert item.fingerprint_version == "v1"
    assert item.fingerprint == fingerprint(item)
    assert item.remediation.secure_sketch is None
    assert item.remediation.where == "apps/api/.env"
    assert "sentinel.surface.env-file is absent for apps/api/.env." in item.remediation.how_to_verify
    assert item.references == ["https://owasp.org/www-project-secrets-management/"]
    executed = report.scanners.executed
    assert len(executed) == 1
    assert executed[0].name == "surface"
    assert executed[0].version == __version__
    assert executed[0].rule_pack_version == "surface-1"
    assert executed[0].tool_version == __version__
    assert executed[0].status == "executed"
    assert executed[0].finding_count == 1
    _assert_clean(report)


def test_private_key_and_wp_config_names_are_not_read(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("a.pem", "id_rsa", "id_dsa", "id_ed25519", "id_rsa.pub", "wp-config.php"):
        _write(root, name, f"{CANARY}=placeholder\n")
    _ctx, report = _scan(root)
    assert sorted(item.location.path for item in _by_rule(report, KEY)) == [
        "a.pem",
        "id_dsa",
        "id_ed25519",
        "id_rsa",
    ]
    assert [item.location.path for item in _by_rule(report, WP)] == ["wp-config.php"]
    for item in report.findings:
        assert item.evidence.snippet is None
        assert item.location.line is None
    _assert_clean(report)


def test_compose_literals_keep_only_the_matching_line(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, "compose.yml", "privileged:true\n")
    _write(root, "compose.yaml", "privileged: true\n")
    _write(
        root,
        "docker-compose.yml",
        f"{CANARY}=placeholder\n# docker.sock\n",
    )
    _ctx, report = _scan(root)
    assert [item.location.path for item in _by_rule(report, PRIV)] == ["compose.yaml"]
    privileged = _by_rule(report, PRIV)[0]
    assert privileged.location.line == 1
    assert privileged.evidence.snippet == "privileged: true"
    sock = _by_rule(report, SOCK)
    assert [item.location.path for item in sock] == ["docker-compose.yml"]
    assert sock[0].location.line == 2
    assert sock[0].evidence.snippet == "# docker.sock"
    assert PRIV not in [item.evidence.rule_id for item in report.findings if item.location.path == "compose.yml"]
    _assert_clean(report)


def test_k8s_literal_uses_the_parent_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, "k8s/app.yaml", "hostNetwork: true\n")
    _write(root, "k8s/notes.txt", f"{CANARY}=placeholder\nhostNetwork: true\n")
    _write(root, "k8s/base/app.yaml", "hostNetwork: true\n")
    _write(root, "other/app.yaml", "hostNetwork: true\n")
    _write(root, "deploy/net.yml", "hostNetwork: true\n")
    _write(root, "kubernetes/net.yaml", "hostNetwork: true\n")
    _ctx, report = _scan(root)
    assert sorted(item.location.path for item in _by_rule(report, K8S)) == [
        "deploy/net.yml",
        "k8s/app.yaml",
        "kubernetes/net.yaml",
    ]
    assert _by_rule(report, K8S)[0].confidence.value == "low"
    _assert_clean(report)


def test_oversize_compose_file_is_not_read(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    blob = f"{CANARY}=placeholder\ndocker.sock\n".encode() + (b"B" * 1_048_576)
    path = root / "compose.yml"
    path.write_bytes(blob)
    _ctx, report = _scan(root)
    assert _by_rule(report, SOCK) == []
    assert "surface skipped content read over 1 MiB: compose.yml" in report.limitations
    _assert_clean(report)


def test_world_writable_uses_the_link_mode(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("symlink mode is asserted on POSIX")
    root = tmp_path / "repo"
    root.mkdir()
    plain = _write(root, "plain.txt", f"{CANARY}=placeholder\n", mode=0o600)
    link = root / ".env"
    link.symlink_to(plain)
    closed = _write(root, ".env.local", "closed\n", mode=0o644)
    _ctx, report = _scan(root)
    assert sorted(item.location.path for item in _by_rule(report, WW)) == [".env"]
    assert closed.name not in [item.location.path for item in _by_rule(report, WW)]
    writable = _by_rule(report, WW)[0]
    assert writable.severity.value == "informational"
    assert writable.confidence.value == "low"
    assert writable.kind.value == "informational"
    assert writable.evidence.snippet is None
    _assert_clean(report)

    env = _write(root, "alone.env", "x\n", mode=0o666)
    del env
    other = tmp_path / "plain-repo"
    other.mkdir()
    _write(other, ".env", "x\n", mode=0o666)
    _ctx, wide = _scan(other)
    assert [item.location.path for item in _by_rule(wide, WW)] == [".env"]
    _write(other, ".env", "x\n", mode=0o644)
    _ctx, narrow = _scan(other)
    assert _by_rule(narrow, WW) == []


def test_outside_symlink_does_not_wipe_siblings(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, ".env", "keep\n")
    outside = tmp_path / "outside"
    outside.write_text(f"{CANARY}=placeholder\n", encoding="utf-8")
    outside.chmod(0o666)
    (root / "id_rsa").symlink_to(outside)
    _ctx, report = _scan(root)
    assert [item.location.path for item in report.findings] == [".env"]
    assert _by_rule(report, KEY) == []
    assert _by_rule(report, WW) == []
    assert report.scanners.executed[0].status == "executed"
    assert "skipped symlink outside target: id_rsa" in report.limitations
    _assert_clean(report)


def test_directory_symlink_is_not_descended(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    real = tmp_path / "real"
    real.mkdir()
    _write(real, ".env", f"{CANARY}=placeholder\n")
    (root / "linked").symlink_to(real, target_is_directory=True)
    _ctx, report = _scan(root)
    assert report.findings == []
    _assert_clean(report)


def test_vendor_and_root_git_are_skipped(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, ".env", "visible\n")
    _write(root, "vendor/.env", f"{CANARY}=placeholder\n")
    _write(root, ".git/config", f"{CANARY}=placeholder\n")
    _ctx, report = _scan(root)
    assert [item.location.path for item in report.findings] == [".env"]
    assert _by_rule(report, VCS) == []
    _assert_clean(report)


def test_nested_git_is_reported_without_reading(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, "nested/.git", f"{CANARY}=placeholder\n")
    _write(root, "repo/.git/HEAD", f"{CANARY}=placeholder\n")
    ctx, report = _scan(root)
    direct = SurfaceScanner().scan(
        ctx,
        ComponentScanTarget(
            component=Component(
                component_id=".",
                root=root,
                languages=(),
                frameworks=(),
                evidence=(),
                kind=ComponentKind.REPOSITORY,
            ),
            exclude_roots=(),
        ),
    )
    direct_paths = sorted(item.location.path for item in direct.findings)
    assert direct_paths == ["nested/.git", "repo/.git"]
    for item in direct.findings:
        assert item.evidence.snippet is None
        assert item.component_id == "."
    assert [item.location.path for item in _by_rule(report, VCS)] == ["nested/.git"]
    assert "unreadable path: repo/.git" in report.limitations
    _assert_clean(report)


def test_dotnet_bin_is_skipped_and_go_bin_is_not(tmp_path: Path) -> None:
    dotnet = tmp_path / "dotnet"
    dotnet.mkdir()
    _write(dotnet, "App.csproj", "<Project></Project>\n")
    _write(dotnet, ".env", "visible\n")
    _write(dotnet, "bin/.env", f"{CANARY}=placeholder\n")
    _ctx, dotnet_report = _scan(dotnet)
    assert [item.location.path for item in dotnet_report.findings] == [".env"]
    _assert_clean(dotnet_report)

    go = tmp_path / "go"
    go.mkdir()
    _write(go, "bin/.env", f"{CANARY}=placeholder\n")
    _ctx, go_report = _scan(go)
    assert [item.location.path for item in go_report.findings] == ["bin/.env"]
    _assert_clean(go_report)


def test_file_cap_stops_before_later_names(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, ".env", "visible\n")
    _write(root, "a.txt", "a\n")
    _write(root, "z.env", f"{CANARY}=placeholder\n")
    _ctx, report = _scan(root, limits=DetectLimits(max_files=1))
    assert [item.location.path for item in report.findings] == [".env"]
    assert "detection stopped: file cap 1 reached; results are incomplete" in report.limitations
    _assert_clean(report)


def test_directory_cap_and_depth(tmp_path: Path) -> None:
    capped = tmp_path / "capped"
    capped.mkdir()
    _write(capped, ".env", "visible\n")
    _write(capped, "sub/.env", f"{CANARY}=placeholder\n")
    _ctx, report = _scan(capped, limits=DetectLimits(max_directories=1))
    assert [item.location.path for item in report.findings] == [".env"]
    assert (
        "detection stopped: directory cap 1 reached; results are incomplete" in report.limitations
    )
    _assert_clean(report)

    deep = tmp_path / "deep"
    deep.mkdir()
    _write(deep, "1/2/3/4/5/6/7/8/.env", "seen\n")
    _write(deep, "1/2/3/4/5/6/7/8/9/.env", f"{CANARY}=placeholder\n")
    _ctx, deep_report = _scan(deep)
    assert [item.location.path for item in deep_report.findings] == ["1/2/3/4/5/6/7/8/.env"]
    assert "detection did not descend below depth 8; deeper paths were not scanned" in (
        deep_report.limitations
    )
    _assert_clean(deep_report)


def test_non_posix_skips_world_writable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sentinel.scanners.surface._platform_is_posix", lambda: False)
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, ".env", "x\n", mode=0o666)
    _ctx, report = _scan(root)
    assert [item.evidence.rule_id for item in report.findings] == [ENV]
    assert _by_rule(report, WW) == []
    assert report.limitations.count(POSIX_SKIP) == 1


def _rel_of_length(total: int, leaf: str) -> str:
    prefix = "/".join(["p" * 200] * 4)
    pad = total - (len(prefix) + 2 + len(leaf))
    assert 1 <= pad <= 255
    relative = prefix + "/" + ("q" * pad) + "/" + leaf
    assert len(relative) == total
    assert relative.count("/") <= 8
    return relative


def test_overlong_path_does_not_abort_or_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def spy(root: Path, candidate: str, max_bytes: int | None = None):
        seen.append(candidate)
        return open_inside(root, candidate, max_bytes)

    monkeypatch.setattr("sentinel.scanners.surface.open_inside", spy)
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, ".env", "visible\n")
    long_env = _rel_of_length(1025, ".env")
    _write(root, long_env, f"{CANARY}=placeholder\npassword=SuperSecretValue99\n")
    long_manifest = _rel_of_length(1025, "app.yaml")
    long_manifest = long_manifest.rsplit("/", 1)[0] + "/k8s/app.yaml"
    assert len(long_manifest) > 1024
    assert long_manifest.count("/") <= 8
    _write(root, long_manifest, f"hostNetwork: true {CANARY}\npassword=SuperSecretValue99\n")
    boundary = _rel_of_length(1024, ".env.local")
    _write(root, boundary, f"{CANARY}=placeholder\n")
    _ctx, report = _scan(root)
    assert report.scanners.executed[0].status == "executed"
    assert ".env" in [item.location.path for item in _by_rule(report, ENV)]
    assert boundary in [item.location.path for item in _by_rule(report, ENV)]
    assert long_env not in [item.location.path for item in report.findings]
    assert long_manifest not in [item.location.path for item in report.findings]
    assert _by_rule(report, K8S) == []
    assert "surface skipped a path longer than 1024 characters" in report.limitations
    assert long_env not in seen
    assert long_manifest not in seen
    assert boundary in seen
    blob = report.model_dump_json()
    assert CANARY not in blob
    assert "SuperSecretValue99" not in blob


def test_symlink_chains_do_not_escape_the_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, ".env", "keep\n")
    outside = tmp_path / "outside-compose.yml"
    outside.write_text(
        f"{CANARY}\npassword=SuperSecretValue99\ndocker.sock\nprivileged: true\n",
        encoding="utf-8",
    )
    (root / "mid.yml").symlink_to(outside)
    (root / "compose.yml").symlink_to(root / "mid.yml")
    hidden = root / "hidden"
    hidden.mkdir()
    _write(hidden, "app.yaml", f"hostNetwork: true {CANARY}\npassword=SuperSecretValue99\n")
    (root / "k8s").symlink_to(hidden, target_is_directory=True)
    nested = root / "sub"
    nested.mkdir()
    (nested / ".env").symlink_to(Path("..") / ".." / outside.name)
    sibling = tmp_path / "repo-secret"
    sibling.mkdir()
    _write(sibling, "compose.yaml", f"privileged: true {CANARY}\n")
    (root / "compose.yaml").symlink_to(sibling / "compose.yaml")
    _ctx, report = _scan(root)
    assert [item.location.path for item in report.findings] == [".env"]
    blob = report.model_dump_json()
    assert CANARY not in blob
    assert "SuperSecretValue99" not in blob
    assert "docker.sock" not in blob
    assert str(outside) not in blob
    assert str(sibling) not in blob
    assert "skipped symlink outside target: compose.yml" in report.limitations
    assert "skipped symlink outside target: compose.yaml" in report.limitations
    assert "skipped symlink outside target: sub/.env" in report.limitations


def test_undecodable_and_adjacent_lines_are_not_stored(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "compose.yml").write_bytes(
        f"{CANARY}\npassword=SuperSecretValue99\n".encode() + b"\xff" + b"docker.sock\n"
    )
    (root / "id_rsa").write_bytes(
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        + CANARY.encode()
        + b"\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    _write(
        root,
        "compose.yaml",
        f"{CANARY}=placeholder\nprivileged: true password=SuperSecretValue99\n"
        "token=SuperSecretValue99\n",
    )
    _ctx, report = _scan(root)
    assert _by_rule(report, SOCK) == []
    privileged = _by_rule(report, PRIV)
    assert len(privileged) == 1
    assert privileged[0].evidence.snippet == "privileged: true password=***"
    assert privileged[0].location.line == 2
    key = _by_rule(report, KEY)
    assert [item.location.path for item in key] == ["id_rsa"]
    assert key[0].evidence.snippet is None
    blob = report.model_dump_json()
    assert CANARY not in blob
    assert "SuperSecretValue99" not in blob
    assert "BEGIN OPENSSH PRIVATE KEY" not in blob


def test_surface_ast_does_not_open_files_or_import_tools() -> None:
    path = Path(SurfaceScanner.__module__)
    source = Path(__file__).resolve().parents[1] / "src/sentinel/scanners/surface.py"
    assert path.name == "sentinel.scanners.surface" or source.is_file()
    tree = ast.parse(source.read_text(encoding="utf-8"))
    banned = {"docker", "socket", "subprocess"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in banned
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "open"
        elif isinstance(node, ast.Attribute):
            assert node.attr not in {"read_text", "read_bytes", "stat"}


def test_file_cap_does_not_enter_a_child_listed_before_the_cutoff(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, ".env", "visible\n")
    _write(root, "m/.env", f"{CANARY}=placeholder\n")
    _write(root, "z.env", f"{CANARY}=placeholder\n")
    _ctx, report = _scan(root, limits=DetectLimits(max_files=1))
    assert [item.location.path for item in report.findings] == [".env"]
    assert "detection stopped: file cap 1 reached; results are incomplete" in report.limitations
    assert CANARY not in report.model_dump_json()


def test_directory_cap_keeps_the_alphabetically_first_child(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("c", "a", "b"):
        _write(root, f"{name}/.env", "visible\n")
    _ctx, report = _scan(root, limits=DetectLimits(max_directories=2))
    assert [item.location.path for item in report.findings] == ["a/.env"]
    assert (
        "detection stopped: directory cap 2 reached; results are incomplete" in report.limitations
    )


def test_project_file_listed_after_bin_still_skips_output(tmp_path: Path) -> None:
    root = tmp_path / "dotnet"
    root.mkdir()
    _write(root, "z.csproj", "<Project></Project>\n")
    _write(root, ".env", "visible\n")
    _write(root, "bin/.env", f"{CANARY}=placeholder\n")
    _write(root, "obj/.env", f"{CANARY}=placeholder\n")
    _ctx, report = _scan(root)
    assert [item.location.path for item in report.findings] == [".env"]
    assert CANARY not in report.model_dump_json()


def test_plan_retains_the_alphabetical_budget_not_the_directory() -> None:
    """A wide directory keeps a budget-sized selection and still sees every name."""

    width = 100_000
    file_budget = 5
    dir_slots = 3

    def stream():
        for index in range(width - 1, -1, -1):
            yield f"d{index:06d}", "dir"
        for index in range(width - 1, -1, -1):
            yield f"f{index:06d}.txt", "file"

    tracemalloc.start()
    plan = _plan_entries(stream(), file_budget=file_budget, dir_slots=dir_slots, depth=0)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert plan.seen == width * 2
    assert plan.file_overflow is True
    assert plan.dirs == ()
    assert plan.files == tuple((f"f{index:06d}.txt", "file") for index in range(file_budget))
    assert "f000000.txt" in {name for name, _kind in plan.files}
    assert "f999999.txt" not in {name for name, _kind in plan.files}
    assert plan.retained_entries <= file_budget + dir_slots + 1
    assert peak < 1_500_000

    directories = _plan_entries(
        ((f"d{index:04d}", "dir") for index in range(999, -1, -1)),
        file_budget=10,
        dir_slots=dir_slots,
        depth=0,
    )
    assert directories.file_overflow is False
    assert directories.dirs == ("d0000", "d0001", "d0002")
    assert directories.directory_overflow is True
    assert directories.retained_entries <= dir_slots + 1

    dotnet = _plan_entries(
        (("bin", "dir"), ("obj", "dir"), ("src", "dir"), ("z.csproj", "file")),
        file_budget=10,
        dir_slots=5,
        depth=0,
    )
    assert dotnet.dotnet is True
    assert dotnet.dirs == ("src",)

    first_bin = _plan_entries(
        (("zzz", "dir"), ("src", "dir"), ("bin", "dir")),
        file_budget=10,
        dir_slots=1,
        depth=0,
    )
    assert first_bin.dotnet is False
    assert first_bin.dirs == ("bin",)
    assert first_bin.directory_overflow is True

    hidden = _plan_entries(
        (("m.txt", "file"), ("z.txt", "file"), ("a", "dir")),
        file_budget=1,
        dir_slots=5,
        depth=8,
    )
    assert hidden.deep_name == "a"
    assert hidden.dirs == ()
    later = _plan_entries(
        (("a.txt", "file"), ("b.txt", "file"), ("m", "dir")),
        file_budget=1,
        dir_slots=5,
        depth=8,
    )
    assert later.deep_name is None
    assert later.file_overflow is True
    assert later.files == (("a.txt", "file"),)


class _SurfaceEntry:
    live = 0
    peak = 0
    created = 0

    def __init__(self, name: str) -> None:
        self.name = name
        type(self).live += 1
        type(self).created += 1
        type(self).peak = max(type(self).peak, type(self).live)

    def __del__(self) -> None:
        type(self).live -= 1

    def is_symlink(self) -> bool:
        return False

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        del follow_symlinks
        return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        del follow_symlinks
        return True


class _SurfaceListing:
    def __init__(self, total: int) -> None:
        self._index = total

    def __iter__(self) -> _SurfaceListing:
        return self

    def __next__(self) -> _SurfaceEntry:
        if self._index <= 0:
            raise StopIteration
        self._index -= 1
        return _SurfaceEntry(f"n{self._index:06d}.txt")

    def close(self) -> None:
        self._index = 0


def test_walk_retains_live_entries_for_the_budget_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    total = 100_000
    budget = 4
    root = tmp_path / "wide"
    root.mkdir()
    _SurfaceEntry.live = 0
    _SurfaceEntry.peak = 0
    _SurfaceEntry.created = 0

    def fake_scandir(_fd: int) -> _SurfaceListing:
        return _SurfaceListing(total)

    monkeypatch.setattr("sentinel.scanners.surface.os.scandir", fake_scandir)
    findings, limitations = _walk(root, DetectLimits(max_files=budget, max_directories=8))
    assert findings == []
    assert limitations == [
        "detection stopped: file cap 4 reached; results are incomplete",
    ]
    assert _SurfaceEntry.created == total
    assert _SurfaceEntry.peak <= 8


def test_note_keeps_first_seen_order_and_drops_duplicates(tmp_path: Path) -> None:
    """Repeated limitations stay a single line, in the order first recorded."""

    state = _Walk(tmp_path, DetectLimits())
    depth = "detection did not descend below depth 8; deeper paths were not scanned"
    state.note_depth()
    state.note(depth)
    first = [f"unreadable path: n{index:04d}" for index in range(300)]
    symlink = "skipped symlink outside target: link"
    for text in (*first, symlink, "unreadable path: n0000", "", *reversed(first), depth, symlink):
        state.note(text)
    assert state.limitations == [depth, *first, symlink]
    assert state.limitations.count(depth) == 1
    assert state.limitations.count("unreadable path: n0000") == 1
    assert state.limitations.count(symlink) == 1
