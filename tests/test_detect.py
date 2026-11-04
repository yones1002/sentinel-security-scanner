"""Detector confinement, marker rules, and component ownership."""

from __future__ import annotations

import ast
import errno
import os
import stat
from pathlib import Path

import pytest

from sentinel.config import (
    Authorization,
    DetectLimits,
    load_scan_config,
)
from sentinel.detect import (
    apply_external_components,
    assign_component_id,
    assign_endpoint_component,
    detect,
    require_unique_components,
)
from sentinel.errors import ScanFailure, UsageError
from sentinel.fs import open_inside
from sentinel.models import Component, ComponentKind, Framework, Language

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SECRET = b"CANARY_OUTSIDE_SECRET"
WP_CANARY = "CANARY_WP_CONFIG_SECRET"
ENV_CANARY = "CANARY_SHOULD_NOT_APPEAR_IN_REPORT"


def _by_id(result):
    return {component.component_id: component for component in result.components}


def _owned(component_id: str) -> Component:
    kind = ComponentKind.REPOSITORY if component_id == "." else ComponentKind.APPLICATION
    return Component(
        component_id=component_id,
        root=Path("/scan"),
        languages=(),
        frameworks=(),
        evidence=(),
        kind=kind,
    )


def test_read_flags_prefer_no_follow() -> None:
    from sentinel import fs

    assert fs._READ_FLAGS & os.O_NOFOLLOW
    assert fs._DIR_FLAGS & os.O_NOFOLLOW


def test_open_inside_reads_a_file_and_strips_a_leading_dot_slash(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "note.txt").write_bytes(b"inside-ok")
    opened = open_inside(root, "./sub/note.txt")
    assert opened.data == b"inside-ok"
    assert opened.relative_posix == "sub/note.txt"
    assert opened.limitation is None


def test_open_inside_refuses_absolute_nul_parent_and_backslash(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "note.txt").write_bytes(b"inside-ok")
    cases = {
        "/etc/passwd": "refused absolute path",
        "C:/Windows/note.txt": "refused absolute path",
        "a\x00b": "refused NUL in path",
        "sub/../../etc/passwd": "refused parent segment",
        "sub\\note.txt": "refused backslash in path",
        "": "refused empty path",
        ".": "refused empty path",
    }
    for candidate, limitation in cases.items():
        opened = open_inside(root, candidate)
        assert opened.data is None
        assert opened.relative_posix is None
        assert opened.limitation == limitation
        assert "inside-ok" not in (opened.limitation or "")
        assert str(root) not in (opened.limitation or "")


def test_open_inside_cap_returns_no_prefix(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "big.bin").write_bytes(b"0123456789")
    opened = open_inside(root, "big.bin", max_bytes=4)
    assert opened.data is None
    assert opened.limitation == "read skipped, larger than 4 bytes: big.bin"
    assert "0123456789" not in (opened.limitation or "")
    exact = open_inside(root, "big.bin", max_bytes=10)
    assert exact.data == b"0123456789"
    assert exact.limitation is None


def test_open_inside_refuses_directory_and_intermediate_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_bytes(SECRET)
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    (root / "sub").mkdir()
    through = open_inside(root, "link/secret.txt")
    assert through.data is None
    assert through.relative_posix is None
    assert through.limitation == "refused directory symlink: link/secret.txt"
    assert SECRET not in (through.limitation or "").encode()
    assert str(secret) not in (through.limitation or "")
    itself = open_inside(root, "link")
    assert itself.data is None
    assert itself.limitation == "skipped symlink outside target: link"
    assert SECRET not in (itself.limitation or "").encode()
    assert str(outside) not in (itself.limitation or "")
    (root / "realdir").mkdir()
    (root / "inner").symlink_to("realdir", target_is_directory=True)
    inner = open_inside(root, "inner")
    assert inner.data is None
    assert inner.limitation == "refused directory symlink: inner"
    real_dir = open_inside(root, "sub")
    assert real_dir.data is None
    assert real_dir.limitation == "unreadable path: sub"


def test_open_inside_file_symlink_inside_and_outside(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_bytes(SECRET)
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "real.txt").write_bytes(b"inside-ok")
    (root / "leak").symlink_to(secret)
    (root / "abs").symlink_to((root / "real.txt").resolve())
    (root / "sub" / "rel").symlink_to("../real.txt")
    (root / "loop").symlink_to("loop")
    leaked = open_inside(root, "leak")
    assert leaked.data is None
    assert leaked.limitation == "skipped symlink outside target: leak"
    assert SECRET not in (leaked.limitation or "").encode()
    assert str(secret) not in (leaked.limitation or "")
    assert str(outside) not in (leaked.limitation or "")
    assert open_inside(root, "abs").data == b"inside-ok"
    relative = open_inside(root, "sub/rel")
    assert relative.data == b"inside-ok"
    assert relative.relative_posix == "sub/rel"
    looped = open_inside(root, "loop")
    assert looped.data is None
    assert SECRET not in (looped.limitation or "").encode()


@pytest.mark.parametrize(
    ("folder", "languages", "frameworks", "evidence", "kind"),
    [
        (
            "laravel_tiny",
            (Language.PHP,),
            (Framework.LARAVEL,),
            ("composer.json", "artisan"),
            ComponentKind.APPLICATION,
        ),
        (
            "wordpress_tiny",
            (Language.PHP,),
            (Framework.WORDPRESS,),
            ("wp-config.php",),
            ComponentKind.APPLICATION,
        ),
        (
            "go_tiny",
            (Language.GO,),
            (),
            ("go.mod",),
            ComponentKind.APPLICATION,
        ),
        (
            "python_django_tiny",
            (Language.PYTHON,),
            (Framework.DJANGO,),
            ("manage.py",),
            ComponentKind.APPLICATION,
        ),
        (
            "python_flask_tiny",
            (Language.PYTHON,),
            (Framework.FLASK,),
            ("requirements.txt",),
            ComponentKind.APPLICATION,
        ),
        (
            "python_fastapi_tiny",
            (Language.PYTHON,),
            (Framework.FASTAPI,),
            ("requirements.txt",),
            ComponentKind.APPLICATION,
        ),
        (
            "node_express_tiny",
            (Language.JAVASCRIPT,),
            (Framework.EXPRESS,),
            ("package.json",),
            ComponentKind.APPLICATION,
        ),
        (
            "node_nestjs_tiny",
            (Language.TYPESCRIPT,),
            (Framework.NESTJS,),
            ("package.json", "tsconfig.json"),
            ComponentKind.APPLICATION,
        ),
        (
            "java_spring_tiny",
            (Language.JAVA,),
            (Framework.SPRING_BOOT,),
            ("pom.xml",),
            ComponentKind.APPLICATION,
        ),
        (
            "dotnet_tiny",
            (Language.CSHARP,),
            (Framework.ASPNET_CORE,),
            ("App.csproj",),
            ComponentKind.APPLICATION,
        ),
        (
            "rails_tiny",
            (Language.RUBY,),
            (Framework.RAILS,),
            ("Gemfile", "config/routes.rb"),
            ComponentKind.APPLICATION,
        ),
        (
            "react_tiny",
            (Language.JAVASCRIPT,),
            (Framework.REACT,),
            ("package.json",),
            ComponentKind.FRONTEND,
        ),
        (
            "vue_tiny",
            (Language.JAVASCRIPT,),
            (Framework.VUE,),
            ("package.json",),
            ComponentKind.FRONTEND,
        ),
        (
            "angular_tiny",
            (Language.TYPESCRIPT,),
            (Framework.ANGULAR,),
            ("angular.json",),
            ComponentKind.FRONTEND,
        ),
    ],
)
def test_stack_fixture(folder, languages, frameworks, evidence, kind) -> None:
    target = FIXTURES / folder
    found = detect(target)
    assert found.limitations == ()
    assert found.nested_unreadable is False
    assert [item.component_id for item in found.components] == ["."]
    component = found.components[0]
    assert component.languages == languages
    assert component.frameworks == frameworks
    assert component.evidence == evidence
    assert component.kind == kind
    assert component.root == Path(os.path.realpath(target))
    assert WP_CANARY not in repr(found)


def test_express_fixture_omits_react() -> None:
    found = detect(FIXTURES / "node_express_tiny")
    assert Framework.REACT not in found.components[0].frameworks


def test_wordpress_plugin_is_not_core() -> None:
    found = detect(FIXTURES / "wordpress_plugin_tiny")
    components = _by_id(found)
    assert components["."].kind == ComponentKind.REPOSITORY
    assert components["."].languages == (Language.PHP,)
    assert components["."].frameworks == ()
    plugin = components["wp-content/plugins/sample"]
    assert plugin.kind == ComponentKind.APPLICATION
    assert plugin.languages == (Language.PHP,)
    assert plugin.frameworks == ()
    assert plugin.evidence == ("wp-content/plugins/sample",)
    assert Framework.WORDPRESS not in plugin.frameworks
    assert "wp-content" not in components
    assert "wp-content/plugins" not in components


def test_wordpress_ancestor_suppresses_plugin_label(tmp_path: Path) -> None:
    root = tmp_path / "wp"
    plugin = root / "wp-content" / "plugins" / "sample"
    plugin.mkdir(parents=True)
    (plugin / "plugin.php").write_text("<?php\n", encoding="utf-8")
    (root / "wp-config.php").write_text("<?php\n// CANARY_WP_CONFIG_SECRET\n", encoding="utf-8")
    found = detect(root)
    assert "wp-content/plugins/sample" not in _by_id(found)
    assert _by_id(found)["."].frameworks == (Framework.WORDPRESS,)
    assert WP_CANARY not in repr(found)


def test_wordpress_directory_pair_is_core(tmp_path: Path) -> None:
    root = tmp_path / "dirs"
    (root / "wp-includes").mkdir(parents=True)
    (root / "wp-content").mkdir()
    found = detect(root)
    component = found.components[0]
    assert component.frameworks == (Framework.WORDPRESS,)
    assert component.evidence == ("wp-includes", "wp-content")


def test_monorepo_ownership_and_canary() -> None:
    found = detect(FIXTURES / "monorepo_tiny")
    components = _by_id(found)
    assert len(components) > 1
    assert components["."].kind == ComponentKind.APPLICATION
    assert components["."].languages == (Language.GO,)
    assert components["."].evidence == ("go.mod",)
    api = components["apps/api"]
    assert api.languages == (Language.PHP,)
    assert api.frameworks == (Framework.LARAVEL,)
    assert api.evidence == ("apps/api/composer.json", "apps/api/artisan")
    assigned = assign_component_id("apps/api/.env", found.components)
    assert assigned.component_id == "apps/api"
    assert assigned.reason == ""
    assert ENV_CANARY not in repr(found)


def test_directory_of_php_files_is_not_a_component(tmp_path: Path) -> None:
    root = tmp_path / "php"
    (root / "pkg").mkdir(parents=True)
    (root / "index.php").write_text("<?php\n", encoding="utf-8")
    (root / "pkg" / "index.php").write_text("<?php\n", encoding="utf-8")
    found = detect(root)
    assert [item.component_id for item in found.components] == ["."]
    assert found.components[0].kind == ComponentKind.REPOSITORY
    assert found.components[0].languages == ()
    assert found.components[0].frameworks == ()


def test_negative_manifest_names_do_not_select_frameworks(tmp_path: Path) -> None:
    root = tmp_path / "names"
    root.mkdir()
    (root / "requirements.txt").write_text("django-filter==1.0.0\n", encoding="utf-8")
    (root / "package.json").write_text(
        '{"dependencies": {"express-session": "1.0.0"}}\n',
        encoding="utf-8",
    )
    (root / "setup.py").write_text("# placeholder\nname = 'django'\n", encoding="utf-8")
    calls: list[str] = []
    real = open_inside

    def wrapped(scan_root, candidate, max_bytes=None):
        calls.append(str(candidate))
        return real(scan_root, candidate, max_bytes)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("sentinel.detect.open_inside", wrapped)
    try:
        found = detect(root)
    finally:
        monkeypatch.undo()
    component = found.components[0]
    assert component.languages == (Language.PYTHON, Language.JAVASCRIPT)
    assert component.frameworks == ()
    assert "setup.py" not in calls
    assert "requirements.txt" in calls
    assert "package.json" in calls


def test_comment_only_gemfile_is_not_rails(tmp_path: Path) -> None:
    root = tmp_path / "gems"
    (root / "config").mkdir(parents=True)
    (root / "Gemfile").write_text('# gem "rails"\ngem "rails-i18n"\n', encoding="utf-8")
    (root / "config" / "routes.rb").write_text("# placeholder\n", encoding="utf-8")
    found = detect(root)
    assert found.components[0].frameworks == ()
    assert found.components[0].kind == ComponentKind.REPOSITORY


def test_manifest_reads_use_open_inside(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "app"
    root.mkdir()
    (root / "package.json").write_text('{"dependencies": {"express": "1"}}\n', encoding="utf-8")
    seen: list[tuple[str, int | None]] = []
    real = open_inside

    def wrapped(scan_root, candidate, max_bytes=None):
        seen.append((str(candidate), max_bytes))
        return real(scan_root, candidate, max_bytes)

    monkeypatch.setattr("sentinel.detect.open_inside", wrapped)
    found = detect(root)
    assert seen == [("package.json", 1_048_576)]
    assert found.components[0].frameworks == (Framework.EXPRESS,)


def test_marker_existence_does_not_read_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    real = open_inside

    def wrapped(scan_root, candidate, max_bytes=None):
        seen.append(str(candidate))
        return real(scan_root, candidate, max_bytes)

    monkeypatch.setattr("sentinel.detect.open_inside", wrapped)
    detect(FIXTURES / "wordpress_tiny")
    detect(FIXTURES / "go_tiny")
    detect(FIXTURES / "laravel_tiny")
    detect(FIXTURES / "monorepo_tiny")
    assert seen == ["composer.json", "apps/api/composer.json"]
    assert "wp-config.php" not in seen
    assert "go.mod" not in seen
    assert ".env" not in seen
    assert "artisan" not in seen


def test_inside_manifest_symlink_is_readable(tmp_path: Path) -> None:
    root = tmp_path / "linked"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "real.json").write_text(
        '{"dependencies": {"express": "1"}}\n',
        encoding="utf-8",
    )
    (root / "pkg" / "package.json").symlink_to("real.json")
    found = detect(root)
    component = _by_id(found)["pkg"]
    assert component.frameworks == (Framework.EXPRESS,)
    assert Framework.REACT not in component.frameworks


def test_directory_symlink_does_not_import_outside_component(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "go.mod").write_text("module outside.example\n\ngo 1.22\n", encoding="utf-8")
    root = tmp_path / "scan"
    root.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)
    found = detect(root)
    blob = repr(found)
    assert all(component.component_id != "escape" for component in found.components)
    assert "outside.example" not in blob
    assert str(outside) not in blob
    assert "skipped symlink outside target: escape" in found.limitations


def test_outside_file_symlinks_are_capped_at_twenty_lines(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_bytes(SECRET)
    root = tmp_path / "scan"
    root.mkdir()
    for index in range(21):
        (root / f"s{index:02d}").symlink_to(secret)
    found = detect(root)
    details = [
        item
        for item in found.limitations
        if item.startswith("skipped symlink outside target:") and not item.endswith(" more")
    ]
    assert len(details) == 20
    assert "skipped symlink outside target: 1 more" in found.limitations
    blob = "\n".join(found.limitations)
    assert SECRET.decode() not in blob
    assert str(secret) not in blob
    assert str(outside) not in blob


def test_file_cap_records_one_limitation(tmp_path: Path) -> None:
    root = tmp_path / "files"
    root.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (root / name).write_text("x", encoding="utf-8")
    found = detect(root, DetectLimits(max_files=2, max_directories=10))
    assert found.limitations == (
        "detection stopped: file cap 2 reached; results are incomplete",
    )
    assert found.nested_unreadable is False


def test_directory_cap_does_not_enter_the_child(tmp_path: Path) -> None:
    root = tmp_path / "dirs"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "go.mod").write_text("module sub.example\n\ngo 1.22\n", encoding="utf-8")
    found = detect(root, DetectLimits(max_files=50, max_directories=1))
    assert found.limitations == (
        "detection stopped: directory cap 1 reached; results are incomplete",
    )
    assert all(component.component_id != "sub" for component in found.components)
    assert "sub.example" not in repr(found)


def test_skipped_directory_files_do_not_count_toward_the_file_cap(tmp_path: Path) -> None:
    root = tmp_path / "deps"
    root.mkdir()
    (root / "keep.txt").write_text("x", encoding="utf-8")
    modules = root / "node_modules"
    modules.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (modules / name).write_text("y", encoding="utf-8")
    found = detect(root, DetectLimits(max_files=1, max_directories=100))
    assert found.limitations == ()


@pytest.mark.parametrize(
    "name",
    [
        ".git",
        "node_modules",
        "vendor",
        "venv",
        ".venv",
        "dist",
        "build",
        "target",
        "__pycache__",
        ".tox",
        ".eggs",
    ],
)
def test_skipped_directory_is_not_a_component(name: str, tmp_path: Path) -> None:
    root = tmp_path / "skip"
    nested = root / name
    nested.mkdir(parents=True)
    (nested / "go.mod").write_text("module skipped.example\n\ngo 1.22\n", encoding="utf-8")
    found = detect(root)
    assert all(component.component_id != name for component in found.components)
    assert "skipped.example" not in repr(found)


def test_go_bin_is_entered_and_dotnet_output_is_not(tmp_path: Path) -> None:
    go_root = tmp_path / "goproj"
    (go_root / "bin").mkdir(parents=True)
    (go_root / "bin" / "go.mod").write_text("module bin.example\n\ngo 1.22\n", encoding="utf-8")
    go_found = detect(go_root)
    assert any(component.component_id == "bin" for component in go_found.components)

    web = tmp_path / "web"
    web.mkdir()
    (web / "App.csproj").write_text("<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n", encoding="utf-8")
    (web / "bin").mkdir()
    (web / "obj").mkdir()
    (web / "bin" / "go.mod").write_text("module should.skip\n\ngo 1.22\n", encoding="utf-8")
    (web / "obj" / "go.mod").write_text("module should.skip.obj\n\ngo 1.22\n", encoding="utf-8")
    found = detect(web)
    ids = {component.component_id for component in found.components}
    assert "bin" not in ids
    assert "obj" not in ids
    assert found.components[0].languages == (Language.CSHARP,)
    assert found.components[0].frameworks == ()
    assert "should.skip" not in repr(found)


def test_depth_eight_keeps_the_directory_and_skips_its_children(tmp_path: Path) -> None:
    root = tmp_path / "deep"
    current = root
    for index in range(1, 9):
        current = current / f"d{index}"
    current.mkdir(parents=True)
    (current / "go.mod").write_text("module seen.deep\n\ngo 1.22\n", encoding="utf-8")
    hidden = current / "d9"
    hidden.mkdir()
    (hidden / "go.mod").write_text("module hidden.deep\n\ngo 1.22\n", encoding="utf-8")
    found = detect(root)
    ids = {component.component_id for component in found.components}
    assert "d1/d2/d3/d4/d5/d6/d7/d8" in ids
    assert "d1/d2/d3/d4/d5/d6/d7/d8/d9" not in ids
    message = "detection did not descend below depth 8; deeper paths were not scanned"
    assert found.limitations.count(message) == 1
    assert "hidden.deep" not in repr(found)


def test_nested_unreadable_directory_is_a_limitation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "tree"
    blocked = root / "blocked"
    blocked.mkdir(parents=True)
    (blocked / "note.txt").write_text("hidden", encoding="utf-8")
    (root / "seen.txt").write_text("ok", encoding="utf-8")
    blocked_id = (blocked.stat().st_dev, blocked.stat().st_ino)
    real = os.scandir

    def fake(path):
        if isinstance(path, int):
            info = os.fstat(path)
            if (info.st_dev, info.st_ino) == blocked_id:
                raise OSError("denied")
            return real(path)
        if Path(path).name == "blocked":
            raise OSError("denied")
        return real(path)

    monkeypatch.setattr(os, "scandir", fake)
    found = detect(root)
    assert found.nested_unreadable is True
    assert "unreadable directory: blocked" in found.limitations
    assert str(root) not in "\n".join(found.limitations)


def test_unlistable_root_raises_scan_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()

    def fake(path):
        raise OSError("denied")

    monkeypatch.setattr(os, "scandir", fake)
    with pytest.raises(ScanFailure) as caught:
        detect(root)
    assert str(caught.value) == "target root cannot be listed"
    assert str(root) not in str(caught.value)


def test_missing_path_and_file_are_usage_errors(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="path does not exist or is not a directory"):
        detect(tmp_path / "missing")
    target = tmp_path / "file.txt"
    target.write_text("x", encoding="utf-8")
    with pytest.raises(UsageError, match="path does not exist or is not a directory"):
        detect(target)


def test_detect_ceilings_below_one_are_usage_errors(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(UsageError, match="detect ceilings must be at least 1"):
        detect(root, DetectLimits(max_files=0, max_directories=10))


def test_oversized_manifest_is_not_parsed(tmp_path: Path) -> None:
    root = tmp_path / "big"
    root.mkdir()
    body = '{"dependencies":{"express":"1"},"pad":"' + ("x" * 1_048_576) + '"}'
    assert len(body.encode("utf-8")) > 1_048_576
    (root / "package.json").write_text(body, encoding="utf-8")
    found = detect(root)
    assert "manifest skipped, larger than 1 MiB: package.json" in found.limitations
    assert not any(item.startswith("read skipped") for item in found.limitations)
    assert found.components[0].frameworks == ()
    assert found.components[0].languages == (Language.JAVASCRIPT,)
    assert "x" * 40 not in "\n".join(found.limitations)


def test_manifest_parse_error_does_not_fail_the_scan(tmp_path: Path) -> None:
    root = tmp_path / "bad"
    root.mkdir()
    (root / "package.json").write_text("{", encoding="utf-8")
    found = detect(root)
    assert "manifest parse error: package.json" in found.limitations
    assert found.components[0].languages == (Language.JAVASCRIPT,)
    assert found.components[0].frameworks == ()
    assert found.nested_unreadable is False


def test_ownership_ranks_segment_depth_not_string_length() -> None:
    components = (_owned("."), _owned("apps"), _owned("apps/api"))
    assigned = assign_component_id("apps/api/.env", components)
    assert assigned.component_id == "apps/api"
    assert assigned.reason == ""
    shallow = assign_component_id("a/main.go", (_owned("."), _owned("a")))
    assert shallow.component_id == "a"
    windows = assign_component_id("apps\\api\\.env", components)
    assert windows.component_id == "apps/api"
    dotted = assign_component_id("./apps/api/.env", components)
    assert dotted.component_id == "apps/api"


def test_ambiguous_duplicate_ids_drop_the_path() -> None:
    assigned = assign_component_id("apps/main.go", (_owned("apps"), _owned("apps")))
    assert assigned.component_id is None
    assert assigned.reason == "ambiguous component for apps/main.go"


def test_rejected_paths_are_dropped() -> None:
    components = (_owned("."), _owned("apps"))
    cases = [
        "apps/\x00.env",
        "/etc/passwd",
        "../etc/passwd",
        "",
    ]
    for path in cases:
        assigned = assign_component_id(path, components)
        assert assigned.component_id is None
        assert assigned.reason == f"unassigned path dropped: {path}"
    missing_root = assign_component_id("notes.txt", (_owned("apps"),))
    assert missing_root.component_id is None
    assert missing_root.reason == "unassigned path dropped: notes.txt"


def test_duplicate_component_id_raises() -> None:
    with pytest.raises(ScanFailure, match="duplicate component_id apps"):
        require_unique_components((_owned("apps"), _owned("apps")))


def test_endpoint_assignment_uses_the_invoked_component() -> None:
    invoked = _owned("apps/api")
    present = assign_endpoint_component(invoked, (_owned("."), invoked))
    assert present.component_id == "apps/api"
    assert present.reason == ""
    suppressed = assign_endpoint_component(invoked, (_owned("."), _owned("apps/web")))
    assert suppressed.component_id is None
    assert suppressed.reason == "unassigned endpoint dropped"
    url = _owned("url")
    assert assign_endpoint_component(url, (url,)).component_id == "url"
    root = _owned(".")
    assert assign_endpoint_component(root, (root,)).component_id == "."


def test_in_repo_config_cannot_label_laravel_or_confirm_reads(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "sentinel.toml").write_text(
        '[[components]]\npath = "."\nframeworks = ["laravel"]\n',
        encoding="utf-8",
    )
    found = detect(root)
    assert found.components[0].frameworks == ()
    assert found.components[0].kind == ComponentKind.REPOSITORY
    loaded = load_scan_config(root / "sentinel.toml", target=root)
    assert loaded.config.component_overrides == ()
    assert loaded.config.ignores == ()
    assert loaded.config.confirm_ambiguous_reads is False
    assert loaded.authorization == Authorization(False)
    assert loaded.limitations == ("in-repo sentinel.toml attempted to set components; ignored",)
    (root / "sentinel.toml").write_text(
        "confirm_ambiguous_reads = true\n\n"
        "[[components]]\n"
        'path = "."\n'
        'frameworks = ["laravel"]\n'
        "\n"
        "[[ignore]]\n"
        f'fingerprint = "{"ab" * 32}"\n'
        'reason = "accepted"\n',
        encoding="utf-8",
    )
    both = load_scan_config(
        root / "sentinel.toml",
        target=root,
        confirm_ambiguous_reads=False,
    )
    assert both.config.confirm_ambiguous_reads is False
    assert both.config.component_overrides == ()
    assert both.config.ignores == ()
    assert both.limitations == (
        "in-repo sentinel.toml attempted to set ignore, components, confirm_ambiguous_reads; ignored",
    )


def test_external_override_unions_and_suppresses(tmp_path: Path) -> None:
    root = tmp_path / "svc"
    (root / "apps" / "api").mkdir(parents=True)
    (root / "manage.py").write_text("", encoding="utf-8")
    (root / "apps" / "api" / "go.mod").write_text("module api.example\n\ngo 1.22\n", encoding="utf-8")
    (root / "services").mkdir()
    found = detect(root)
    config = tmp_path / "user.toml"
    config.write_text(
        "confirm_ambiguous_reads = true\n"
        "authorized = true\n"
        "\n"
        "[[components]]\n"
        'path = "."\n'
        'frameworks = ["laravel"]\n'
        "\n"
        "[[ignore]]\n"
        f'fingerprint = "{"cd" * 32}"\n'
        'reason = "later milestone"\n',
        encoding="utf-8",
    )
    loaded = load_scan_config(config, target=root, confirm_ambiguous_reads=False, attested=False)
    assert loaded.limitations == ()
    assert loaded.config.confirm_ambiguous_reads is False
    assert loaded.authorization.attested is False
    assert len(loaded.config.ignores) == 1
    assert loaded.config.ignores[0].reason == "later milestone"
    updated = apply_external_components(found.components, loaded.config.component_overrides)
    root_component = _by_id_tuple(updated)["."]
    assert root_component.frameworks == (Framework.DJANGO, Framework.LARAVEL)
    assert root_component.evidence == ("manage.py",)
    assert root_component.kind == ComponentKind.APPLICATION
    invented = tmp_path / "invent.toml"
    invented.write_text(
        "[[components]]\npath = \"services\"\nframeworks = [\"laravel\"]\n",
        encoding="utf-8",
    )
    invented_loaded = load_scan_config(invented, target=root)
    unchanged = apply_external_components(found.components, invented_loaded.config.component_overrides)
    assert "services" not in {item.component_id for item in unchanged}
    suppress = tmp_path / "suppress.toml"
    suppress.write_text(
        '[[components]]\npath = "apps/api"\nsuppress = true\n\n'
        '[[components]]\npath = "."\nsuppress = true\n',
        encoding="utf-8",
    )
    suppressed = apply_external_components(
        found.components,
        load_scan_config(suppress, target=root).config.component_overrides,
    )
    assigned = assign_component_id("apps/api/main.go", suppressed)
    assert "apps/api" not in {item.component_id for item in suppressed}
    assert "." not in {item.component_id for item in suppressed}
    assert assigned.component_id is None
    assert assigned.reason == "unassigned path dropped: apps/api/main.go"


def test_external_config_rejects_unknown_values(tmp_path: Path) -> None:
    root = tmp_path / "svc"
    root.mkdir()
    missing = tmp_path / "missing.toml"
    missing.write_text('[[components]]\npath = "nope"\n', encoding="utf-8")
    with pytest.raises(UsageError, match="component path does not exist: nope"):
        load_scan_config(missing, target=root)
    unknown_framework = tmp_path / "framework.toml"
    unknown_framework.write_text(
        '[[components]]\npath = "."\nframeworks = ["magento"]\n',
        encoding="utf-8",
    )
    with pytest.raises(UsageError, match="unknown framework: magento"):
        load_scan_config(unknown_framework, target=root)
    unknown_key = tmp_path / "key.toml"
    unknown_key.write_text('password = "nope"\n', encoding="utf-8")
    with pytest.raises(UsageError, match="unknown config key: password"):
        load_scan_config(unknown_key, target=root)
    bad_suppress = tmp_path / "suppress.toml"
    bad_suppress.write_text('[[components]]\npath = "."\nsuppress = "yes"\n', encoding="utf-8")
    with pytest.raises(UsageError, match="suppress must be a boolean"):
        load_scan_config(bad_suppress, target=root)
    linked = tmp_path / "linked-target"
    (linked / "real").mkdir(parents=True)
    (linked / "alias").symlink_to(linked / "real", target_is_directory=True)
    alias = tmp_path / "alias.toml"
    alias.write_text('[[components]]\npath = "alias"\n', encoding="utf-8")
    with pytest.raises(UsageError, match="component path does not exist: alias"):
        load_scan_config(alias, target=linked)
    with pytest.raises(UsageError, match="unknown fail_on value: weird"):
        load_scan_config(None, target=root, fail_on="weird")
    with pytest.raises(UsageError, match="detect ceilings must be at least 1"):
        load_scan_config(None, target=root, detect=DetectLimits(max_files=0, max_directories=1))


def test_detect_does_not_open_files_except_through_open_inside() -> None:
    source = (Path(__file__).resolve().parents[1] / "src" / "sentinel" / "detect.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    banned: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in {"subprocess", "socket", "docker"}:
                    banned.append(alias.name)
        imported = isinstance(node, ast.ImportFrom) and node.module is not None
        if imported and node.module.split(".")[0] in {"subprocess", "socket", "docker"}:
            banned.append(node.module)
        named_call = isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        if named_call and node.func.id in {"open", "exec", "eval"}:
            banned.append(node.func.id)
        attribute_call = isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        banned_attrs = {"read_text", "read_bytes", "readlink", "iterdir", "open"}
        if attribute_call and node.func.attr in banned_attrs:
            banned.append(node.func.attr)
    assert banned == []


def test_open_inside_rejects_inode_swap_without_reading(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "note.txt").write_bytes(b"safe-bytes")
    secret = tmp_path / "secret.txt"
    secret.write_bytes(SECRET)
    seen: list[bytes] = []
    real_lstat = os.lstat
    real_read = os.read
    swapped = {"done": False}

    def lstat(path, *args, dir_fd=None, **kwargs):
        info = real_lstat(path, *args, dir_fd=dir_fd, **kwargs)
        if swapped["done"] or dir_fd is None or path != "note.txt" or not stat.S_ISREG(info.st_mode):
            return info
        swapped["done"] = True
        target = root / "note.txt"
        target.unlink()
        os.link(secret, target)
        return info

    def read(fd, size):
        block = real_read(fd, size)
        seen.append(block)
        return block

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "read", read)
    opened = open_inside(root, "note.txt")
    assert swapped["done"] is True
    assert opened.data is None
    assert opened.limitation == "refused inode mismatch: note.txt"
    assert all(SECRET not in block for block in seen)
    assert SECRET not in (opened.limitation or "").encode()


def test_open_inside_rejects_directory_inode_swap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    (root / "mid").mkdir(parents=True)
    (root / "mid" / "note.txt").write_bytes(b"safe-bytes")
    seen: list[bytes] = []
    real_lstat = os.lstat
    real_read = os.read
    swapped = {"done": False}

    def lstat(path, *args, dir_fd=None, **kwargs):
        info = real_lstat(path, *args, dir_fd=dir_fd, **kwargs)
        if (
            swapped["done"]
            or dir_fd is None
            or path != "mid"
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
        ):
            return info
        swapped["done"] = True
        live = root / "mid"
        os.rename(live, root / "mid.orig")
        live.mkdir()
        (live / "note.txt").write_bytes(SECRET)
        return info

    def read(fd, size):
        block = real_read(fd, size)
        seen.append(block)
        return block

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "read", read)
    opened = open_inside(root, "mid/note.txt")
    assert swapped["done"] is True
    assert opened.data is None
    assert opened.limitation == "refused inode mismatch: mid/note.txt"
    assert all(SECRET not in block for block in seen)


def test_symlink_limitations_match_the_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "real.txt").write_bytes(b"inside-ok")
    (root / "missing-link").symlink_to("missing.txt")
    broken = open_inside(root, "missing-link")
    assert broken.data is None
    assert broken.limitation == "skipped broken symlink: missing-link"
    os.mkfifo(root / "pipe")
    (root / "pipe-link").symlink_to("pipe")
    unusual = open_inside(root, "pipe-link")
    assert unusual.data is None
    assert unusual.limitation == "refused non-regular file: pipe-link"
    current = root / "hop0"
    for index in range(7):
        nxt = root / f"hop{index + 1}"
        current.symlink_to(nxt.name)
        current = nxt
    current.symlink_to("real.txt")
    assert open_inside(root, "hop0").data == b"inside-ok"
    current = root / "long0"
    for index in range(8):
        nxt = root / f"long{index + 1}"
        current.symlink_to(nxt.name)
        current = nxt
    current.symlink_to("real.txt")
    limited = open_inside(root, "long0")
    assert limited.data is None
    assert limited.limitation == "refused symlink hop limit: long0"
    (root / "hidden.txt").write_bytes(b"hidden")
    (root / "denied").symlink_to("hidden.txt")
    real_open = os.open

    def deny(path, flags, *args, **kwargs):
        if path == "hidden.txt" and not flags & os.O_DIRECTORY:
            raise PermissionError(errno.EACCES, "denied", path)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny)
    denied = open_inside(root, "denied")
    assert denied.data is None
    assert denied.limitation == "permission denied: denied"
    assert b"hidden" not in (denied.limitation or "").encode()


def test_detect_rejects_directory_inode_swap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "scan"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "keep.txt").write_text("inside", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "go.mod").write_text("module OUTSIDE_CANARY_MODULE\n\ngo 1.22\n", encoding="utf-8")
    (outside / "secret.txt").write_bytes(SECRET)
    outside_id = (outside.stat().st_dev, outside.stat().st_ino)
    real_lstat = os.lstat
    real_scandir = os.scandir
    swapped = {"done": False}
    listed: list[tuple[int, int]] = []

    def lstat(path, *args, dir_fd=None, **kwargs):
        info = real_lstat(path, *args, dir_fd=dir_fd, **kwargs)
        if (
            swapped["done"]
            or dir_fd is None
            or path != "sub"
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
        ):
            return info
        swapped["done"] = True
        os.rename(root / "sub", root / "sub.orig")
        os.rename(outside, root / "sub")
        return info

    def scandir(path):
        if isinstance(path, int):
            info = os.fstat(path)
            listed.append((info.st_dev, info.st_ino))
        return real_scandir(path)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "scandir", scandir)
    found = detect(root)
    blob = repr(found)
    assert swapped["done"] is True
    assert outside_id not in listed
    assert "OUTSIDE_CANARY_MODULE" not in blob
    assert SECRET.decode() not in blob
    assert "sub" not in {component.component_id for component in found.components}
    assert "refused directory inode mismatch: sub" in found.limitations


def test_detect_rejects_directory_symlink_swap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "scan"
    (root / "sub").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "go.mod").write_text("module OUTSIDE_CANARY_MODULE\n\ngo 1.22\n", encoding="utf-8")
    (outside / "secret.txt").write_bytes(SECRET)
    real_lstat = os.lstat
    swapped = {"done": False}

    def lstat(path, *args, dir_fd=None, **kwargs):
        info = real_lstat(path, *args, dir_fd=dir_fd, **kwargs)
        if (
            swapped["done"]
            or dir_fd is None
            or path != "sub"
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
        ):
            return info
        swapped["done"] = True
        os.rename(root / "sub", root / "sub.orig")
        (root / "sub").symlink_to(outside, target_is_directory=True)
        return info

    monkeypatch.setattr(os, "lstat", lstat)
    found = detect(root)
    blob = repr(found)
    assert swapped["done"] is True
    assert "OUTSIDE_CANARY_MODULE" not in blob
    assert SECRET.decode() not in blob
    assert str(outside) not in blob
    assert "refused directory symlink: sub" in found.limitations
    assert "sub" not in {component.component_id for component in found.components}


def test_detect_listing_without_nofollow_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "scan"
    root.mkdir()
    (root / "go.mod").write_text("module SHOULD_NOT_LIST\n\ngo 1.22\n", encoding="utf-8")
    calls: list[object] = []
    real = os.scandir

    def scandir(path):
        calls.append(path)
        return real(path)

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr("sentinel.fs.confined_directory_flags", lambda: None)
    with pytest.raises(ScanFailure, match="target root cannot be listed"):
        detect(root)
    assert calls == []


def test_pyproject_django_requires_a_dependency_table(tmp_path: Path) -> None:
    negative = tmp_path / "negative"
    negative.mkdir()
    (negative / "pyproject.toml").write_text(
        '[tool.coverage.report]\ndjango = "skip"\n',
        encoding="utf-8",
    )
    skipped = detect(negative)
    assert skipped.components[0].frameworks == ()
    assert skipped.components[0].languages == (Language.PYTHON,)
    positive = tmp_path / "positive"
    positive.mkdir()
    (positive / "pyproject.toml").write_text(
        '[project]\ndependencies = ["Django>=4.2"]\n',
        encoding="utf-8",
    )
    found = detect(positive)
    assert found.components[0].frameworks == (Framework.DJANGO,)
    assert found.components[0].languages == (Language.PYTHON,)
    assert found.components[0].evidence == ("pyproject.toml",)
    poetry = tmp_path / "poetry"
    poetry.mkdir()
    (poetry / "pyproject.toml").write_text(
        "[tool.poetry.dependencies]\ndjango = \"^4.2\"\n",
        encoding="utf-8",
    )
    poet = detect(poetry)
    assert poet.components[0].frameworks == (Framework.DJANGO,)


def test_laravel_with_react_keeps_javascript(tmp_path: Path) -> None:
    root = tmp_path / "app"
    root.mkdir()
    (root / "composer.json").write_text(
        '{"require": {"laravel/framework": "11.0.0"}}\n',
        encoding="utf-8",
    )
    (root / "artisan").write_text("", encoding="utf-8")
    (root / "package.json").write_text(
        '{"dependencies": {"react": "18.2.0"}}\n',
        encoding="utf-8",
    )
    found = detect(root)
    component = found.components[0]
    assert component.frameworks == (Framework.LARAVEL,)
    assert Framework.REACT not in component.frameworks
    assert component.languages == (Language.PHP, Language.JAVASCRIPT)
    assert component.kind == ComponentKind.APPLICATION
    assert component.evidence == ("composer.json", "artisan", "package.json")


def _by_id_tuple(components):
    return {component.component_id: component for component in components}
