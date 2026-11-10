"""Python start allowlist. No Docker import and no execution of the target."""

from __future__ import annotations

from pathlib import Path

from sentinel.models import Component, ComponentKind, Framework
from sentinel.sandbox.allowlist import plan_start
from sentinel.sandbox.spec import StartPlan

_FASTAPI = (
    "python",
    "-m",
    "uvicorn",
    "{module}:application",
    "--host",
    "0.0.0.0",
    "--port",
    "8080",
)
_FLASK = (
    "python",
    "-m",
    "flask",
    "--app",
    "{module}:application",
    "run",
    "--host",
    "0.0.0.0",
    "--port",
    "8080",
)


def _component(
    root: Path,
    *,
    frameworks: tuple[Framework, ...] = (),
) -> Component:
    return Component(
        component_id="app",
        root=root,
        languages=(),
        frameworks=frameworks,
        evidence=(),
        kind=ComponentKind.APPLICATION,
    )


def _write(root: Path, relative: str, source: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _expect(module: str, framework: str) -> StartPlan:
    template = _FASTAPI if framework == "FastAPI" else _FLASK
    argv = tuple(item.format(module=module) for item in template)
    return StartPlan(argv=argv, image_key="python", tmpfs_exec=False)


def test_fastapi_app_py_uses_app_application(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(
        root,
        "app.py",
        "value = 'before'\napp = 1\napplication = FastAPI()\nafter = False\n",
    )
    plan = plan_start(_component(root, frameworks=(Framework.LARAVEL,)))
    assert plan == _expect("app", "FastAPI")


def test_fastapi_main_py_uses_main_application(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(root, "main.py", "application = FastAPI()\n")
    assert plan_start(_component(root)) == _expect("main", "FastAPI")


def test_fastapi_app_main_py_uses_app_main_application(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(root, "app/main.py", "ready = 1\napplication = FastAPI()\ndone = 2\n")
    assert plan_start(_component(root)) == _expect("app.main", "FastAPI")


def test_flask_app_py_uses_the_flask_cli(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(
        root,
        "app.py",
        "app = FastAPI()\nready = True\napplication = Flask()\ndone = 'ok'\n",
    )
    plan = plan_start(_component(root))
    assert plan == _expect("app", "Flask")
    assert plan is not None
    assert "uvicorn" not in plan.argv


def test_annassign_and_nested_assign_do_not_count(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(
        root,
        "app.py",
        "def make():\n"
        "    application = Flask()\n"
        "application: object = Flask()\n"
        "application = FastAPI()\n"
        "other = 1\n",
    )
    assert plan_start(_component(root)) == _expect("app", "FastAPI")


def test_source_is_parsed_not_executed(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(
        root,
        "app.py",
        "raise SystemExit('executed')\napplication = FastAPI()\n",
    )
    assert plan_start(_component(root)) == _expect("app", "FastAPI")


def test_in_root_symlink_can_qualify(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(root, "real_app.py", "application = FastAPI()\n")
    (root / "app.py").symlink_to((root / "real_app.py").resolve())
    assert plan_start(_component(root)) == _expect("app", "FastAPI")


def test_rejected_application_does_not_fall_through(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(root, "main.py", "application = FastAPI()\n")
    _write(root, "app/main.py", "application = FastAPI()\n")
    samples = (
        "application = create_app()\n",
        "application = fastapi.FastAPI()\n",
        "app = FastAPI()\n",
        "application = app = FastAPI()\n",
        "application = FastAPI()\napplication = Flask()\n",
        "application = FastAPI()\napplication = create_app()\n",
        "application = (\n",
        "def make():\n    application = FastAPI()\n",
    )
    for source in samples:
        _write(root, "app.py", source)
        assert plan_start(_component(root)) is None


def test_directory_named_app_py_does_not_fall_through(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").mkdir()
    _write(root, "main.py", "application = FastAPI()\n")
    assert plan_start(_component(root)) is None


def test_outside_symlink_does_not_fall_through(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("application = FastAPI()\n", encoding="utf-8")
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").symlink_to(outside)
    _write(root, "main.py", "application = FastAPI()\n")
    assert plan_start(_component(root)) is None


def test_over_cap_source_does_not_fall_through(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    payload = b"application = FastAPI()\n" + b"x" * 1_048_576
    assert len(payload) > 1_048_576
    (root / "app.py").write_bytes(payload)
    _write(root, "main.py", "application = FastAPI()\n")
    assert plan_start(_component(root)) is None


def test_laravel_label_without_a_python_file_has_no_plan(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(root, "composer.json", '{"require": {"laravel/framework": "11.0.0"}}\n')
    _write(root, "artisan", "#!/usr/bin/env php\n")
    plan = plan_start(_component(root, frameworks=(Framework.LARAVEL,)))
    assert plan is None


def test_server_js_alone_has_no_plan(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    _write(root, "server.js", "console.log('no')\n")
    _write(root, "index.js", "console.log('no')\n")
    plan = plan_start(_component(root, frameworks=(Framework.EXPRESS,)))
    assert plan is None
