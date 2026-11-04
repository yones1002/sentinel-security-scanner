"""AST import boundaries. The engine must not reach Docker or scanner modules."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "sentinel"

_ENGINE_BLOCKED = (
    "sentinel.registry",
    "sentinel.scanners",
    "sentinel.sandbox.docker_runner",
    "docker",
    ".registry",
    ".scanners",
    ".sandbox.docker_runner",
)


def _modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module:
                found.add("." * node.level + module)
            if node.level == 0 and module:
                for alias in node.names:
                    found.add(f"{module}.{alias.name}")
            elif node.level and module:
                prefix = "." * node.level + module
                for alias in node.names:
                    found.add(f"{prefix}.{alias.name}")
            elif node.level:
                for alias in node.names:
                    found.add("." * node.level + alias.name)
    return found


def _blocked(name: str, prefixes: tuple[str, ...]) -> bool:
    return any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes)


def _imports_docker(name: str) -> bool:
    return "docker" in [part for part in name.split(".") if part]


def test_engine_ast_rejects_registry_scanners_and_docker() -> None:
    modules = _modules(SRC / "engine.py")
    leaked = sorted(name for name in modules if _blocked(name, _ENGINE_BLOCKED))
    assert leaked == []


def test_no_module_imports_docker_before_the_runner_exists() -> None:
    runner = SRC / "sandbox" / "docker_runner.py"
    assert not runner.exists()
    leaked: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        for name in _modules(path):
            if _imports_docker(name):
                leaked.append(f"{path.relative_to(ROOT)}:{name}")
    assert leaked == []


def test_protocols_and_registry_stay_leaves() -> None:
    protocols = _modules(SRC / "protocols.py")
    assert not any(_blocked(name, _ENGINE_BLOCKED) for name in protocols)
    assert "sentinel.sandbox.spec" not in protocols
    registry = _modules(SRC / "registry.py")
    assert not any(_blocked(name, ("sentinel.scanners", "docker")) for name in registry)
    text = (SRC / "registry.py").read_text(encoding="utf-8")
    assert "entry_points" not in text
    assert "importlib" not in text


def test_importing_the_engine_does_not_load_docker() -> None:
    import sentinel.engine  # noqa: F401

    assert "docker" not in sys.modules
