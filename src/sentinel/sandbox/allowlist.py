"""Python start plans read from source text.

The first existing candidate is ``app.py``, then ``main.py``, then
``app/main.py``. The file is read with ``open_inside`` and parsed with
``ast.parse``. It is not imported and it is not executed.
"""

from __future__ import annotations

import ast
import os
import stat
from pathlib import Path

from sentinel.fs import open_inside
from sentinel.models import Component
from sentinel.sandbox.spec import StartPlan

_SOURCE_MAX_BYTES = 1_048_576
_ATTRIBUTE = "application"
_CANDIDATES = (
    ("app.py", "app"),
    ("main.py", "main"),
    ("app/main.py", "app.main"),
)
_FRAMEWORKS = frozenset({"FastAPI", "Flask"})
_HOST = "0.0.0.0"
_PORT = "8080"


def plan_start(component: Component) -> StartPlan | None:
    """Return a Python start plan, or ``None`` when no file qualifies.

    A candidate that exists and does not qualify fails closed. The planner
    does not try a later filename. Framework labels are not an input.
    """

    for relative, module in _CANDIDATES:
        if not _is_present(component.root, relative):
            continue
        framework = _framework_at(component.root, relative)
        if framework is None:
            return None
        return _start_plan(module, framework)
    return None


def _is_present(root: Path, relative: str) -> bool:
    """Return true when the relative name exists without following a link.

    An intermediate symlink or a non-directory parent counts as present so
    the caller can fail closed instead of skipping to the next filename.
    """

    current = root
    parts = relative.split("/")
    last = len(parts) - 1
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if index == last:
            return True
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            return True
    return True


def _framework_at(root: Path, relative: str) -> str | None:
    opened = open_inside(root, relative, max_bytes=_SOURCE_MAX_BYTES)
    if opened.data is None:
        return None
    try:
        source = opened.data.decode("utf-8")
        tree = ast.parse(source, filename=relative)
    except (UnicodeDecodeError, SyntaxError, ValueError):
        return None
    return _module_framework(tree)


def _module_framework(tree: ast.AST) -> str | None:
    """Return FastAPI or Flask when the module has one valid assignment.

    Only module-body ``ast.Assign`` nodes count. Exactly one of them may
    bind ``application``. That assignment needs one ``ast.Name`` target and
    a direct ``FastAPI()`` or ``Flask()`` call. A second binding, including
    ``application = app = FastAPI()``, fails closed.
    """

    if not isinstance(tree, ast.Module):
        return None
    found: str | None = None
    seen = 0
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not _binds_application(node):
            continue
        seen += 1
        if seen > 1:
            return None
        found = _direct_framework(node)
    if seen != 1:
        return None
    return found


def _binds_application(node: ast.Assign) -> bool:
    return any(_target_binds(target) for target in node.targets)


def _target_binds(target: ast.AST) -> bool:
    if isinstance(target, ast.Name):
        return target.id == _ATTRIBUTE
    if isinstance(target, ast.Tuple | ast.List):
        return any(_target_binds(item) for item in target.elts)
    if isinstance(target, ast.Starred):
        return _target_binds(target.value)
    return False


def _direct_framework(node: ast.Assign) -> str | None:
    if len(node.targets) != 1:
        return None
    target = node.targets[0]
    if not isinstance(target, ast.Name) or target.id != _ATTRIBUTE:
        return None
    value = node.value
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name):
        return None
    if value.func.id not in _FRAMEWORKS:
        return None
    return value.func.id


def _start_plan(module: str, framework: str) -> StartPlan:
    target = f"{module}:{_ATTRIBUTE}"
    if framework == "FastAPI":
        argv = ("python", "-m", "uvicorn", target, "--host", _HOST, "--port", _PORT)
    elif framework == "Flask":
        argv = (
            "python",
            "-m",
            "flask",
            "--app",
            target,
            "run",
            "--host",
            _HOST,
            "--port",
            _PORT,
        )
    else:
        raise RuntimeError(f"unknown framework: {framework}")
    return StartPlan(argv=argv, image_key="python", tmpfs_exec=False)
