"""Component detection inside one scan root.

File bytes are read only through ``fs.open_inside``. Directory symlinks are
not descended. Ownership ranks path-segment depth, and a tie drops the path.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tomllib
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.config import ComponentOverride, DetectLimits
from sentinel.errors import ScanFailure, UsageError
from sentinel.fs import classify_symlink, open_confined_directory, open_inside
from sentinel.models import Component, ComponentKind, Framework, Language

_MANIFEST_BYTES = 1_048_576
_MAX_DEPTH = 8
_SYMLINK_LINES = 20
_SKIP_DIRS = frozenset(
    {
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
    }
)
_FRONTEND = frozenset({Framework.REACT, Framework.VUE, Framework.ANGULAR})
_FRAMEWORK_ORDER = (
    Framework.LARAVEL,
    Framework.WORDPRESS,
    Framework.DJANGO,
    Framework.FLASK,
    Framework.FASTAPI,
    Framework.EXPRESS,
    Framework.NESTJS,
    Framework.SPRING_BOOT,
    Framework.ASPNET_CORE,
    Framework.RAILS,
    Framework.REACT,
    Framework.VUE,
    Framework.ANGULAR,
)
_PY_NAMES = {
    "django": Framework.DJANGO,
    "Django": Framework.DJANGO,
    "flask": Framework.FLASK,
    "Flask": Framework.FLASK,
    "fastapi": Framework.FASTAPI,
}
_PY_MANIFESTS = ("pyproject.toml", "requirements.txt", "Pipfile")
_PY_BARE = ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile")
_RAILS_GEM = re.compile(r"""gem\s*\(?\s*['"]rails['"]""")
_LINK_TEXT = {
    "broken": "skipped broken symlink: {path}",
    "hop": "refused symlink hop limit: {path}",
    "unusual": "refused non-regular file: {path}",
    "permission": "permission denied: {path}",
    "unreadable": "unreadable path: {path}",
    "mismatch": "refused inode mismatch: {path}",
    "unsupported": "unreadable path: {path}",
}


@dataclass(frozen=True)
class Assignment:
    """Owner id and the limitation reason. The reason is empty on success."""

    component_id: str | None
    reason: str


@dataclass(frozen=True)
class Detection:
    """Components under a target, plus limitations from the walk.

    ``nested_unreadable`` is true when a directory below the root could not
    be listed. The CLI maps that to exit 2 after the report is written.
    """

    components: tuple[Component, ...]
    limitations: tuple[str, ...]
    nested_unreadable: bool


@dataclass
class _Node:
    rel: str
    names: dict[str, str] = field(default_factory=dict)


@dataclass
class _Built:
    languages: set[Language] = field(default_factory=set)
    frameworks: set[Framework] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)
    wordpress: bool = False
    plugin: bool = False
    tsconfig: bool = False
    bare_package: bool = False

    @property
    def selected(self) -> bool:
        return bool(self.languages or self.frameworks or self.plugin)


def detect(target: Path, limits: DetectLimits | None = None) -> Detection:
    """Detect one component per matched directory under ``target``."""
    bounds = limits if limits is not None else DetectLimits()
    if bounds.max_files < 1 or bounds.max_directories < 1:
        raise UsageError("detect ceilings must be at least 1")
    if not target.exists() or not target.is_dir():
        raise UsageError("path does not exist or is not a directory")
    try:
        root = Path(os.path.realpath(target))
    except OSError as exc:
        raise ScanFailure("target root cannot be listed") from exc
    walker = _Walker(root, bounds)
    nodes = walker.walk()
    by_rel = {node.rel: node for node in nodes}
    built = {node.rel: _match(walker, node, by_rel) for node in nodes}
    _apply_plugins(built)
    components = _components(root, nodes, built)
    require_unique_components(components)
    limitations = tuple(walker.limitations)
    if walker.symlink_total > _SYMLINK_LINES:
        extra = walker.symlink_total - _SYMLINK_LINES
        limitations = (*limitations, f"skipped symlink outside target: {extra} more")
    return Detection(components, limitations, walker.nested_unreadable)


def assign_component_id(relative_path: str, components: tuple[Component, ...]) -> Assignment:
    """Return the deepest owner, or a drop reason when there is no unique owner."""
    normalized = _assign_path(relative_path)
    if normalized is None:
        return Assignment(None, f"unassigned path dropped: {relative_path}")
    containing: list[tuple[int, str]] = []
    for component in components:
        if _contains(component.component_id, normalized):
            containing.append((_segment_depth(component.component_id), component.component_id))
    if not containing:
        return Assignment(None, f"unassigned path dropped: {relative_path}")
    deepest = max(depth for depth, _component_id in containing)
    winners = [
        component_id
        for depth, component_id in containing
        if depth == deepest and component_id != "."
    ]
    if len(winners) >= 2:
        return Assignment(None, f"ambiguous component for {relative_path}")
    if len(winners) == 1:
        return Assignment(winners[0], "")
    if any(component_id == "." for _depth, component_id in containing):
        return Assignment(".", "")
    return Assignment(None, f"unassigned path dropped: {relative_path}")


def assign_endpoint_component(invoked: Component, components: tuple[Component, ...]) -> Assignment:
    """Keep the invoked component, or drop the endpoint when it was suppressed."""
    ids = {component.component_id for component in components}
    if invoked.component_id in ids:
        return Assignment(invoked.component_id, "")
    return Assignment(None, "unassigned endpoint dropped")


def apply_external_components(
    components: tuple[Component, ...],
    overrides: tuple[ComponentOverride, ...],
) -> tuple[Component, ...]:
    """Union external framework labels. ``suppress`` drops that id only.

    An override does not create a component, delete detected evidence, or
    change ``kind``. Callers still stamp paths with ``assign_component_id``.
    """
    require_unique_components(components)
    current = {component.component_id: component for component in components}
    suppressed: set[str] = set()
    for override in overrides:
        key = _normalize_id(override.path)
        component = current.get(key)
        if component is None or key in suppressed:
            continue
        if override.suppress:
            suppressed.add(key)
            continue
        frameworks = list(component.frameworks)
        for framework in override.frameworks:
            if framework not in frameworks:
                frameworks.append(framework)
        current[key] = Component(
            component_id=component.component_id,
            root=component.root,
            languages=component.languages,
            frameworks=tuple(frameworks),
            evidence=component.evidence,
            kind=component.kind,
        )
    result = tuple(
        current[component.component_id]
        for component in components
        if component.component_id not in suppressed
    )
    require_unique_components(result)
    return result


def require_unique_components(components: tuple[Component, ...]) -> None:
    """Raise when two components share an id. Do not pick a winner."""
    seen: set[str] = set()
    for component in components:
        if component.component_id in seen:
            raise ScanFailure(f"duplicate component_id {component.component_id}")
        seen.add(component.component_id)


class _Walker:
    def __init__(self, root: Path, limits: DetectLimits) -> None:
        self.root = root
        self.limits = limits
        self.limitations: list[str] = []
        self.nested_unreadable = False
        self.entered = 0
        self.files_seen = 0
        self.stopped: str | None = None
        self.depth_noted = False
        self.symlink_total = 0
        self._symlink_seen: set[str] = set()
        self._reads: dict[str, bytes | None] = {}

    def walk(self) -> list[_Node]:
        nodes: list[_Node] = []
        try:
            root_info = os.lstat(self.root)
        except OSError as exc:
            raise ScanFailure("target root cannot be listed") from exc
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise ScanFailure("target root cannot be listed")
        root_id = (root_info.st_dev, root_info.st_ino)
        pending: deque[tuple[str, int, tuple[int, int]]] = deque([("", 0, root_id)])
        while pending and self.stopped is None:
            rel, depth, expected = pending.popleft()
            if self.entered >= self.limits.max_directories:
                self._stop("directory")
                break
            self.entered += 1
            fd, reason = open_confined_directory(self.root, rel, expected)
            if fd is None:
                self._directory_failure(rel, reason)
                continue
            try:
                try:
                    entries = _list_fd(fd)
                except TypeError:
                    self._directory_failure(rel, "unsupported")
                    continue
                except OSError as exc:
                    self._directory_failure(rel, "unreadable", cause=exc)
                    continue
                node = _Node(rel)
                nodes.append(node)
                dotnet_parent = _has_dotnet_project(entries, fd)
                for entry in entries:
                    if self.stopped is not None:
                        break
                    name = entry.name
                    if name in {"", ".", ".."}:
                        continue
                    child = name if rel == "" else f"{rel}/{_nfc(name)}"
                    child = _nfc(child)
                    try:
                        info = os.lstat(name, dir_fd=fd)
                    except OSError:
                        self.limitations.append(f"unreadable path: {child}")
                        continue
                    if stat.S_ISLNK(info.st_mode):
                        self._symlink(node, name, child, fd)
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        node.names[name] = "dir"
                        if name in _SKIP_DIRS or (name in {"bin", "obj"} and dotnet_parent):
                            continue
                        if depth >= _MAX_DEPTH:
                            self._note_depth()
                            continue
                        pending.append((child, depth + 1, (info.st_dev, info.st_ino)))
                        continue
                    if not self._accept_file():
                        break
                    node.names[name] = "file" if stat.S_ISREG(info.st_mode) else "other"
            finally:
                os.close(fd)
        return nodes

    def _directory_failure(self, rel: str, reason: str, cause: BaseException | None = None) -> None:
        if rel == "" or reason == "mismatch-root":
            raise ScanFailure("target root cannot be listed") from cause
        if reason == "symlink":
            self.limitations.append(f"refused directory symlink: {rel}")
            return
        if reason == "mismatch":
            self.limitations.append(f"refused directory inode mismatch: {rel}")
        elif reason == "permission":
            self.limitations.append(f"permission denied: {rel}")
        elif reason == "unsupported":
            self.limitations.append(
                f"directory listing refused, no confined descriptor: {rel}"
            )
        else:
            self.limitations.append(f"unreadable directory: {rel}")
        self.nested_unreadable = True

    def note_symlink(self, relative: str) -> None:
        if relative in self._symlink_seen:
            return
        self._symlink_seen.add(relative)
        self.symlink_total += 1
        if self.symlink_total <= _SYMLINK_LINES:
            self.limitations.append(f"skipped symlink outside target: {relative}")

    def read_manifest(self, relative: str) -> bytes | None:
        if relative in self._reads:
            return self._reads[relative]
        opened = open_inside(self.root, relative, max_bytes=_MANIFEST_BYTES)
        if opened.data is None:
            limitation = opened.limitation or ""
            if limitation.startswith("read skipped"):
                self.limitations.append(f"manifest skipped, larger than 1 MiB: {relative}")
            elif limitation.startswith("skipped symlink outside target"):
                self.note_symlink(relative)
            elif limitation:
                self.limitations.append(limitation)
            self._reads[relative] = None
            return None
        self._reads[relative] = opened.data
        return opened.data

    def _symlink(self, node: _Node, name: str, child: str, dir_fd: int) -> None:
        kind = classify_symlink(self.root, child)
        if kind == "inside-dir":
            node.names[name] = "dir-symlink"
            return
        if kind == "inside-file":
            if self._accept_file():
                node.names[name] = "file-symlink"
            return
        if kind == "outside":
            self.note_symlink(child)
        else:
            self._note_link_issue(child, kind)
        if _points_at_directory(name, dir_fd):
            node.names[name] = "outside-symlink"
            return
        if self._accept_file():
            node.names[name] = "outside-symlink"

    def _note_link_issue(self, relative: str, kind: str) -> None:
        if relative in self._symlink_seen:
            return
        self._symlink_seen.add(relative)
        template = _LINK_TEXT.get(kind, "unreadable path: {path}")
        self.limitations.append(template.format(path=relative))

    def _accept_file(self) -> bool:
        if self.files_seen >= self.limits.max_files:
            self._stop("file")
            return False
        self.files_seen += 1
        return True

    def _stop(self, kind: str) -> None:
        if self.stopped is not None:
            return
        self.stopped = kind
        if kind == "file":
            self.limitations.append(
                f"detection stopped: file cap {self.limits.max_files} reached; "
                "results are incomplete"
            )
            return
        self.limitations.append(
            f"detection stopped: directory cap {self.limits.max_directories} reached; "
            "results are incomplete"
        )

    def _note_depth(self) -> None:
        if self.depth_noted:
            return
        self.depth_noted = True
        self.limitations.append(
            "detection did not descend below depth 8; deeper paths were not scanned"
        )


def _list_fd(fd: int) -> list[os.DirEntry[str]]:
    iterator = os.scandir(fd)
    try:
        return list(iterator)
    finally:
        iterator.close()


def _has_dotnet_project(entries: list[os.DirEntry[str]], dir_fd: int) -> bool:
    for entry in entries:
        if not (entry.name.endswith(".csproj") or entry.name.endswith(".sln")):
            continue
        try:
            info = os.lstat(entry.name, dir_fd=dir_fd)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return True
    return False


def _points_at_directory(name: str, dir_fd: int) -> bool:
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=True)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode)


def _match(walker: _Walker, node: _Node, nodes: dict[str, _Node]) -> _Built:
    built = _Built()
    _match_laravel(walker, node, built)
    _match_wordpress(node, built)
    _match_python(walker, node, built)
    _match_node(walker, node, built)
    _match_java(walker, node, built)
    _match_dotnet(walker, node, built)
    _match_rails(walker, node, nodes, built)
    if _is_file(node, "go.mod"):
        built.languages.add(Language.GO)
        built.evidence.append(_rel(node, "go.mod"))
    _finish_node_languages(built)
    return built


def _match_laravel(walker: _Walker, node: _Node, built: _Built) -> None:
    if not (_is_file(node, "composer.json") and _is_file(node, "artisan")):
        return
    document = _json_object(walker, _rel(node, "composer.json"))
    if document is None or not _composer_laravel(document):
        return
    built.frameworks.add(Framework.LARAVEL)
    built.languages.add(Language.PHP)
    built.evidence.append(_rel(node, "composer.json"))
    built.evidence.append(_rel(node, "artisan"))


def _match_wordpress(node: _Node, built: _Built) -> None:
    files = [name for name in ("wp-config.php", "wp-settings.php") if _is_file(node, name)]
    directories = _is_real_dir(node, "wp-includes") and _is_real_dir(node, "wp-content")
    if not files and not directories:
        return
    built.wordpress = True
    built.frameworks.add(Framework.WORDPRESS)
    built.languages.add(Language.PHP)
    for name in files:
        built.evidence.append(_rel(node, name))
    if directories:
        built.evidence.append(_rel(node, "wp-includes"))
        built.evidence.append(_rel(node, "wp-content"))


def _match_python(walker: _Walker, node: _Node, built: _Built) -> None:
    found: set[Framework] = set()
    token_files: list[str] = []
    for name in _PY_MANIFESTS:
        if not _is_file(node, name):
            continue
        text = _text(walker, _rel(node, name))
        if text is None:
            continue
        if name == "pyproject.toml":
            matched = _pyproject_frameworks(text)
            if matched is None:
                walker.limitations.append(f"manifest parse error: {_rel(node, name)}")
                continue
        else:
            matched = _python_frameworks(text)
        if matched:
            found.update(matched)
            token_files.append(_rel(node, name))
    if _is_file(node, "manage.py"):
        found.add(Framework.DJANGO)
        built.evidence.append(_rel(node, "manage.py"))
    if found:
        built.frameworks.update(found)
        built.languages.add(Language.PYTHON)
        built.evidence.extend(token_files)
        return
    bare = [name for name in _PY_BARE if _is_file(node, name)]
    if not bare:
        return
    built.languages.add(Language.PYTHON)
    for name in bare:
        built.evidence.append(_rel(node, name))


def _match_node(walker: _Walker, node: _Node, built: _Built) -> None:
    built.tsconfig = _is_file(node, "tsconfig.json")
    keys: set[str] = set()
    if _is_file(node, "package.json"):
        document = _json_object(walker, _rel(node, "package.json"))
        if document is not None:
            keys = _dependency_keys(document)
    if "express" in keys:
        built.frameworks.add(Framework.EXPRESS)
    if "@nestjs/core" in keys:
        built.frameworks.add(Framework.NESTJS)
    if "react" in keys:
        built.frameworks.add(Framework.REACT)
    if "vue" in keys:
        built.frameworks.add(Framework.VUE)
    angular_file = _is_file(node, "angular.json")
    if "@angular/core" in keys or angular_file:
        built.frameworks.add(Framework.ANGULAR)
    node_keys = keys & {"express", "@nestjs/core", "react", "vue", "@angular/core"}
    if node_keys:
        built.evidence.append(_rel(node, "package.json"))
    if angular_file:
        built.evidence.append(_rel(node, "angular.json"))
    if built.frameworks & _FRONTEND or _node_application(built.frameworks):
        return
    if _is_file(node, "package.json"):
        built.bare_package = True
        built.evidence.append(_rel(node, "package.json"))


def _match_java(walker: _Walker, node: _Node, built: _Built) -> None:
    spring = False
    for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        if not _is_file(node, name):
            continue
        text = _text(walker, _rel(node, name))
        if text is None or not _has_spring(name, text):
            continue
        spring = True
        built.frameworks.add(Framework.SPRING_BOOT)
        built.languages.add(Language.JAVA)
        built.evidence.append(_rel(node, name))
    if spring or not _is_file(node, "pom.xml"):
        return
    built.languages.add(Language.JAVA)
    built.evidence.append(_rel(node, "pom.xml"))


def _match_dotnet(walker: _Walker, node: _Node, built: _Built) -> None:
    csprojs = _files_ending(node, ".csproj")
    slns = _files_ending(node, ".sln")
    matched: list[str] = []
    for name in csprojs:
        text = _text(walker, _rel(node, name))
        if text is not None and _has_aspnet(text):
            matched.append(name)
    if matched and (csprojs or slns):
        built.frameworks.add(Framework.ASPNET_CORE)
        built.languages.add(Language.CSHARP)
        for name in matched:
            built.evidence.append(_rel(node, name))
        for name in slns:
            built.evidence.append(_rel(node, name))
        return
    if not csprojs:
        return
    built.languages.add(Language.CSHARP)
    for name in csprojs:
        built.evidence.append(_rel(node, name))


def _match_rails(
    walker: _Walker,
    node: _Node,
    nodes: dict[str, _Node],
    built: _Built,
) -> None:
    routes = _nested_file(nodes, node, "config", "routes.rb")
    rails_bin = _nested_file(nodes, node, "bin", "rails")
    if not (_is_file(node, "Gemfile") and (routes or rails_bin)):
        return
    text = _text(walker, _rel(node, "Gemfile"))
    if text is None or not _gemfile_has_rails(text):
        return
    built.frameworks.add(Framework.RAILS)
    built.languages.add(Language.RUBY)
    built.evidence.append(_rel(node, "Gemfile"))
    if routes:
        built.evidence.append(_rel(node, "config/routes.rb"))
    if rails_bin:
        built.evidence.append(_rel(node, "bin/rails"))


def _finish_node_languages(built: _Built) -> None:
    """Record languages from every matched rule, then omit frontend frameworks."""
    present = set(built.frameworks)
    if Framework.EXPRESS in present:
        built.languages.add(Language.JAVASCRIPT)
        if built.tsconfig:
            built.languages.add(Language.TYPESCRIPT)
    if Framework.NESTJS in present:
        built.languages.add(Language.TYPESCRIPT if built.tsconfig else Language.JAVASCRIPT)
    if Framework.REACT in present or Framework.VUE in present:
        built.languages.add(Language.TYPESCRIPT if built.tsconfig else Language.JAVASCRIPT)
    if Framework.ANGULAR in present:
        built.languages.add(Language.TYPESCRIPT)
    if built.bare_package:
        built.languages.add(Language.JAVASCRIPT)
    if built.tsconfig and any(
        item in present
        for item in (Framework.EXPRESS, Framework.NESTJS, Framework.REACT, Framework.VUE)
    ):
        _append_tsconfig(built)
    built.frameworks = set(_ordered(present))


def _append_tsconfig(built: _Built) -> None:
    for index, item in enumerate(built.evidence):
        if item.endswith("/package.json") or item == "package.json":
            built.evidence.insert(index + 1, _tsconfig_path(item))
            return
    built.evidence.append("tsconfig.json")


def _tsconfig_path(package_path: str) -> str:
    if package_path == "package.json":
        return "tsconfig.json"
    return package_path[: -len("package.json")] + "tsconfig.json"


def _apply_plugins(built: dict[str, _Built]) -> None:
    for rel, match in built.items():
        if not _is_plugin_dir(rel) or match.wordpress or _ancestor_wordpress(rel, built):
            continue
        match.plugin = True
        match.languages.add(Language.PHP)
        match.evidence.insert(0, rel)


def _components(root: Path, nodes: list[_Node], built: dict[str, _Built]) -> tuple[Component, ...]:
    children: list[Component] = []
    child_languages: set[Language] = set()
    root_match = built.get("")
    for node in nodes:
        if node.rel == "":
            continue
        match = built[node.rel]
        if not match.selected:
            continue
        children.append(_to_component(root, node.rel, match))
        child_languages.update(match.languages)
    if root_match is not None and root_match.selected:
        components = [_to_component(root, "", root_match), *children]
    else:
        components = [
            Component(
                component_id=".",
                root=root,
                languages=_language_tuple(child_languages),
                frameworks=(),
                evidence=(),
                kind=ComponentKind.REPOSITORY,
            ),
            *children,
        ]
    components.sort(key=lambda item: (item.component_id != ".", item.component_id))
    return tuple(components)


def _to_component(root: Path, rel: str, match: _Built) -> Component:
    frameworks = _ordered(match.frameworks)
    if frameworks and all(item in _FRONTEND for item in frameworks):
        kind = ComponentKind.FRONTEND
    else:
        kind = ComponentKind.APPLICATION
    directory = root if rel == "" else root.joinpath(*rel.split("/"))
    return Component(
        component_id="." if rel == "" else rel,
        root=directory,
        languages=_language_tuple(match.languages),
        frameworks=frameworks,
        evidence=_dedupe(match.evidence),
        kind=kind,
    )


def _json_object(walker: _Walker, relative: str) -> dict[str, object] | None:
    payload = walker.read_manifest(relative)
    if payload is None:
        return None
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        walker.limitations.append(f"manifest parse error: {relative}")
        return None
    if not isinstance(parsed, dict):
        walker.limitations.append(f"manifest parse error: {relative}")
        return None
    return parsed


def _text(walker: _Walker, relative: str) -> str | None:
    payload = walker.read_manifest(relative)
    if payload is None:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        walker.limitations.append(f"manifest parse error: {relative}")
        return None


def _composer_laravel(document: dict[str, object]) -> bool:
    for section in ("require", "require-dev"):
        block = document.get(section)
        if isinstance(block, dict) and "laravel/framework" in block:
            return True
    return False


def _dependency_keys(document: dict[str, object]) -> set[str]:
    keys: set[str] = set()
    for section in ("dependencies", "devDependencies"):
        block = document.get(section)
        if isinstance(block, dict):
            keys.update(key for key in block if isinstance(key, str))
    return keys


def _pyproject_frameworks(text: str) -> set[Framework] | None:
    """Frameworks named in pyproject dependency tables. None means invalid TOML."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None
    if not isinstance(document, dict):
        return None
    found: set[Framework] = set()
    for name in _pyproject_dependency_names(document):
        framework = _PY_NAMES.get(name)
        if framework is not None:
            found.add(framework)
    return found


def _pyproject_dependency_names(document: dict[str, object]) -> list[str]:
    names: list[str] = []
    project = document.get("project")
    if isinstance(project, dict):
        _collect_requirement_strings(project.get("dependencies"), names)
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for value in optional.values():
                _collect_requirement_strings(value, names)
    groups = document.get("dependency-groups")
    if isinstance(groups, dict):
        for value in groups.values():
            _collect_requirement_strings(value, names)
    tool = document.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        _collect_table_keys(poetry.get("dependencies"), names)
        _collect_table_keys(poetry.get("dev-dependencies"), names)
        group = poetry.get("group")
        if isinstance(group, dict):
            for value in group.values():
                if isinstance(value, dict):
                    _collect_table_keys(value.get("dependencies"), names)
    return names


def _collect_requirement_strings(value: object, names: list[str]) -> None:
    if not isinstance(value, list):
        return
    for item in value:
        if not isinstance(item, str):
            continue
        parsed = _python_requirement_name(item)
        if parsed is not None:
            names.append(parsed)


def _collect_table_keys(value: object, names: list[str]) -> None:
    if not isinstance(value, dict):
        return
    for key in value:
        if not isinstance(key, str):
            continue
        base = key.split("[", 1)[0].strip()
        if base:
            names.append(base)


def _python_frameworks(text: str) -> set[Framework]:
    found: set[Framework] = set()
    for line in text.splitlines():
        name = _python_requirement_name(line)
        framework = _PY_NAMES.get(name) if name is not None else None
        if framework is not None:
            found.add(framework)
    return found


def _python_requirement_name(line: str) -> str | None:
    stripped = line.strip()
    if stripped == "" or stripped.startswith(("#", "-")):
        return None
    comment = stripped.find(" #")
    if comment != -1:
        stripped = stripped[:comment].strip()
    if ";" in stripped:
        stripped = stripped.split(";", 1)[0].strip()
    stripped = stripped.strip().strip(",").strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        stripped = stripped[1:-1].strip()
    for separator in ("===", "==", ">=", "<=", "~=", "!=", ">", "<", "="):
        if separator in stripped:
            stripped = stripped.split(separator, 1)[0].strip()
            break
    if "[" in stripped:
        stripped = stripped.split("[", 1)[0].strip()
    stripped = stripped.strip("'\"")
    if stripped == "" or any(char.isspace() for char in stripped):
        return None
    if "/" in stripped or stripped.startswith("."):
        return None
    return stripped


def _has_spring(name: str, text: str) -> bool:
    if name == "pom.xml":
        return "spring-boot" in text
    if name in {"build.gradle", "build.gradle.kts"}:
        return "springframework.boot" in text or "spring-boot" in text
    return False


def _has_aspnet(text: str) -> bool:
    return "Microsoft.NET.Sdk.Web" in text or "Microsoft.AspNetCore" in text


def _gemfile_has_rails(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "" or stripped.startswith("#"):
            continue
        if _RAILS_GEM.search(stripped):
            return True
    return False


def _ordered(found: set[Framework]) -> tuple[Framework, ...]:
    kept = found
    if any(item not in _FRONTEND for item in found):
        kept = {item for item in found if item not in _FRONTEND}
    return tuple(item for item in _FRAMEWORK_ORDER if item in kept)


def _language_tuple(found: set[Language]) -> tuple[Language, ...]:
    return tuple(item for item in Language if item in found)


def _node_application(found: set[Framework]) -> bool:
    return bool(found & {Framework.EXPRESS, Framework.NESTJS})


def _is_file(node: _Node, name: str) -> bool:
    return node.names.get(name) in {"file", "file-symlink"}


def _is_real_dir(node: _Node, name: str) -> bool:
    return node.names.get(name) == "dir"


def _files_ending(node: _Node, suffix: str) -> list[str]:
    names = [
        name
        for name, kind in node.names.items()
        if kind in {"file", "file-symlink"} and name.endswith(suffix)
    ]
    return sorted(names)


def _nested_file(
    nodes: dict[str, _Node],
    node: _Node,
    directory: str,
    filename: str,
) -> bool:
    """True when a real child directory contains the file.

    The child must have been entered by the walk. A directory symlink has no
    child node, so the marker is not treated as present.
    """
    if not _is_real_dir(node, directory):
        return False
    parent = directory if node.rel == "" else f"{node.rel}/{directory}"
    child = nodes.get(parent)
    if child is None:
        return False
    return _is_file(child, filename)


def _rel(node: _Node, name: str) -> str:
    if node.rel == "":
        return name
    return f"{node.rel}/{name}"


def _is_plugin_dir(relative: str) -> bool:
    parts = relative.split("/")
    return len(parts) == 3 and parts[0] == "wp-content" and parts[1] == "plugins" and parts[2] != ""


def _ancestor_wordpress(relative: str, built: dict[str, _Built]) -> bool:
    parts = relative.split("/")
    current = ""
    for part in parts[:-1]:
        current = part if current == "" else f"{current}/{part}"
        match = built.get(current)
        if match is not None and match.wordpress:
            return True
    root = built.get("")
    return root is not None and root.wordpress and relative != ""


def _assign_path(relative_path: str) -> str | None:
    if "\x00" in relative_path:
        return None
    text = unicodedata.normalize("NFC", relative_path.replace("\\", "/"))
    while text.startswith("./"):
        text = text[2:]
    if text == "" or text.startswith("/"):
        return None
    if any(part == ".." for part in text.split("/")):
        return None
    return text


def _contains(component_id: str, path: str) -> bool:
    if component_id == ".":
        return True
    return path == component_id or path.startswith(component_id + "/")


def _segment_depth(component_id: str) -> int:
    if component_id == ".":
        return 0
    return len([part for part in component_id.split("/") if part not in {"", "."}])


def _normalize_id(value: str) -> str:
    text = unicodedata.normalize("NFC", value.replace("\\", "/"))
    while text.startswith("./"):
        text = text[2:]
    return text


def _dedupe(items: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return tuple(ordered)


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)
