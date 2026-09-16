"""Small, explicit UTF-8 resource catalog; resource text is not Python code."""

import os
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_RESOURCE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
MAX_RESOURCES = 128
MAX_DIRECTORY_ENTRIES = 2048


class ResourceError(ValueError):
    """A manifest resource is unsafe, too large, or invalid."""


def contained_path(root: Path, relative: str) -> Path:
    """Resolve a portable relative path and reject traversal, including symlinks."""
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
        raise ResourceError(f"Expected a relative POSIX path: {relative!r}")
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ResourceError(f"Resource path escapes plugin root: {relative!r}")
    candidate = (root / path).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ResourceError(f"Resource path escapes plugin root: {relative!r}")
    return candidate


def _walk_error(error: OSError) -> None:
    raise ResourceError(f"Cannot read resource directory: {error}") from error


def _read_utf8(path: Path) -> str:
    with path.open("rb") as handle:
        content = handle.read(MAX_RESOURCE_BYTES + 1)
    if len(content) > MAX_RESOURCE_BYTES:
        raise ResourceError(f"Resource exceeds {MAX_RESOURCE_BYTES} bytes: {path.name}")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ResourceError(f"Resource must be UTF-8: {path.name}") from exc


def skill_metadata(text: str) -> dict[str, str]:
    """Read the deliberately small name/description front matter subset.

    Supports unquoted and single/double quoted one-line strings. YAML structures,
    block scalars, aliases and tags are not supported. No YAML is evaluated.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ResourceError("SKILL.md requires --- front matter with name and description")
    try:
        end = next(i for i, line in enumerate(lines[1:], 1) if line.strip() == "---")
    except StopIteration as exc:
        raise ResourceError("Unterminated SKILL.md front matter") from exc
    metadata = {}
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([a-zA-Z][a-zA-Z0-9_-]*):\s*(.*?)\s*", line)
        if not match:
            raise ResourceError("SKILL.md front matter supports single-line key: value fields only")
        key, value = match.groups()
        if key in metadata:
            raise ResourceError(f"Duplicate SKILL.md field: {key}")
        if value[:1] in {"'", '"'}:
            if len(value) < 2 or value[-1] != value[0]:
                raise ResourceError(f"Unterminated quoted SKILL.md field: {key}")
            value = value[1:-1]
        elif value[:1] in {"|", ">", "[", "{", "&", "*", "!"}:
            raise ResourceError(f"Unsupported structured SKILL.md field: {key}")
        metadata[key] = value
    if not metadata.get("name") or not metadata.get("description"):
        raise ResourceError("SKILL.md requires nonempty name and description")
    return metadata


@dataclass(frozen=True)
class Resource:
    path: str
    kind: str
    name: str
    description: str
    size: int


class PluginResources:
    """Catalog only manifest-listed .md/.txt files and directories.

    Files are validated and snapshotted at activation. ``read`` checks the path
    again and returns the bounded snapshot, so replacing a file cannot silently
    change instructions in an existing plugin session.
    """

    def __init__(self, root: Path, paths: Iterable[str] = ()):
        self.root = root.resolve()
        self._resources: dict[str, Resource] = {}
        self._texts: dict[str, str] = {}
        total = 0
        visited = 0
        candidates: set[str] = set()
        for relative in paths:
            target = contained_path(self.root, relative)
            if not target.exists():
                raise ResourceError(f"Resource does not exist: {relative}")
            if target.is_dir():
                for directory, dirs, files in os.walk(target, followlinks=False, onerror=_walk_error):
                    dirs.sort()
                    files.sort()
                    for entry in dirs + files:
                        visited += 1
                        if visited > MAX_DIRECTORY_ENTRIES:
                            raise ResourceError("Resource directory contains too many entries")
                        candidate = Path(directory) / entry
                        contained_path(self.root, candidate.relative_to(self.root).as_posix())
                    # Do not recurse through symlink directories, even internal ones.
                    dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
                    for name in files:
                        if Path(name).suffix.lower() in {".md", ".txt"}:
                            candidates.add((Path(directory) / name).relative_to(self.root).as_posix())
            elif target.is_file():
                if target.suffix.lower() not in {".md", ".txt"}:
                    raise ResourceError(f"Resource must be .md or .txt: {relative}")
                candidates.add(relative)
            else:
                raise ResourceError(f"Resource is not a regular file or directory: {relative}")
        if len(candidates) > MAX_RESOURCES:
            raise ResourceError(f"Plugin exceeds {MAX_RESOURCES} text resources")
        names: set[str] = set()
        for relative in sorted(candidates):
            target = contained_path(self.root, relative)
            if not target.is_file():
                raise ResourceError(f"Resource is not a regular file: {relative}")
            text = _read_utf8(target)
            size = len(text.encode("utf-8"))
            total += size
            if total > MAX_TOTAL_BYTES:
                raise ResourceError(f"Plugin resources exceed {MAX_TOTAL_BYTES} total bytes")
            skill = target.name == "SKILL.md"
            metadata = skill_metadata(text) if skill else {}
            name = metadata.get("name", target.stem)
            if skill and name in names:
                raise ResourceError(f"Duplicate skill name: {name}")
            if skill:
                names.add(name)
            self._resources[relative] = Resource(
                relative, "skill" if skill else "evidence", name, metadata.get("description", ""), size,
            )
            self._texts[relative] = text

    def inventory(self) -> list[dict]:
        return [asdict(resource) for resource in self._resources.values()]

    def read(self, path: str) -> str:
        contained_path(self.root, path)
        if path not in self._resources:
            raise ResourceError(f"Resource is not declared: {path}")
        return self._texts[path]

    def selected(self, active_skills: Iterable[str], include_resources: bool = True) -> list[Resource]:
        requested = set(active_skills)
        matched = set()
        selected = []
        for resource in self._resources.values():
            if resource.kind == "skill":
                selectors = {resource.name, resource.path, str(Path(resource.path).parent).replace("\\", "/")}
                matches = requested & selectors
                matched.update(matches)
                if matches:
                    selected.append(resource)
            elif include_resources:
                selected.append(resource)
        unknown = requested - matched
        if unknown:
            raise ResourceError(f"Unknown active_skills: {', '.join(sorted(unknown))}")
        return selected
