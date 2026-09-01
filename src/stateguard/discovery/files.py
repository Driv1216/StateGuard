"""Deterministic, non-executing Python project file discovery."""

from __future__ import annotations

import io
import os
import tokenize
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import sha256_digest, source_file_id
from stateguard.discovery.contracts import (
    AnalysisDiagnosticCode,
    AnalysisDiagnosticRecord,
    SourceFileRecord,
)

_MANDATORY_EXCLUDED_COMPONENTS = frozenset({".git", ".stateguard", ".venv", "venv"})


class ProjectDiscoveryError(ValueError):
    """Fatal project-discovery failure that cannot produce usable artifacts."""


@dataclass(frozen=True)
class SourceSnapshot:
    record: SourceFileRecord
    source_root_relative_path: str
    decoded_source: str | None


@dataclass(frozen=True)
class FileDiscoveryResult:
    repository_root: Path
    source_root: Path
    snapshots: tuple[SourceSnapshot, ...]
    diagnostics: tuple[AnalysisDiagnosticRecord, ...]


def _match_segments(path_parts: tuple[str, ...], pattern_parts: tuple[str, ...]) -> bool:
    if not pattern_parts:
        return not path_parts
    head, *tail = pattern_parts
    remaining_pattern = tuple(tail)
    if head == "**":
        return _match_segments(path_parts, remaining_pattern) or bool(
            path_parts and _match_segments(path_parts[1:], pattern_parts)
        )
    return bool(
        path_parts
        and fnmatchcase(path_parts[0], head)
        and _match_segments(path_parts[1:], remaining_pattern)
    )


def matches_glob(path: str, pattern: str) -> bool:
    return _match_segments(tuple(path.split("/")), tuple(pattern.split("/")))


def _is_mandatory_excluded(relative_path: str) -> bool:
    return any(part in _MANDATORY_EXCLUDED_COMPONENTS for part in relative_path.split("/"))


def _selected(relative_path: str, config: StateGuardConfig) -> bool:
    if not relative_path.endswith(".py") or _is_mandatory_excluded(relative_path):
        return False
    included = any(matches_glob(relative_path, pattern) for pattern in config.analysis.include)
    excluded = any(matches_glob(relative_path, pattern) for pattern in config.analysis.exclude)
    return included and not excluded


def _repository_relative(repository_root: Path, path: Path) -> str:
    return path.relative_to(repository_root).as_posix() or "."


def _decode_python(raw_bytes: bytes) -> str:
    reader = io.BytesIO(raw_bytes).readline
    encoding, _ = tokenize.detect_encoding(reader)
    return raw_bytes.decode(encoding, errors="strict")


def discover_python_files(
    repository_root: Path,
    config: StateGuardConfig,
) -> FileDiscoveryResult:
    configured_repository = repository_root
    try:
        resolved_repository = configured_repository.resolve(strict=True)
    except OSError as exc:
        raise ProjectDiscoveryError("repository root does not exist or cannot be resolved") from exc
    if not resolved_repository.is_dir():
        raise ProjectDiscoveryError("repository root must be a directory")

    configured_source = resolved_repository / config.project.source_root
    if configured_source.is_symlink():
        raise ProjectDiscoveryError("configured source root must not be a symlink")
    try:
        resolved_source = configured_source.resolve(strict=True)
    except OSError as exc:
        raise ProjectDiscoveryError("source root does not exist or cannot be resolved") from exc
    try:
        resolved_source.relative_to(resolved_repository)
    except ValueError as exc:
        raise ProjectDiscoveryError("source root must remain inside the repository root") from exc
    if not resolved_source.is_dir():
        raise ProjectDiscoveryError("source root must be a directory")

    snapshots: list[SourceSnapshot] = []
    diagnostics: list[AnalysisDiagnosticRecord] = []
    pending = [resolved_source]
    root_enumerated = False
    while pending:
        directory = pending.pop()
        directory_relative = _repository_relative(resolved_repository, directory)
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
            if directory == resolved_source:
                root_enumerated = True
        except OSError as exc:
            if directory == resolved_source:
                raise ProjectDiscoveryError("source root cannot be enumerated") from exc
            diagnostics.append(
                AnalysisDiagnosticRecord(
                    code=AnalysisDiagnosticCode.UNREADABLE_DIRECTORY,
                    path=directory_relative,
                )
            )
            continue

        child_directories: list[Path] = []
        for entry in entries:
            entry_path = Path(entry.path)
            source_relative = entry_path.relative_to(resolved_source).as_posix()
            project_relative = _repository_relative(resolved_repository, entry_path)
            if _is_mandatory_excluded(source_relative):
                continue
            try:
                is_symlink = entry.is_symlink()
            except OSError:
                is_symlink = True
            if is_symlink:
                if entry.name.endswith(".py") or not any(
                    matches_glob(source_relative, pattern) for pattern in config.analysis.exclude
                ):
                    diagnostics.append(
                        AnalysisDiagnosticRecord(
                            code=AnalysisDiagnosticCode.SYMLINK_SKIPPED,
                            path=project_relative,
                        )
                    )
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    child_directories.append(entry_path)
                    continue
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                is_file = False
            if not is_file or not _selected(source_relative, config):
                continue
            try:
                raw_bytes = entry_path.read_bytes()
            except OSError:
                diagnostics.append(
                    AnalysisDiagnosticRecord(
                        code=AnalysisDiagnosticCode.UNREADABLE_FILE,
                        path=project_relative,
                    )
                )
                continue
            record = SourceFileRecord(
                file_id=source_file_id(config.project.id, project_relative),
                path=project_relative,
                content_fingerprint=sha256_digest(raw_bytes),
                byte_size=len(raw_bytes),
            )
            try:
                decoded = _decode_python(raw_bytes)
            except (LookupError, SyntaxError, UnicodeDecodeError):
                decoded = None
                diagnostics.append(
                    AnalysisDiagnosticRecord(
                        code=AnalysisDiagnosticCode.INVALID_SOURCE_ENCODING,
                        path=project_relative,
                    )
                )
            snapshots.append(
                SourceSnapshot(
                    record=record,
                    source_root_relative_path=source_relative,
                    decoded_source=decoded,
                )
            )
        pending.extend(reversed(child_directories))

    if not root_enumerated:
        raise ProjectDiscoveryError("source root cannot be enumerated")
    snapshots.sort(key=lambda item: item.record.path)
    diagnostics.sort(key=lambda item: (item.path or "", item.code.value))
    return FileDiscoveryResult(
        repository_root=resolved_repository,
        source_root=resolved_source,
        snapshots=tuple(snapshots),
        diagnostics=tuple(diagnostics),
    )
