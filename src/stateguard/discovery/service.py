"""Application service for deterministic project discovery and source indexing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from stateguard import __version__
from stateguard.contracts.common import SourceLocation
from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import canonical_json, sha256_digest
from stateguard.discovery.contracts import (
    AnalysisDiagnosticCode,
    AnalysisDiagnosticRecord,
    ProjectDiscoveryArtifact,
    SourceIndexArtifact,
    completeness_for,
    project_source_fingerprint,
    source_index_fingerprint,
)
from stateguard.discovery.fastapi import analyze_fastapi
from stateguard.discovery.files import ProjectDiscoveryError, discover_python_files
from stateguard.discovery.python_ast import analyze_module, module_name_for
from stateguard.discovery.resolution import resolve_modules


class StaleSourceIndexError(ValueError):
    """Current source bytes no longer match a Source Index snapshot."""


@dataclass(frozen=True)
class DiscoveryArtifacts:
    discovery: ProjectDiscoveryArtifact
    source_index: SourceIndexArtifact


_DISCOVERY_DIAGNOSTIC_CODES = frozenset(
    {
        AnalysisDiagnosticCode.UNREADABLE_DIRECTORY,
        AnalysisDiagnosticCode.UNREADABLE_FILE,
        AnalysisDiagnosticCode.SYMLINK_SKIPPED,
        AnalysisDiagnosticCode.INVALID_SOURCE_ENCODING,
        AnalysisDiagnosticCode.SYNTAX_ERROR,
        AnalysisDiagnosticCode.MODULE_NAME_COLLISION,
        AnalysisDiagnosticCode.AUTOMATIC_APP_TARGET_MISSING,
        AnalysisDiagnosticCode.AUTOMATIC_APP_TARGET_AMBIGUOUS,
        AnalysisDiagnosticCode.CONFIGURED_APP_TARGET_MISSING,
        AnalysisDiagnosticCode.CONFIGURED_APP_TARGET_AMBIGUOUS,
        AnalysisDiagnosticCode.CONFIGURED_APP_TARGET_UNPARSABLE,
        AnalysisDiagnosticCode.CONFIGURED_APP_TARGET_NOT_FASTAPI,
    }
)


T = TypeVar("T")


def _ordered(records: list[T] | tuple[T, ...]) -> tuple[T, ...]:
    return tuple(sorted(records, key=canonical_json))


def discover_and_index_project(
    repository_root: Path,
    config: StateGuardConfig,
    *,
    generated_at: datetime | None = None,
) -> DiscoveryArtifacts:
    timestamp = generated_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    files = discover_python_files(repository_root, config)

    modules = []
    diagnostics: list[AnalysisDiagnosticRecord] = list(files.diagnostics)
    unparsed_module_names: set[str] = set()
    for snapshot in files.snapshots:
        module_name = module_name_for(snapshot.source_root_relative_path)
        if snapshot.decoded_source is None:
            unparsed_module_names.add(module_name)
            continue
        try:
            modules.append(
                analyze_module(
                    file=snapshot.record,
                    source_root_relative_path=snapshot.source_root_relative_path,
                    source=snapshot.decoded_source,
                )
            )
        except SyntaxError as exc:
            unparsed_module_names.add(module_name)
            line = max(exc.lineno or 1, 1)
            column = max((exc.offset or 1) - 1, 0)
            diagnostics.append(
                AnalysisDiagnosticRecord(
                    code=AnalysisDiagnosticCode.SYNTAX_ERROR,
                    path=snapshot.record.path,
                    source_location=_point_location(snapshot.record.path, line, column),
                )
            )
    if not modules:
        raise ProjectDiscoveryError("no usable selected Python source")

    module_tuple = tuple(modules)
    resolved = resolve_modules(module_tuple)
    diagnostics.extend(resolved.diagnostics)
    fastapi = analyze_fastapi(
        modules=module_tuple,
        resolution=resolved.context,
        configured_app_target=config.project.app_target,
        unparsed_module_names=frozenset(unparsed_module_names),
    )
    diagnostics.extend(fastapi.diagnostics)

    file_records = tuple(snapshot.record for snapshot in files.snapshots)
    project_fingerprint = project_source_fingerprint(file_records)
    symbols = _ordered([symbol for module in module_tuple for symbol in module.symbols])
    imports = _ordered(list(resolved.imports))
    calls = _ordered(list(resolved.call_sites))
    references = _ordered([reference for module in module_tuple for reference in module.references])
    framework_instances = _ordered(list(fastapi.framework_instances))
    app_targets = _ordered(list(fastapi.app_targets))
    routes = _ordered(list(fastapi.routes))
    router_includes = _ordered(list(fastapi.router_includes))
    all_diagnostics = _ordered(diagnostics)
    discovery_diagnostics = tuple(
        item
        for item in all_diagnostics
        if isinstance(item, AnalysisDiagnosticRecord) and item.code in _DISCOVERY_DIAGNOSTIC_CODES
    )
    index_completeness = completeness_for(
        item for item in all_diagnostics if isinstance(item, AnalysisDiagnosticRecord)
    )
    discovery_completeness = completeness_for(discovery_diagnostics)

    discovery = ProjectDiscoveryArtifact(
        producer_version=__version__,
        generated_at=timestamp,
        project_id=config.project.id,
        source_root=config.project.source_root,
        project_source_fingerprint=project_fingerprint,
        files=file_records,
        app_targets=app_targets,
        diagnostics=discovery_diagnostics,
        completeness=discovery_completeness,
    )
    index_fingerprint = source_index_fingerprint(
        project_id=config.project.id,
        project_source_fingerprint=project_fingerprint,
        indexed_files=file_records,
        symbols=symbols,
        imports=imports,
        call_sites=calls,
        references=references,
        framework_instances=framework_instances,
        app_targets=app_targets,
        routes=routes,
        router_includes=router_includes,
        diagnostics=all_diagnostics,
        completeness=index_completeness,
    )
    source_index = SourceIndexArtifact(
        producer_version=__version__,
        generated_at=timestamp,
        project_id=config.project.id,
        project_source_fingerprint=project_fingerprint,
        source_index_fingerprint=index_fingerprint,
        indexed_files=file_records,
        symbols=symbols,
        imports=imports,
        call_sites=calls,
        references=references,
        framework_instances=framework_instances,
        app_targets=app_targets,
        routes=routes,
        router_includes=router_includes,
        diagnostics=all_diagnostics,
        completeness=index_completeness,
    )
    return DiscoveryArtifacts(discovery=discovery, source_index=source_index)


def validate_indexed_source_snapshot(
    repository_root: Path,
    source_index: SourceIndexArtifact,
) -> None:
    try:
        resolved_root = repository_root.resolve(strict=True)
    except OSError as exc:
        raise StaleSourceIndexError("repository root is unavailable") from exc
    if not resolved_root.is_dir():
        raise StaleSourceIndexError("repository root is unavailable")
    for record in source_index.indexed_files:
        path = resolved_root / record.path
        if path.is_symlink():
            raise StaleSourceIndexError("indexed source path is now a symlink")
        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(resolved_root)
            raw_bytes = resolved_path.read_bytes()
        except (OSError, ValueError) as exc:
            raise StaleSourceIndexError("indexed source path is missing or unreadable") from exc
        if (
            len(raw_bytes) != record.byte_size
            or sha256_digest(raw_bytes) != record.content_fingerprint
        ):
            raise StaleSourceIndexError("indexed source bytes changed; re-indexing is required")


def _point_location(path: str, line: int, column: int) -> SourceLocation:
    return SourceLocation(
        path=path,
        line_start=line,
        column_start=column,
        line_end=line,
        column_end=column,
    )
