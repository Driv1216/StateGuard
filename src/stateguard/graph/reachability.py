"""Deterministic effective FastAPI route composition from a selected app."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from stateguard.contracts.common import FrameworkInstanceId, SourceLocation, SymbolId
from stateguard.contracts.identity import (
    canonical_json,
    include_occurrence_anchor,
    route_registration_id,
)
from stateguard.discovery.contracts import (
    AppTargetSelection,
    FrameworkKind,
    RouteRecord,
    RouterIncludeRecord,
    SourceIndexArtifact,
)
from stateguard.graph.contracts import (
    EffectiveRouteRegistration,
    GraphDiagnosticCode,
    GraphDiagnosticImpact,
    GraphDiagnosticRecord,
)


@dataclass(frozen=True)
class ReachableRoute:
    registration: EffectiveRouteRegistration
    owner_symbol_id: SymbolId
    route_location: SourceLocation
    include_locations: tuple[SourceLocation, ...]
    include_anchors: tuple[str, ...]


@dataclass(frozen=True)
class ReachabilityResult:
    routes: tuple[ReachableRoute, ...]
    diagnostics: tuple[GraphDiagnosticRecord, ...]


@dataclass(frozen=True)
class _IncludeOccurrence:
    record: RouterIncludeRecord
    anchor: str


def _compose_path(prefixes: tuple[str, ...], route_path: str) -> str:
    prefix = ""
    for component in prefixes:
        if component:
            prefix += component.rstrip("/")
    if not prefix:
        return route_path
    if route_path == "/":
        return f"{prefix}/"
    return f"{prefix}{route_path}"


def _include_occurrences(
    includes: tuple[RouterIncludeRecord, ...],
) -> tuple[_IncludeOccurrence, ...]:
    grouped: dict[tuple[str, str, str | None], list[RouterIncludeRecord]] = defaultdict(list)
    for item in includes:
        grouped[(item.parent_instance_id, item.included_router_instance_id, item.prefix)].append(
            item
        )
    result: list[_IncludeOccurrence] = []
    for shape in sorted(grouped, key=canonical_json):
        records = sorted(grouped[shape], key=lambda item: canonical_json(item.source_location))
        for ordinal, record in enumerate(records):
            result.append(
                _IncludeOccurrence(
                    record=record,
                    anchor=include_occurrence_anchor(
                        record.parent_instance_id,
                        record.included_router_instance_id,
                        record.prefix,
                        ordinal,
                    ),
                )
            )
    return tuple(sorted(result, key=lambda item: canonical_json(item.record)))


def _route_ordinals(routes: tuple[RouteRecord, ...]) -> dict[int, int]:
    grouped: dict[tuple[str, str, str, str], list[tuple[int, RouteRecord]]] = defaultdict(list)
    for index, item in enumerate(routes):
        grouped[
            (item.registrar_instance_id, item.owner_symbol_id, item.method, item.route_path)
        ].append((index, item))
    result: dict[int, int] = {}
    for records in grouped.values():
        for ordinal, (index, _) in enumerate(
            sorted(records, key=lambda pair: canonical_json(pair[1].source_location))
        ):
            result[index] = ordinal
    return result


def compose_effective_routes(source_index: SourceIndexArtifact) -> ReachabilityResult:
    selected = [
        item
        for item in source_index.app_targets
        if item.selection in {AppTargetSelection.CONFIGURED, AppTargetSelection.AUTO_SELECTED}
    ]
    if len(selected) != 1:
        return ReachabilityResult(
            routes=(),
            diagnostics=(
                GraphDiagnosticRecord(
                    code=GraphDiagnosticCode.APP_TARGET_UNSELECTED,
                    impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
                ),
            ),
        )

    app_id = selected[0].framework_instance_id
    framework_by_id = {
        item.framework_instance_id: item for item in source_index.framework_instances
    }
    occurrences = _include_occurrences(source_index.router_includes)
    includes_by_parent: dict[FrameworkInstanceId, list[_IncludeOccurrence]] = defaultdict(list)
    for item in occurrences:
        includes_by_parent[item.record.parent_instance_id].append(item)
    routes = tuple(source_index.routes)
    route_ordinals = _route_ordinals(routes)
    routes_by_registrar: dict[FrameworkInstanceId, list[tuple[int, RouteRecord]]] = defaultdict(
        list
    )
    for index, route in enumerate(routes):
        routes_by_registrar[route.registrar_instance_id].append((index, route))

    reachable: list[ReachableRoute] = []
    diagnostics: list[GraphDiagnosticRecord] = []

    def walk(
        instance_id: FrameworkInstanceId,
        prefixes: tuple[str, ...],
        anchors: tuple[str, ...],
        include_locations: tuple[SourceLocation, ...],
        stack: tuple[FrameworkInstanceId, ...],
    ) -> None:
        for route_index, route in sorted(
            routes_by_registrar.get(instance_id, []), key=lambda pair: canonical_json(pair[1])
        ):
            registration_id = route_registration_id(
                selected_app_instance_id=app_id,
                include_anchors=anchors,
                registrar_instance_id=route.registrar_instance_id,
                owner_symbol_id=route.owner_symbol_id,
                method=route.method,
                route_path=route.route_path,
                same_shape_ordinal=route_ordinals[route_index],
            )
            reachable.append(
                ReachableRoute(
                    registration=EffectiveRouteRegistration(
                        route_registration_id=registration_id,
                        app_instance_id=app_id,
                        registrar_instance_id=route.registrar_instance_id,
                        method=route.method,
                        component_path=route.route_path,
                        effective_path=_compose_path(prefixes, route.route_path),
                    ),
                    owner_symbol_id=route.owner_symbol_id,
                    route_location=route.source_location,
                    include_locations=include_locations,
                    include_anchors=anchors,
                )
            )

        for occurrence in sorted(
            includes_by_parent.get(instance_id, []), key=lambda item: canonical_json(item.record)
        ):
            include = occurrence.record
            child = framework_by_id.get(include.included_router_instance_id)
            if include.prefix is None or child is None or child.prefix is None:
                diagnostics.append(
                    GraphDiagnosticRecord(
                        code=GraphDiagnosticCode.ROUTE_COMPOSITION_UNRESOLVED,
                        impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
                        source_location=include.source_location,
                    )
                )
                continue
            if child.kind != FrameworkKind.API_ROUTER:
                diagnostics.append(
                    GraphDiagnosticRecord(
                        code=GraphDiagnosticCode.ROUTE_COMPOSITION_UNRESOLVED,
                        impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
                        source_location=include.source_location,
                    )
                )
                continue
            if child.framework_instance_id in stack:
                diagnostics.append(
                    GraphDiagnosticRecord(
                        code=GraphDiagnosticCode.ROUTE_COMPOSITION_CYCLE,
                        impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
                        source_location=include.source_location,
                    )
                )
                continue
            walk(
                child.framework_instance_id,
                (*prefixes, include.prefix, child.prefix),
                (*anchors, occurrence.anchor),
                (*include_locations, include.source_location),
                (*stack, child.framework_instance_id),
            )

    walk(app_id, (), (), (), (app_id,))
    return ReachabilityResult(
        routes=tuple(sorted(reachable, key=lambda item: canonical_json(item.registration))),
        diagnostics=tuple(sorted(diagnostics, key=canonical_json)),
    )
