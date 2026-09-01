"""Deterministic FastAPI application, route, and router-composition analysis."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from stateguard.contracts.common import SourceLocation
from stateguard.contracts.identity import framework_instance_id
from stateguard.discovery.contracts import (
    AnalysisDiagnosticCode,
    AnalysisDiagnosticRecord,
    AppTargetRecord,
    AppTargetSelection,
    FrameworkInstanceRecord,
    FrameworkKind,
    RouteRecord,
    RouterIncludeRecord,
)
from stateguard.discovery.python_ast import ModuleAnalysis, ModuleBinding
from stateguard.discovery.resolution import ResolutionContext

_HTTP_METHODS = frozenset({"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"})
_FASTAPI_CONSTRUCTORS = {
    "fastapi.FastAPI": FrameworkKind.FASTAPI_APP,
    "fastapi.APIRouter": FrameworkKind.API_ROUTER,
}


@dataclass(frozen=True)
class FastAPIAnalysisResult:
    framework_instances: tuple[FrameworkInstanceRecord, ...]
    app_targets: tuple[AppTargetRecord, ...]
    routes: tuple[RouteRecord, ...]
    router_includes: tuple[RouterIncludeRecord, ...]
    diagnostics: tuple[AnalysisDiagnosticRecord, ...]


class _FrameworkResolver:
    def __init__(self, modules: tuple[ModuleAnalysis, ...], resolution: ResolutionContext) -> None:
        self.modules = modules
        self.resolution = resolution
        self.bindings_by_module: dict[str, list[ModuleBinding]] = {
            module.module_name: sorted(module.bindings, key=lambda item: item.position)
            for module in modules
        }
        self.module_scope_id = {
            module.module_name: next(
                symbol.symbol_id
                for symbol in module.symbols
                if symbol.qualified_name == module.module_name
            )
            for module in modules
        }
        self.instance_for_assignment: dict[
            tuple[str, str, tuple[int, int]], FrameworkInstanceRecord
        ] = {}
        self.instances_by_qualified_name: dict[str, list[FrameworkInstanceRecord]] = defaultdict(
            list
        )

    def _latest_binding(
        self,
        module_name: str,
        name: str,
        position: tuple[int, int] | None,
    ) -> ModuleBinding | None:
        candidates = [
            item
            for item in self.bindings_by_module[module_name]
            if item.name == name and (position is None or item.position < position)
        ]
        return candidates[-1] if candidates else None

    def resolve_reference(
        self,
        module: ModuleAnalysis,
        reference: str,
        position: tuple[int, int],
        seen: frozenset[str] = frozenset(),
    ) -> str | None:
        head, separator, tail = reference.partition(".")
        if head in seen:
            return None
        binding = self._latest_binding(module.module_name, head, position)
        if binding is not None:
            if binding.reference is None:
                return None
            expanded = binding.reference + (f".{tail}" if separator else "")
            return self.resolve_reference(
                module,
                expanded,
                binding.position,
                seen | {head},
            )
        scope_id = self.module_scope_id[module.module_name]
        return self.resolution.canonicalize_reference(scope_id, reference)

    def _resolve_imported_string(self, canonical: str) -> str | None:
        matching_modules = sorted(
            (
                module_name
                for module_name in self.bindings_by_module
                if canonical == module_name or canonical.startswith(f"{module_name}.")
            ),
            key=len,
            reverse=True,
        )
        if not matching_modules:
            return None
        module_name = matching_modules[0]
        suffix = canonical[len(module_name) :].lstrip(".")
        if not suffix or "." in suffix:
            return None
        binding = self._latest_binding(module_name, suffix, None)
        return binding.string_value if binding is not None else None

    def resolve_string(
        self,
        module: ModuleAnalysis,
        *,
        value: str | None,
        reference: str | None,
        position: tuple[int, int],
    ) -> str | None:
        if value is not None:
            return value
        if reference is None:
            return None
        binding = self._latest_binding(module.module_name, reference, position)
        if binding is not None:
            if binding.string_value is not None:
                return binding.string_value
            if binding.reference is not None:
                return self.resolve_string(
                    module,
                    value=None,
                    reference=binding.reference,
                    position=binding.position,
                )
            return None
        canonical = self.resolution.canonicalize_reference(
            self.module_scope_id[module.module_name],
            reference,
        )
        return self._resolve_imported_string(canonical)

    def collect_instances(self) -> tuple[FrameworkInstanceRecord, ...]:
        ordinal_by_binding: dict[tuple[str, str], int] = defaultdict(int)
        for module in self.modules:
            assignments = sorted(module.framework_assignments, key=lambda item: item.position)
            for assignment in assignments:
                constructor = self.resolve_reference(
                    module,
                    assignment.constructor_reference,
                    assignment.position,
                )
                kind = _FASTAPI_CONSTRUCTORS.get(constructor or "")
                if kind is None:
                    continue
                key = (module.module_name, assignment.binding_name)
                ordinal = ordinal_by_binding[key]
                ordinal_by_binding[key] += 1
                prefix = self.resolve_string(
                    module,
                    value=assignment.prefix_value,
                    reference=assignment.prefix_reference,
                    position=assignment.position,
                )
                if assignment.prefix_dynamic:
                    prefix = None
                qualified = f"{module.module_name}.{assignment.binding_name}"
                instance = FrameworkInstanceRecord(
                    framework_instance_id=framework_instance_id(
                        module.file.file_id,
                        qualified,
                        kind.value,
                        ordinal,
                    ),
                    source_file_id=module.file.file_id,
                    qualified_binding_name=qualified,
                    kind=kind,
                    definition_ordinal=ordinal,
                    prefix=prefix,
                    source_location=assignment.location,
                )
                self.instance_for_assignment[
                    (module.module_name, assignment.binding_name, assignment.position)
                ] = instance
                self.instances_by_qualified_name[qualified].append(instance)
        return tuple(
            sorted(
                (item for values in self.instances_by_qualified_name.values() for item in values),
                key=lambda item: (
                    item.source_location.path,
                    item.source_location.line_start,
                    item.source_location.column_start,
                    item.qualified_binding_name,
                    item.definition_ordinal,
                ),
            )
        )

    def _active_local_instance(
        self,
        module: ModuleAnalysis,
        name: str,
        position: tuple[int, int] | None,
        seen: frozenset[str] = frozenset(),
    ) -> FrameworkInstanceRecord | None:
        if name in seen:
            return None
        binding = self._latest_binding(module.module_name, name, position)
        if binding is None:
            canonical = self.resolution.canonicalize_reference(
                self.module_scope_id[module.module_name],
                name,
            )
            if canonical != name:
                return self._active_imported_instance(canonical)
            return None
        direct = self.instance_for_assignment.get((module.module_name, name, binding.position))
        if direct is not None:
            return direct
        if binding.reference is None:
            return None
        return self.resolve_instance_reference(
            module,
            binding.reference,
            binding.position,
            seen | {name},
        )

    def _active_imported_instance(self, qualified: str) -> FrameworkInstanceRecord | None:
        matching_modules = sorted(
            (module for module in self.modules if qualified.startswith(f"{module.module_name}.")),
            key=lambda item: len(item.module_name),
            reverse=True,
        )
        if not matching_modules:
            return None
        module = matching_modules[0]
        suffix = qualified[len(module.module_name) :].lstrip(".")
        if not suffix or "." in suffix:
            return None
        return self._active_local_instance(module, suffix, None)

    def resolve_instance_reference(
        self,
        module: ModuleAnalysis,
        reference: str,
        position: tuple[int, int],
        seen: frozenset[str] = frozenset(),
    ) -> FrameworkInstanceRecord | None:
        head, separator, tail = reference.partition(".")
        local = self._active_local_instance(module, head, position, seen)
        if local is not None:
            return local if not separator else None
        canonical = self.resolution.canonicalize_reference(
            self.module_scope_id[module.module_name],
            reference,
        )
        return self._active_imported_instance(canonical)

    def resolve_registrar_and_method(
        self,
        module: ModuleAnalysis,
        registrar_reference: str,
        decorator_method: str,
        position: tuple[int, int],
    ) -> tuple[FrameworkInstanceRecord | None, str | None]:
        if decorator_method != "<alias>":
            return (
                self.resolve_instance_reference(module, registrar_reference, position),
                decorator_method,
            )
        binding = self._latest_binding(module.module_name, registrar_reference, position)
        if binding is None or binding.reference is None or "." not in binding.reference:
            return None, None
        instance_reference, _, method = binding.reference.rpartition(".")
        if method not in {
            "get",
            "put",
            "post",
            "delete",
            "options",
            "head",
            "patch",
            "trace",
            "api_route",
        }:
            return None, None
        return self.resolve_instance_reference(module, instance_reference, binding.position), method

    def active_instances(self, kind: FrameworkKind) -> tuple[FrameworkInstanceRecord, ...]:
        result: list[FrameworkInstanceRecord] = []
        for qualified in sorted(self.instances_by_qualified_name):
            candidates = self.instances_by_qualified_name[qualified]
            module = max(
                (item for item in self.modules if qualified.startswith(f"{item.module_name}.")),
                key=lambda item: len(item.module_name),
            )
            name = qualified[len(module.module_name) :].lstrip(".")
            active = self._active_local_instance(module, name, None)
            if active is not None and active.kind == kind and active in candidates:
                result.append(active)
        return tuple(result)

    def ambiguous_framework_binding_locations(self) -> tuple[SourceLocation, ...]:
        locations: list[SourceLocation] = []
        for qualified, candidates in self.instances_by_qualified_name.items():
            module = max(
                (item for item in self.modules if qualified.startswith(f"{item.module_name}.")),
                key=lambda item: len(item.module_name),
            )
            name = qualified[len(module.module_name) :].lstrip(".")
            if self._active_local_instance(module, name, None) is None:
                latest = self._latest_binding(module.module_name, name, None)
                locations.append(
                    latest.location if latest is not None else candidates[-1].source_location
                )
        return tuple(locations)


def analyze_fastapi(
    *,
    modules: tuple[ModuleAnalysis, ...],
    resolution: ResolutionContext,
    configured_app_target: str | None,
    unparsed_module_names: frozenset[str],
) -> FastAPIAnalysisResult:
    resolver = _FrameworkResolver(modules, resolution)
    instances = resolver.collect_instances()
    diagnostics: list[AnalysisDiagnosticRecord] = []

    for location in resolver.ambiguous_framework_binding_locations():
        diagnostics.append(
            AnalysisDiagnosticRecord(
                code=AnalysisDiagnosticCode.AMBIGUOUS_FRAMEWORK_BINDING,
                source_location=location,
            )
        )

    for instance in instances:
        if instance.kind == FrameworkKind.API_ROUTER and instance.prefix is None:
            diagnostics.append(
                AnalysisDiagnosticRecord(
                    code=AnalysisDiagnosticCode.DYNAMIC_ROUTER_PREFIX,
                    source_location=instance.source_location,
                )
            )

    routes: list[RouteRecord] = []
    includes: list[RouterIncludeRecord] = []
    for module in modules:
        for raw in module.routes:
            registrar, method_name = resolver.resolve_registrar_and_method(
                module,
                raw.registrar_reference,
                raw.decorator_method,
                raw.position,
            )
            if registrar is None or method_name is None:
                diagnostics.append(
                    AnalysisDiagnosticRecord(
                        code=AnalysisDiagnosticCode.DYNAMIC_ROUTE_REGISTRATION,
                        source_location=raw.location,
                    )
                )
                continue
            route_path = resolver.resolve_string(
                module,
                value=raw.path_value,
                reference=raw.path_reference,
                position=raw.position,
            )
            if route_path is None or not route_path.startswith("/"):
                diagnostics.append(
                    AnalysisDiagnosticRecord(
                        code=AnalysisDiagnosticCode.DYNAMIC_ROUTE_PATH,
                        source_location=raw.location,
                    )
                )
                continue
            methods: tuple[str, ...]
            if method_name == "api_route":
                if raw.methods_dynamic or raw.methods is None:
                    diagnostics.append(
                        AnalysisDiagnosticRecord(
                            code=AnalysisDiagnosticCode.DYNAMIC_ROUTE_METHODS,
                            source_location=raw.location,
                        )
                    )
                    continue
                normalized = tuple(item.strip().upper() for item in raw.methods)
                if any(item not in _HTTP_METHODS for item in normalized):
                    diagnostics.append(
                        AnalysisDiagnosticRecord(
                            code=AnalysisDiagnosticCode.DYNAMIC_ROUTE_METHODS,
                            source_location=raw.location,
                        )
                    )
                    methods = tuple(item for item in normalized if item in _HTTP_METHODS)
                else:
                    methods = normalized
            else:
                methods = (method_name.upper(),)
            for method in methods:
                routes.append(
                    RouteRecord(
                        owner_symbol_id=raw.owner_symbol_id,
                        registrar_instance_id=registrar.framework_instance_id,
                        method=method,
                        route_path=route_path,
                        source_location=raw.location,
                    )
                )

        for raw_include in module.router_includes:
            parent = resolver.resolve_instance_reference(
                module,
                raw_include.parent_reference,
                raw_include.position,
            )
            router = (
                resolver.resolve_instance_reference(
                    module,
                    raw_include.router_reference,
                    raw_include.position,
                )
                if raw_include.router_reference is not None
                else None
            )
            if parent is None or router is None or router.kind != FrameworkKind.API_ROUTER:
                diagnostics.append(
                    AnalysisDiagnosticRecord(
                        code=AnalysisDiagnosticCode.UNRESOLVED_ROUTER_INCLUDE,
                        source_location=raw_include.location,
                    )
                )
                continue
            prefix = resolver.resolve_string(
                module,
                value=raw_include.prefix_value,
                reference=raw_include.prefix_reference,
                position=raw_include.position,
            )
            if (
                raw_include.prefix_dynamic
                or prefix is None
                or (prefix and not prefix.startswith("/"))
            ):
                diagnostics.append(
                    AnalysisDiagnosticRecord(
                        code=AnalysisDiagnosticCode.DYNAMIC_ROUTER_PREFIX,
                        source_location=raw_include.location,
                    )
                )
                prefix = None
            includes.append(
                RouterIncludeRecord(
                    parent_instance_id=parent.framework_instance_id,
                    included_router_instance_id=router.framework_instance_id,
                    prefix=prefix,
                    source_location=raw_include.location,
                )
            )

    active_apps = resolver.active_instances(FrameworkKind.FASTAPI_APP)
    app_targets: list[AppTargetRecord] = []
    if configured_app_target is not None:
        module_name, attribute = configured_app_target.split(":", 1)
        qualified = f"{module_name}.{attribute}"
        candidates = [item for item in active_apps if item.qualified_binding_name == qualified]
        if len(candidates) == 1:
            selected = candidates[0]
            app_targets.append(
                AppTargetRecord(
                    import_target=configured_app_target,
                    framework_instance_id=selected.framework_instance_id,
                    selection=AppTargetSelection.CONFIGURED,
                    source_location=selected.source_location,
                )
            )
        else:
            if module_name in unparsed_module_names:
                code = AnalysisDiagnosticCode.CONFIGURED_APP_TARGET_UNPARSABLE
            elif len(candidates) > 1:
                code = AnalysisDiagnosticCode.CONFIGURED_APP_TARGET_AMBIGUOUS
            elif any(item.qualified_binding_name == qualified for item in instances):
                code = AnalysisDiagnosticCode.CONFIGURED_APP_TARGET_NOT_FASTAPI
            else:
                code = AnalysisDiagnosticCode.CONFIGURED_APP_TARGET_MISSING
            diagnostics.append(AnalysisDiagnosticRecord(code=code))
        selected_ids = {item.framework_instance_id for item in app_targets}
        for app in active_apps:
            if app.framework_instance_id not in selected_ids:
                app_targets.append(
                    AppTargetRecord(
                        import_target=_import_target(app.qualified_binding_name),
                        framework_instance_id=app.framework_instance_id,
                        selection=AppTargetSelection.AUTO_CANDIDATE,
                        source_location=app.source_location,
                    )
                )
    elif len(active_apps) == 1:
        app = active_apps[0]
        app_targets.append(
            AppTargetRecord(
                import_target=_import_target(app.qualified_binding_name),
                framework_instance_id=app.framework_instance_id,
                selection=AppTargetSelection.AUTO_SELECTED,
                source_location=app.source_location,
            )
        )
    elif not active_apps:
        diagnostics.append(
            AnalysisDiagnosticRecord(code=AnalysisDiagnosticCode.AUTOMATIC_APP_TARGET_MISSING)
        )
    else:
        diagnostics.append(
            AnalysisDiagnosticRecord(code=AnalysisDiagnosticCode.AUTOMATIC_APP_TARGET_AMBIGUOUS)
        )
        for app in active_apps:
            app_targets.append(
                AppTargetRecord(
                    import_target=_import_target(app.qualified_binding_name),
                    framework_instance_id=app.framework_instance_id,
                    selection=AppTargetSelection.AUTO_CANDIDATE,
                    source_location=app.source_location,
                )
            )

    return FastAPIAnalysisResult(
        framework_instances=instances,
        app_targets=tuple(app_targets),
        routes=tuple(routes),
        router_includes=tuple(includes),
        diagnostics=tuple(diagnostics),
    )


def _import_target(qualified_binding_name: str) -> str:
    module, _, attribute = qualified_binding_name.rpartition(".")
    return f"{module}:{attribute}"
