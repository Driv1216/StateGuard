"""Bounded deterministic import, name, and call resolution."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from stateguard.contracts.common import SymbolId
from stateguard.discovery.contracts import (
    AnalysisDiagnosticCode,
    AnalysisDiagnosticRecord,
    CallSiteRecord,
    ImportBindingRecord,
    ImportKind,
    SymbolRecord,
)
from stateguard.discovery.python_ast import ModuleAnalysis, RawImport, ScopeInfo


@dataclass(frozen=True)
class _AliasTarget:
    canonical_prefix: str
    resolved_symbol_id: SymbolId | None


@dataclass(frozen=True)
class ResolutionResult:
    imports: tuple[ImportBindingRecord, ...]
    call_sites: tuple[CallSiteRecord, ...]
    diagnostics: tuple[AnalysisDiagnosticRecord, ...]
    context: ResolutionContext


class ResolutionContext:
    def __init__(self, modules: tuple[ModuleAnalysis, ...]) -> None:
        self.modules = modules
        self.module_by_name: dict[str, ModuleAnalysis] = {}
        self.colliding_modules: set[str] = set()
        grouped_modules: dict[str, list[ModuleAnalysis]] = defaultdict(list)
        for module in modules:
            grouped_modules[module.module_name].append(module)
        for name, candidates in grouped_modules.items():
            if len(candidates) == 1:
                self.module_by_name[name] = candidates[0]
            else:
                self.colliding_modules.add(name)

        self.symbol_by_id: dict[SymbolId, SymbolRecord] = {}
        grouped_symbols: dict[str, list[SymbolRecord]] = defaultdict(list)
        self.scope_by_id: dict[SymbolId, ScopeInfo] = {}
        self.module_for_scope: dict[SymbolId, ModuleAnalysis] = {}
        for module in modules:
            for symbol in module.symbols:
                self.symbol_by_id[symbol.symbol_id] = symbol
                grouped_symbols[symbol.qualified_name].append(symbol)
            for scope_id, scope in module.scopes.items():
                self.scope_by_id[scope_id] = scope
                self.module_for_scope[scope_id] = module
        self.unique_symbol_by_name = {
            name: values[0] for name, values in grouped_symbols.items() if len(values) == 1
        }
        self._raw_imports_by_scope: dict[SymbolId, list[RawImport]] = defaultdict(list)
        for module in modules:
            for item in module.imports:
                self._raw_imports_by_scope[item.owner_symbol_id].append(item)
        self._alias_cache: dict[SymbolId, dict[str, _AliasTarget]] = {}

    def _relative_base(self, module: ModuleAnalysis, level: int) -> str | None:
        if level == 0:
            return ""
        if module.module_name == "__init__":
            return None
        parts = module.module_name.split(".")
        is_package = module.file.path.endswith("/__init__.py")
        package_parts = parts if is_package else parts[:-1]
        ascents = level - 1
        if ascents > len(package_parts):
            return None
        retained = package_parts[: len(package_parts) - ascents]
        return ".".join(retained) if retained else None

    def canonical_import_reference(self, raw: RawImport) -> str | None:
        module = self.module_for_scope[raw.owner_symbol_id]
        if raw.level:
            base = self._relative_base(module, raw.level)
            if base is None:
                return None
            if raw.module_name:
                base = f"{base}.{raw.module_name}"
        else:
            base = raw.module_name
        if raw.imported_name is not None:
            return f"{base}.{raw.imported_name}" if base else raw.imported_name
        return base or None

    def _aliases_for_scope(self, scope_id: SymbolId) -> dict[str, _AliasTarget]:
        cached = self._alias_cache.get(scope_id)
        if cached is not None:
            return cached
        grouped: dict[str, list[_AliasTarget]] = defaultdict(list)
        for raw in self._raw_imports_by_scope.get(scope_id, []):
            if raw.local_name is None:
                continue
            canonical = self.canonical_import_reference(raw)
            if canonical is None:
                continue
            if raw.imported_name is None and raw.local_name == raw.module_name.split(".", 1)[0]:
                canonical_prefix = raw.local_name
            else:
                canonical_prefix = canonical
            symbol = self.unique_symbol_by_name.get(canonical)
            grouped[raw.local_name].append(
                _AliasTarget(
                    canonical_prefix=canonical_prefix,
                    resolved_symbol_id=symbol.symbol_id if symbol is not None else None,
                )
            )
        result = {name: values[0] for name, values in grouped.items() if len(values) == 1}
        self._alias_cache[scope_id] = result
        return result

    def _scope_chain(self, scope_id: SymbolId) -> list[ScopeInfo]:
        result: list[ScopeInfo] = []
        current: SymbolId | None = scope_id
        while current is not None:
            scope = self.scope_by_id[current]
            result.append(scope)
            current = scope.parent_symbol_id
        return result

    def canonicalize_reference(self, scope_id: SymbolId, reference: str) -> str:
        if reference.startswith("<"):
            return reference
        head, separator, tail = reference.partition(".")
        for scope in self._scope_chain(scope_id):
            alias = self._aliases_for_scope(scope.symbol.symbol_id).get(head)
            if alias is not None:
                return alias.canonical_prefix + (f".{tail}" if separator else "")
            if head in scope.writes:
                break
        return reference

    def resolve_framework_import_reference(
        self,
        scope_id: SymbolId,
        reference: str,
    ) -> str:
        return self.canonicalize_reference(scope_id, reference)

    def resolve_call_symbol(self, caller_symbol_id: SymbolId, reference: str) -> SymbolId | None:
        if reference.startswith("<"):
            return None
        canonical = self.canonicalize_reference(caller_symbol_id, reference)
        direct = self.unique_symbol_by_name.get(canonical)
        if direct is not None:
            return direct.symbol_id

        caller_scope = self.scope_by_id[caller_symbol_id]
        if "." not in reference:
            name = reference
            for scope in self._scope_chain(caller_symbol_id):
                definitions = scope.definitions.get(name, [])
                if definitions and name not in scope.writes and len(definitions) == 1:
                    return definitions[0]
                if name in scope.writes:
                    return None
            module = self.module_for_scope[caller_symbol_id]
            module_symbol = self.unique_symbol_by_name.get(f"{module.module_name}.{name}")
            return module_symbol.symbol_id if module_symbol is not None else None

        head, _, tail = reference.partition(".")
        if head in {"self", "cls"} and caller_scope.first_parameter == head:
            class_id = caller_scope.enclosing_class_symbol_id
            if class_id is not None:
                class_scope = self.scope_by_id[class_id]
                definitions = class_scope.definitions.get(tail, [])
                if len(definitions) == 1 and tail not in class_scope.writes:
                    return definitions[0]
            return None

        module = self.module_for_scope[caller_symbol_id]
        local_qualified = f"{module.module_name}.{reference}"
        local_symbol = self.unique_symbol_by_name.get(local_qualified)
        return local_symbol.symbol_id if local_symbol is not None else None


def resolve_modules(modules: tuple[ModuleAnalysis, ...]) -> ResolutionResult:
    context = ResolutionContext(modules)
    diagnostics: list[AnalysisDiagnosticRecord] = []
    for module_name in sorted(context.colliding_modules):
        for module in sorted(
            (item for item in modules if item.module_name == module_name),
            key=lambda item: item.file.path,
        ):
            diagnostics.append(
                AnalysisDiagnosticRecord(
                    code=AnalysisDiagnosticCode.MODULE_NAME_COLLISION,
                    path=module.file.path,
                )
            )

    imports: list[ImportBindingRecord] = []
    for module in modules:
        for raw_import in module.imports:
            canonical = context.canonical_import_reference(raw_import)
            if raw_import.imported_name == "*":
                diagnostics.append(
                    AnalysisDiagnosticRecord(
                        code=AnalysisDiagnosticCode.WILDCARD_IMPORT,
                        source_location=raw_import.location,
                    )
                )
            elif raw_import.level and canonical is None:
                diagnostics.append(
                    AnalysisDiagnosticRecord(
                        code=AnalysisDiagnosticCode.UNRESOLVED_RELATIVE_IMPORT,
                        source_location=raw_import.location,
                    )
                )
            symbol = context.unique_symbol_by_name.get(canonical) if canonical is not None else None
            imports.append(
                ImportBindingRecord(
                    owner_symbol_id=raw_import.owner_symbol_id,
                    kind=(
                        ImportKind.IMPORT
                        if raw_import.imported_name is None
                        else ImportKind.FROM_IMPORT
                    ),
                    syntactic_reference=raw_import.syntactic_reference,
                    local_name=raw_import.local_name,
                    canonical_reference=canonical,
                    resolved_symbol_id=symbol.symbol_id if symbol is not None else None,
                    source_location=raw_import.location,
                )
            )

    calls: list[CallSiteRecord] = []
    for module in modules:
        for raw_call in module.calls:
            canonical = context.canonicalize_reference(
                raw_call.caller_symbol_id,
                raw_call.reference,
            )
            calls.append(
                CallSiteRecord(
                    caller_symbol_id=raw_call.caller_symbol_id,
                    callee_symbol_id=context.resolve_call_symbol(
                        raw_call.caller_symbol_id,
                        raw_call.reference,
                    ),
                    callee_reference=canonical,
                    source_location=raw_call.location,
                )
            )

    return ResolutionResult(
        imports=tuple(imports),
        call_sites=tuple(calls),
        diagnostics=tuple(diagnostics),
        context=context,
    )
