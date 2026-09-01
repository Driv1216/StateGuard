"""Confidentiality-safe structural extraction from Python ASTs."""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field

from stateguard.contracts.common import SourceLocation, SymbolId
from stateguard.contracts.identity import symbol_id
from stateguard.discovery.contracts import (
    SourceFileRecord,
    SourceReferenceKind,
    SourceReferenceRecord,
    SymbolKind,
    SymbolRecord,
    source_reference_for_payment_identifier,
    source_reference_for_payment_literal,
)

_ROUTE_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace", "api_route"}
)


@dataclass(frozen=True)
class RawImport:
    owner_symbol_id: SymbolId
    module_name: str
    level: int
    imported_name: str | None
    local_name: str | None
    syntactic_reference: str
    location: SourceLocation


@dataclass(frozen=True)
class RawCall:
    caller_symbol_id: SymbolId
    reference: str
    location: SourceLocation


@dataclass(frozen=True)
class ModuleBinding:
    name: str
    reference: str | None
    string_value: str | None
    call_reference: str | None
    dynamic: bool
    position: tuple[int, int]
    location: SourceLocation


@dataclass(frozen=True)
class RawFrameworkAssignment:
    binding_name: str
    constructor_reference: str
    prefix_value: str | None
    prefix_reference: str | None
    prefix_dynamic: bool
    position: tuple[int, int]
    location: SourceLocation


@dataclass(frozen=True)
class RawRoute:
    owner_symbol_id: SymbolId
    registrar_reference: str
    decorator_method: str
    path_value: str | None
    path_reference: str | None
    methods: tuple[str, ...] | None
    methods_dynamic: bool
    position: tuple[int, int]
    location: SourceLocation


@dataclass(frozen=True)
class RawRouterInclude:
    owner_symbol_id: SymbolId
    parent_reference: str
    router_reference: str | None
    prefix_value: str | None
    prefix_reference: str | None
    prefix_dynamic: bool
    position: tuple[int, int]
    location: SourceLocation


@dataclass
class ScopeInfo:
    symbol: SymbolRecord
    parent_symbol_id: SymbolId | None
    enclosing_class_symbol_id: SymbolId | None
    first_parameter: str | None = None
    definitions: dict[str, list[SymbolId]] = field(default_factory=lambda: defaultdict(list))
    writes: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class ModuleAnalysis:
    module_name: str
    file: SourceFileRecord
    symbols: tuple[SymbolRecord, ...]
    scopes: dict[SymbolId, ScopeInfo]
    imports: tuple[RawImport, ...]
    calls: tuple[RawCall, ...]
    references: tuple[SourceReferenceRecord, ...]
    bindings: tuple[ModuleBinding, ...]
    framework_assignments: tuple[RawFrameworkAssignment, ...]
    routes: tuple[RawRoute, ...]
    router_includes: tuple[RawRouterInclude, ...]


def module_name_for(source_root_relative_path: str) -> str:
    parts = source_root_relative_path.split("/")
    filename = parts[-1]
    if filename == "__init__.py":
        return ".".join(parts[:-1]) or "__init__"
    parts[-1] = filename[:-3]
    return ".".join(parts)


def _location(path: str, node: ast.AST) -> SourceLocation:
    line_start = max(getattr(node, "lineno", 1), 1)
    column_start = max(getattr(node, "col_offset", 0), 0)
    line_end = max(getattr(node, "end_lineno", line_start) or line_start, line_start)
    column_end = max(getattr(node, "end_col_offset", column_start) or column_start, 0)
    return SourceLocation(
        path=path,
        line_start=line_start,
        column_start=column_start,
        line_end=line_end,
        column_end=column_end,
    )


def _reference(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _reference(node.value)
        return f"{parent}.{node.attr}" if parent is not None else None
    return None


def _string_or_name(node: ast.AST | None) -> tuple[str | None, str | None, bool]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, None, False
    if isinstance(node, ast.Name):
        return None, node.id, False
    return None, None, node is not None


def _safe_signature(arguments: ast.arguments) -> str:
    positional = [*arguments.posonlyargs, *arguments.args]
    defaults_start = len(positional) - len(arguments.defaults)
    rendered: list[str] = []
    for index, argument in enumerate(positional):
        value = argument.arg
        if index >= defaults_start:
            value += "=<default>"
        rendered.append(value)
        if arguments.posonlyargs and index + 1 == len(arguments.posonlyargs):
            rendered.append("/")
    if arguments.vararg is not None:
        rendered.append(f"*{arguments.vararg.arg}")
    elif arguments.kwonlyargs:
        rendered.append("*")
    for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
        value = argument.arg
        if default is not None:
            value += "=<default>"
        rendered.append(value)
    if arguments.kwarg is not None:
        rendered.append(f"**{arguments.kwarg.arg}")
    return f"({', '.join(rendered)})"


def _first_parameter(arguments: ast.arguments) -> str | None:
    positional = [*arguments.posonlyargs, *arguments.args]
    return positional[0].arg if positional else None


class _Extractor:
    def __init__(self, module_name: str, file: SourceFileRecord, tree: ast.Module) -> None:
        self.module_name = module_name
        self.file = file
        self.tree = tree
        self.symbols: list[SymbolRecord] = []
        self.scopes: dict[SymbolId, ScopeInfo] = {}
        self.imports: list[RawImport] = []
        self.calls: list[RawCall] = []
        self.references: list[SourceReferenceRecord] = []
        self.bindings: list[ModuleBinding] = []
        self.framework_assignments: list[RawFrameworkAssignment] = []
        self.routes: list[RawRoute] = []
        self.router_includes: list[RawRouterInclude] = []
        self._ordinals: dict[tuple[str, SymbolKind], int] = defaultdict(int)

    def extract(self) -> ModuleAnalysis:
        module_location = _location(self.file.path, self.tree)
        module_symbol = self._new_symbol(
            qualified_name=self.module_name,
            kind=SymbolKind.MODULE,
            signature="",
            location=module_location,
        )
        self.scopes[module_symbol.symbol_id] = ScopeInfo(
            symbol=module_symbol,
            parent_symbol_id=None,
            enclosing_class_symbol_id=None,
        )
        for statement in self.tree.body:
            self._record_direct_module_binding(statement)
            _NodeCollector(self, module_symbol.symbol_id).visit(statement)
        return ModuleAnalysis(
            module_name=self.module_name,
            file=self.file,
            symbols=tuple(self.symbols),
            scopes=self.scopes,
            imports=tuple(self.imports),
            calls=tuple(self.calls),
            references=tuple(self.references),
            bindings=tuple(self.bindings),
            framework_assignments=tuple(self.framework_assignments),
            routes=tuple(self.routes),
            router_includes=tuple(self.router_includes),
        )

    def _new_symbol(
        self,
        *,
        qualified_name: str,
        kind: SymbolKind,
        signature: str,
        location: SourceLocation,
    ) -> SymbolRecord:
        key = (qualified_name, kind)
        ordinal = self._ordinals[key]
        self._ordinals[key] += 1
        record = SymbolRecord(
            symbol_id=symbol_id(self.file.file_id, qualified_name, kind.value, ordinal),
            source_file_id=self.file.file_id,
            qualified_name=qualified_name,
            kind=kind,
            signature=signature,
            definition_ordinal=ordinal,
            source_location=location,
        )
        self.symbols.append(record)
        return record

    def _qualified_child(self, owner: SymbolRecord, name: str) -> str:
        if owner.kind in {
            SymbolKind.FUNCTION,
            SymbolKind.ASYNC_FUNCTION,
            SymbolKind.METHOD,
            SymbolKind.ASYNC_METHOD,
        }:
            return f"{owner.qualified_name}.<locals>.{name}"
        return f"{owner.qualified_name}.{name}"

    def process_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        owner_symbol_id: SymbolId,
    ) -> None:
        owner_scope = self.scopes[owner_symbol_id]
        owner = owner_scope.symbol
        in_class = owner.kind == SymbolKind.CLASS
        if isinstance(node, ast.AsyncFunctionDef):
            kind = SymbolKind.ASYNC_METHOD if in_class else SymbolKind.ASYNC_FUNCTION
        else:
            kind = SymbolKind.METHOD if in_class else SymbolKind.FUNCTION
        symbol = self._new_symbol(
            qualified_name=self._qualified_child(owner, node.name),
            kind=kind,
            signature=_safe_signature(node.args),
            location=_location(self.file.path, node),
        )
        owner_scope.definitions[node.name].append(symbol.symbol_id)
        enclosing_class = owner.symbol_id if in_class else owner_scope.enclosing_class_symbol_id
        scope = ScopeInfo(
            symbol=symbol,
            parent_symbol_id=owner_symbol_id,
            enclosing_class_symbol_id=enclosing_class,
            first_parameter=_first_parameter(node.args),
        )
        for argument in [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]:
            scope.writes.add(argument.arg)
        if node.args.vararg is not None:
            scope.writes.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            scope.writes.add(node.args.kwarg.arg)
        self.scopes[symbol.symbol_id] = scope

        for decorator in node.decorator_list:
            self._record_route(decorator, symbol.symbol_id)
            _NodeCollector(self, owner_symbol_id).visit(decorator)
        for expression in [*node.args.defaults, *node.args.kw_defaults]:
            if expression is not None:
                _NodeCollector(self, owner_symbol_id).visit(expression)
        for statement in node.body:
            _NodeCollector(self, symbol.symbol_id).visit(statement)

    def process_class(self, node: ast.ClassDef, owner_symbol_id: SymbolId) -> None:
        owner_scope = self.scopes[owner_symbol_id]
        owner = owner_scope.symbol
        symbol = self._new_symbol(
            qualified_name=self._qualified_child(owner, node.name),
            kind=SymbolKind.CLASS,
            signature="",
            location=_location(self.file.path, node),
        )
        owner_scope.definitions[node.name].append(symbol.symbol_id)
        self.scopes[symbol.symbol_id] = ScopeInfo(
            symbol=symbol,
            parent_symbol_id=owner_symbol_id,
            enclosing_class_symbol_id=symbol.symbol_id,
        )
        expressions = [
            *node.decorator_list,
            *node.bases,
            *[item.value for item in node.keywords],
        ]
        for expression in expressions:
            _NodeCollector(self, owner_symbol_id).visit(expression)
        for statement in node.body:
            _NodeCollector(self, symbol.symbol_id).visit(statement)

    def record_import(self, node: ast.Import | ast.ImportFrom, owner_symbol_id: SymbolId) -> None:
        owner_scope = self.scopes[owner_symbol_id]
        location = _location(self.file.path, node)
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                owner_scope.writes.add(local_name)
                self.imports.append(
                    RawImport(
                        owner_symbol_id=owner_symbol_id,
                        module_name=alias.name,
                        level=0,
                        imported_name=None,
                        local_name=local_name,
                        syntactic_reference=alias.name,
                        location=location,
                    )
                )
                self.references.append(
                    SourceReferenceRecord(
                        kind=SourceReferenceKind.IMPORT,
                        value=alias.name,
                        source_location=location,
                    )
                )
        else:
            module = node.module or ""
            prefix = "." * node.level
            for alias in node.names:
                imported_name = alias.name
                syntactic = f"{prefix}{module}"
                if module:
                    syntactic += f".{imported_name}"
                else:
                    syntactic += imported_name
                bound_name = None if imported_name == "*" else alias.asname or imported_name
                if bound_name is not None:
                    owner_scope.writes.add(bound_name)
                self.imports.append(
                    RawImport(
                        owner_symbol_id=owner_symbol_id,
                        module_name=module,
                        level=node.level,
                        imported_name=imported_name,
                        local_name=bound_name,
                        syntactic_reference=syntactic,
                        location=location,
                    )
                )
                reference_value = ".".join(part for part in (module, imported_name) if part)
                if reference_value and imported_name != "*":
                    self.references.append(
                        SourceReferenceRecord(
                            kind=SourceReferenceKind.IMPORT,
                            value=reference_value,
                            source_location=location,
                        )
                    )

    def record_call(self, node: ast.Call, owner_symbol_id: SymbolId) -> None:
        reference = _reference(node.func) or (
            "<subscript-call>" if isinstance(node.func, ast.Subscript) else "<dynamic-call>"
        )
        location = _location(self.file.path, node)
        self.calls.append(
            RawCall(
                caller_symbol_id=owner_symbol_id,
                reference=reference,
                location=location,
            )
        )
        if isinstance(node.func, ast.Attribute) and node.func.attr == "include_router":
            parent = _reference(node.func.value)
            router = _reference(node.args[0]) if node.args else None
            prefix_node = next((item.value for item in node.keywords if item.arg == "prefix"), None)
            prefix_value, prefix_reference, prefix_dynamic = _string_or_name(prefix_node)
            if parent is not None:
                self.router_includes.append(
                    RawRouterInclude(
                        owner_symbol_id=owner_symbol_id,
                        parent_reference=parent,
                        router_reference=router,
                        prefix_value=prefix_value if prefix_node is not None else "",
                        prefix_reference=prefix_reference,
                        prefix_dynamic=prefix_dynamic,
                        position=(location.line_start, location.column_start),
                        location=location,
                    )
                )

    def record_attribute(self, node: ast.Attribute) -> None:
        reference = _reference(node)
        if reference is not None and len(reference) <= 256:
            self.references.append(
                SourceReferenceRecord(
                    kind=SourceReferenceKind.ATTRIBUTE,
                    value=reference,
                    source_location=_location(self.file.path, node),
                )
            )

    def record_name(self, node: ast.Name, owner_symbol_id: SymbolId) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.scopes[owner_symbol_id].writes.add(node.id)
        payment = source_reference_for_payment_identifier(
            node.id,
            _location(self.file.path, node),
        )
        if payment is not None:
            self.references.append(payment)

    def record_constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            payment = source_reference_for_payment_literal(
                node.value,
                _location(self.file.path, node),
            )
            if payment is not None:
                self.references.append(payment)

    def record_nested_module_write(
        self,
        node: ast.Assign | ast.AnnAssign,
        owner_symbol_id: SymbolId,
    ) -> None:
        if self.scopes[owner_symbol_id].symbol.kind != SymbolKind.MODULE:
            return
        if isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        else:
            names = [node.target.id] if isinstance(node.target, ast.Name) else []
        if not names:
            return
        location = _location(self.file.path, node)
        position = (location.line_start, location.column_start)
        for name in names:
            already_recorded = any(
                item.name == name and item.position == position for item in self.bindings
            )
            if not already_recorded:
                self.bindings.append(
                    ModuleBinding(
                        name=name,
                        reference=None,
                        string_value=None,
                        call_reference=None,
                        dynamic=True,
                        position=position,
                        location=location,
                    )
                )

    def _record_direct_module_binding(self, node: ast.stmt) -> None:
        module_symbol_id = self.symbols[0].symbol_id
        names: list[str] = []
        value: ast.AST | None = None
        simple_framework_target = False
        if isinstance(node, ast.Assign):
            value = node.value
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            simple_framework_target = len(node.targets) == 1 and len(names) == 1
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            value = node.value
            names = [node.target.id]
            simple_framework_target = True
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        if not names:
            return
        location = _location(self.file.path, node)
        for name in names:
            reference = _reference(value)
            string_value = (
                value.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str)
                else None
            )
            call_reference = _reference(value.func) if isinstance(value, ast.Call) else None
            dynamic = (
                value is not None
                and reference is None
                and string_value is None
                and call_reference is None
            )
            self.bindings.append(
                ModuleBinding(
                    name=name,
                    reference=reference,
                    string_value=string_value,
                    call_reference=call_reference,
                    dynamic=dynamic,
                    position=(location.line_start, location.column_start),
                    location=location,
                )
            )
            if (
                simple_framework_target
                and isinstance(value, ast.Call)
                and call_reference is not None
            ):
                prefix_node = next(
                    (item.value for item in value.keywords if item.arg == "prefix"),
                    None,
                )
                prefix_value, prefix_reference, prefix_dynamic = _string_or_name(prefix_node)
                self.framework_assignments.append(
                    RawFrameworkAssignment(
                        binding_name=name,
                        constructor_reference=call_reference,
                        prefix_value=prefix_value if prefix_node is not None else "",
                        prefix_reference=prefix_reference,
                        prefix_dynamic=prefix_dynamic,
                        position=(location.line_start, location.column_start),
                        location=location,
                    )
                )
        self.scopes[module_symbol_id].writes.update(names)

    def _record_route(self, decorator: ast.expr, owner_symbol_id: SymbolId) -> None:
        if not isinstance(decorator, ast.Call):
            return
        if isinstance(decorator.func, ast.Attribute):
            method = decorator.func.attr
            if method not in _ROUTE_METHODS:
                return
            registrar = _reference(decorator.func.value)
            if registrar is None:
                return
        elif isinstance(decorator.func, ast.Name):
            method = "<alias>"
            registrar = decorator.func.id
        else:
            return
        path_node = (
            decorator.args[0]
            if decorator.args
            else next(
                (item.value for item in decorator.keywords if item.arg == "path"),
                None,
            )
        )
        path_value, path_reference, _ = _string_or_name(path_node)
        methods: tuple[str, ...] | None = None
        methods_dynamic = False
        if method == "api_route":
            methods_node = next(
                (item.value for item in decorator.keywords if item.arg == "methods"),
                None,
            )
            if isinstance(methods_node, (ast.List, ast.Tuple, ast.Set)) and all(
                isinstance(item, ast.Constant) and isinstance(item.value, str)
                for item in methods_node.elts
            ):
                literal_methods: list[str] = []
                for item in methods_node.elts:
                    if isinstance(item, ast.Constant) and isinstance(item.value, str):
                        literal_methods.append(item.value)
                methods = tuple(literal_methods)
            else:
                methods_dynamic = True
        location = _location(self.file.path, decorator)
        self.routes.append(
            RawRoute(
                owner_symbol_id=owner_symbol_id,
                registrar_reference=registrar,
                decorator_method=method,
                path_value=path_value,
                path_reference=path_reference,
                methods=methods,
                methods_dynamic=methods_dynamic,
                position=(location.line_start, location.column_start),
                location=location,
            )
        )


class _NodeCollector(ast.NodeVisitor):
    def __init__(self, extractor: _Extractor, owner_symbol_id: SymbolId) -> None:
        self.extractor = extractor
        self.owner_symbol_id = owner_symbol_id
        self._inside_attribute = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.extractor.process_function(node, self.owner_symbol_id)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.extractor.process_function(node, self.owner_symbol_id)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.extractor.process_class(node, self.owner_symbol_id)

    def visit_Import(self, node: ast.Import) -> None:
        self.extractor.record_import(node, self.owner_symbol_id)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.extractor.record_import(node, self.owner_symbol_id)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.extractor.record_nested_module_write(node, self.owner_symbol_id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.extractor.record_nested_module_write(node, self.owner_symbol_id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self.extractor.record_call(node, self.owner_symbol_id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        outermost = not self._inside_attribute
        if outermost:
            self.extractor.record_attribute(node)
        previous = self._inside_attribute
        self._inside_attribute = True
        self.generic_visit(node)
        self._inside_attribute = previous

    def visit_Name(self, node: ast.Name) -> None:
        self.extractor.record_name(node, self.owner_symbol_id)

    def visit_Constant(self, node: ast.Constant) -> None:
        self.extractor.record_constant(node)


def analyze_module(
    *,
    file: SourceFileRecord,
    source_root_relative_path: str,
    source: str,
) -> ModuleAnalysis:
    tree = ast.parse(
        source,
        filename=file.path,
        mode="exec",
        type_comments=True,
        feature_version=(3, 11),
    )
    return _Extractor(module_name_for(source_root_relative_path), file, tree).extract()
