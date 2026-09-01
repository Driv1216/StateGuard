from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .schemas import CallEdge, RouteInfo, SourceBundle, SourceFile, SymbolInfo


PREDICATE_ORACLE_NAMES = {"can_enter_event", "can_open_workspace", "may_launch_product"}


def _module_name(logical_path: str) -> str:
    return logical_path.removesuffix(".py").replace("/", ".")


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    arguments = [arg.arg for arg in node.args.args]
    return f"({', '.join(arguments)})"


def _literal_state(test: ast.AST) -> str | None:
    literals = {
        value.value
        for value in ast.walk(test)
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    }
    if "payment.captured" in literals:
        return "captured"
    if "payment.authorized" in literals:
        return "authorized"
    return None


@dataclass
class _FunctionContext:
    qualified_name: str
    payment_states: list[str | None]


class _Indexer(ast.NodeVisitor):
    def __init__(self, module: str, path: str) -> None:
        self.module = module
        self.path = path
        self.symbols: list[SymbolInfo] = []
        self.edges: list[CallEdge] = []
        self.routes: list[RouteInfo] = []
        self.imports: set[str] = set()
        self.payment_literals: set[str] = set()
        self.module_aliases: dict[str, str] = {}
        self.local_functions: set[str] = set()
        self.class_stack: list[str] = []
        self.context_stack: list[_FunctionContext] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.module_aliases[local] = alias.name
            self.imports.add(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = node.module or ""
        if node.level and base:
            prefix = self.module.rsplit(".", node.level)[0]
            base = f"{prefix}.{base}" if prefix else base
        elif node.level:
            base = self.module.rsplit(".", node.level)[0]
        for alias in node.names:
            local = alias.asname or alias.name
            resolved = f"{base}.{alias.name}" if base else alias.name
            self.module_aliases[local] = resolved
            self.imports.add(resolved)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, async_: bool) -> None:
        parts = [self.module, *self.class_stack, node.name]
        qualified = ".".join(parts)
        kind = ("async_" if async_ else "") + ("method" if self.class_stack else "function")
        self.symbols.append(SymbolInfo(
            qualified_name=qualified,
            kind=kind,
            path=self.path,
            signature=_signature(node),
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
        ))
        self.local_functions.add(node.name)
        self._detect_route(qualified, node)
        self.context_stack.append(_FunctionContext(qualified, []))
        self.generic_visit(node)
        self.context_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, True)

    def _detect_route(self, qualified: str, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            method = decorator.func.attr.lower()
            if method not in {"post", "get", "put", "patch", "delete", "route", "api_route"}:
                continue
            path = ""
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                path = str(decorator.args[0].value)
            self.routes.append(RouteInfo(symbol=qualified, method=method.upper(), path=path))

    def visit_If(self, node: ast.If) -> None:
        state = _literal_state(node.test)
        if self.context_stack:
            self.context_stack[-1].payment_states.append(state)
        self.visit(node.test)
        for item in node.body:
            self.visit(item)
        if self.context_stack:
            self.context_stack[-1].payment_states.pop()
        for item in node.orelse:
            self.visit(item)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and node.value in {"payment.captured", "payment.authorized"}:
            self.payment_literals.add(node.value)

    def _resolve_call(self, node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in self.module_aliases:
                return self.module_aliases[func.id]
            return f"{self.module}.{func.id}"
        if isinstance(func, ast.Attribute):
            segments: list[str] = [func.attr]
            current = func.value
            while isinstance(current, ast.Attribute):
                segments.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                root = current.id
                base = self.module_aliases.get(root, root)
                return ".".join([base, *reversed(segments)])
        return None

    def visit_Call(self, node: ast.Call) -> None:
        if self.context_stack:
            callee = self._resolve_call(node)
            if callee:
                states = [state for state in self.context_stack[-1].payment_states if state]
                self.edges.append(CallEdge(
                    caller=self.context_stack[-1].qualified_name,
                    callee=callee,
                    payment_state=states[-1] if states else None,
                    line=node.lineno,
                ))
        self.generic_visit(node)


def build_source_bundle(application_id: str, source_root: Path) -> SourceBundle:
    app_root = source_root / "app"
    files: list[SourceFile] = []
    symbols: list[SymbolInfo] = []
    edges: list[CallEdge] = []
    routes: list[RouteInfo] = []
    payment_literals: set[str] = set()
    imports: set[str] = set()
    for path in sorted(app_root.rglob("*.py")):
        logical = path.relative_to(source_root).as_posix()
        content = path.read_text(encoding="utf-8")
        if any(name in content for name in PREDICATE_ORACLE_NAMES):
            raise ValueError(f"business-value predicate leaked into mapper source: {logical}")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        files.append(SourceFile(logical_path=logical, content=content, sha256=digest))
        indexer = _Indexer(_module_name(logical), logical)
        indexer.visit(ast.parse(content, filename=logical))
        symbols.extend(indexer.symbols)
        edges.extend(indexer.edges)
        routes.extend(indexer.routes)
        payment_literals.update(indexer.payment_literals)
        imports.update(indexer.imports)
    return SourceBundle(
        application_id=application_id,
        files=files,
        symbols=sorted(symbols, key=lambda item: item.qualified_name),
        call_edges=sorted(edges, key=lambda item: (item.caller, item.line, item.callee)),
        routes=sorted(routes, key=lambda item: item.symbol),
        payment_literals=sorted(payment_literals),
        imports=sorted(imports),
    )


def identifier_tokens(symbol: str) -> set[str]:
    tail = symbol.rsplit(".", 1)[-1]
    expanded = re.sub(r"([a-z])([A-Z])", r"\1_\2", tail)
    return {token.casefold() for token in expanded.split("_") if token}

