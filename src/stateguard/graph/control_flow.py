"""Transient bounded Python control and payment-origin analysis for graph construction."""

from __future__ import annotations

import ast
import io
import tokenize
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from stateguard.contracts.common import SourceLocation, SymbolId
from stateguard.contracts.identity import sha256_digest, structural_anchor
from stateguard.discovery.contracts import SourceIndexArtifact, SymbolKind, SymbolRecord
from stateguard.discovery.service import StaleSourceIndexError
from stateguard.graph.contracts import BranchDisposition


class ValueOrigin(StrEnum):
    RAW_WEBHOOK_BODY = "RAW_WEBHOOK_BODY"
    PARSED_WEBHOOK_BODY = "PARSED_WEBHOOK_BODY"
    WEBHOOK_SIGNATURE = "WEBHOOK_SIGNATURE"
    WEBHOOK_EVENT_ID = "WEBHOOK_EVENT_ID"
    PAYMENT_EVENT_SELECTOR = "PAYMENT_EVENT_SELECTOR"
    CHECKOUT_PAYMENT_ID = "CHECKOUT_PAYMENT_ID"
    CLIENT_RETURNED_ORDER_ID = "CLIENT_RETURNED_ORDER_ID"
    CHECKOUT_SIGNATURE = "CHECKOUT_SIGNATURE"
    SERVER_CONFIRMED_ORDER_ID = "SERVER_CONFIRMED_ORDER_ID"
    MERCHANT_STATE_CARRIER = "MERCHANT_STATE_CARRIER"
    UNCONFIRMED_MERCHANT_STATE = "UNCONFIRMED_MERCHANT_STATE"
    UNKNOWN = "UNKNOWN"


class ExceptionRegionKind(StrEnum):
    TRY_BODY = "TRY_BODY"
    EXCEPT_HANDLER = "EXCEPT_HANDLER"
    TRY_ELSE = "TRY_ELSE"
    FINALLY = "FINALLY"


class SdkBindingState(StrEnum):
    RAZORPAY_CLIENT = "RAZORPAY_CLIENT"
    NOT_RAZORPAY_CLIENT = "NOT_RAZORPAY_CLIENT"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True)
class BranchContext:
    gate_anchor: str
    disposition: BranchDisposition


@dataclass(frozen=True)
class ExceptionRegion:
    try_anchor: str
    kind: ExceptionRegionKind
    handler_index: int | None
    handlers_allow_continuation: bool
    handlers_may_return: bool
    finally_terminates: bool
    finally_may_return: bool


@dataclass(frozen=True)
class StatementContext:
    symbol_id: SymbolId
    node: ast.stmt
    anchor: str
    ordinal: int
    ancestors: tuple[BranchContext, ...]
    exception_regions: tuple[ExceptionRegion, ...] = ()
    in_loop: bool = False

    @property
    def location_tuple(self) -> tuple[int, int]:
        return (
            max(getattr(self.node, "lineno", 1), 1),
            max(getattr(self.node, "col_offset", 0), 0),
        )


@dataclass(frozen=True)
class ModuleControlModel:
    path: str
    tree: ast.Module
    sdk_bindings: dict[str, SdkBindingState]
    module_state_names: frozenset[str]


@dataclass(frozen=True)
class FunctionControlModel:
    symbol: SymbolRecord
    function: ast.FunctionDef | ast.AsyncFunctionDef
    module: ModuleControlModel
    statements: tuple[StatementContext, ...]
    name_origins: dict[str, ValueOrigin]
    unsupported_exception_flow: bool = False

    def context_for(self, node: ast.AST) -> StatementContext | None:
        containing = [
            item
            for item in self.statements
            if item.node is node or any(child is node for child in ast.walk(item.node))
        ]
        return containing[-1] if containing else None


@dataclass(frozen=True)
class ParsedProject:
    functions: dict[SymbolId, FunctionControlModel]
    modules_by_path: dict[str, ModuleControlModel]


def source_location(path: str, node: ast.AST) -> SourceLocation:
    line = max(getattr(node, "lineno", 1), 1)
    column = max(getattr(node, "col_offset", 0), 0)
    end_line = max(getattr(node, "end_lineno", line) or line, line)
    end_column = max(getattr(node, "end_col_offset", column) or column, column)
    return SourceLocation(
        path=path,
        line_start=line,
        column_start=column,
        line_end=end_line,
        column_end=end_column,
    )


def reference_for(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = reference_for(node.value)
        return f"{parent}.{node.attr}" if parent is not None else None
    return None


def string_key(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.strip().casefold()
    return None


def _decode_python(raw_bytes: bytes) -> str:
    encoding, _ = tokenize.detect_encoding(io.BytesIO(raw_bytes).readline)
    return raw_bytes.decode(encoding, errors="strict")


def _assigned_names(node: ast.AST) -> set[str]:
    targets: list[ast.AST] = []
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        if isinstance(node, ast.Assign):
            targets.extend(node.targets)
        else:
            targets.append(node.target)
    result: set[str] = set()
    for target in targets:
        for item in ast.walk(target):
            if isinstance(item, ast.Name):
                result.add(item.id)
    return result


def _module_properties(
    tree: ast.Module,
) -> tuple[dict[str, SdkBindingState], frozenset[str]]:
    razorpay_modules: set[str] = set()
    client_constructors: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name == "razorpay":
                    razorpay_modules.add(alias.asname or "razorpay")
        elif isinstance(statement, ast.ImportFrom) and statement.module == "razorpay":
            for alias in statement.names:
                if alias.name == "Client":
                    client_constructors.add(alias.asname or alias.name)

    sdk_bindings: dict[str, SdkBindingState] = {}
    module_state: set[str] = set()
    for statement in tree.body:
        targets: list[ast.expr] = []
        value: ast.AST | None = None
        if isinstance(statement, ast.Assign):
            targets = list(statement.targets)
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
            value = statement.value
        names = [target.id for target in targets if isinstance(target, ast.Name)]
        if isinstance(value, (ast.Dict, ast.Set, ast.List, ast.Tuple)) or (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id in {"dict", "set", "list"}
        ):
            module_state.update(names)
        if names:
            constructor = reference_for(value.func) if isinstance(value, ast.Call) else None
            state = (
                SdkBindingState.RAZORPAY_CLIENT
                if constructor in client_constructors
                or any(constructor == f"{module}.Client" for module in razorpay_modules)
                else SdkBindingState.NOT_RAZORPAY_CLIENT
            )
            for name in names:
                sdk_bindings[name] = state

        if isinstance(statement, (ast.If, ast.Match, ast.Try, ast.TryStar, ast.For, ast.While)):
            for nested in ast.walk(statement):
                for name in _assigned_names(nested):
                    sdk_bindings[name] = SdkBindingState.AMBIGUOUS
    return sdk_bindings, frozenset(module_state)


def _statement_shape(node: ast.stmt) -> str:
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def block_terminates(statements: list[ast.stmt]) -> bool:
    if not statements:
        return False
    last = statements[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If):
        return block_terminates(last.body) and block_terminates(last.orelse)
    if isinstance(last, ast.Match):
        has_default = any(
            isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None
            for case in last.cases
        )
        return has_default and all(block_terminates(case.body) for case in last.cases)
    if isinstance(last, (ast.Try, ast.TryStar)):
        if block_terminates(last.finalbody):
            return True
        normal_path = block_terminates(last.orelse) if last.orelse else block_terminates(last.body)
        return normal_path and all(block_terminates(handler.body) for handler in last.handlers)
    return False


def _may_return(statements: list[ast.stmt]) -> bool:
    return any(
        isinstance(item, ast.Return) for statement in statements for item in ast.walk(statement)
    )


def _exception_region(
    *,
    try_anchor: str,
    kind: ExceptionRegionKind,
    handler_index: int | None,
    handlers_allow_continuation: bool,
    handlers_may_return: bool,
    finally_terminates: bool,
    finally_may_return: bool,
) -> ExceptionRegion:
    return ExceptionRegion(
        try_anchor=try_anchor,
        kind=kind,
        handler_index=handler_index,
        handlers_allow_continuation=handlers_allow_continuation,
        handlers_may_return=handlers_may_return,
        finally_terminates=finally_terminates,
        finally_may_return=finally_may_return,
    )


def _collect_statements(
    symbol_id: SymbolId,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[StatementContext, ...]:
    result: list[StatementContext] = []
    shape_counts: dict[str, int] = defaultdict(int)

    def visit_block(
        statements: list[ast.stmt],
        ancestors: tuple[BranchContext, ...],
        *,
        exception_regions: tuple[ExceptionRegion, ...] = (),
        in_loop: bool = False,
    ) -> None:
        for node in statements:
            shape = _statement_shape(node)
            ordinal = shape_counts[shape]
            shape_counts[shape] += 1
            anchor = structural_anchor(symbol_id, type(node).__name__, shape, ordinal)
            context = StatementContext(
                symbol_id=symbol_id,
                node=node,
                anchor=anchor,
                ordinal=ordinal,
                ancestors=ancestors,
                exception_regions=exception_regions,
                in_loop=in_loop,
            )
            result.append(context)
            if isinstance(node, ast.If):
                visit_block(
                    node.body,
                    (*ancestors, BranchContext(anchor, BranchDisposition.MATCHED)),
                    exception_regions=exception_regions,
                    in_loop=in_loop,
                )
                visit_block(
                    node.orelse,
                    (*ancestors, BranchContext(anchor, BranchDisposition.NOT_MATCHED)),
                    exception_regions=exception_regions,
                    in_loop=in_loop,
                )
            elif isinstance(node, ast.Match):
                for case in node.cases:
                    disposition = (
                        BranchDisposition.DEFAULT
                        if isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None
                        else BranchDisposition.MATCHED
                    )
                    visit_block(
                        case.body,
                        (*ancestors, BranchContext(anchor, disposition)),
                        exception_regions=exception_regions,
                        in_loop=in_loop,
                    )
            elif isinstance(node, ast.Try):
                handlers_allow_continuation = any(
                    not block_terminates(handler.body) for handler in node.handlers
                )
                handlers_may_return = any(_may_return(handler.body) for handler in node.handlers)
                finally_terminates = block_terminates(node.finalbody)
                finally_may_return = _may_return(node.finalbody)

                def region(
                    kind: ExceptionRegionKind,
                    handler_index: int | None = None,
                    *,
                    try_anchor: str = anchor,
                    handlers_continue: bool = handlers_allow_continuation,
                    handlers_return: bool = handlers_may_return,
                    final_terminates: bool = finally_terminates,
                    final_returns: bool = finally_may_return,
                ) -> ExceptionRegion:
                    return _exception_region(
                        try_anchor=try_anchor,
                        kind=kind,
                        handler_index=handler_index,
                        handlers_allow_continuation=handlers_continue,
                        handlers_may_return=handlers_return,
                        finally_terminates=final_terminates,
                        finally_may_return=final_returns,
                    )

                visit_block(
                    node.body,
                    ancestors,
                    exception_regions=(*exception_regions, region(ExceptionRegionKind.TRY_BODY)),
                    in_loop=in_loop,
                )
                for index, handler in enumerate(node.handlers):
                    visit_block(
                        handler.body,
                        ancestors,
                        exception_regions=(
                            *exception_regions,
                            region(ExceptionRegionKind.EXCEPT_HANDLER, index),
                        ),
                        in_loop=in_loop,
                    )
                visit_block(
                    node.orelse,
                    ancestors,
                    exception_regions=(*exception_regions, region(ExceptionRegionKind.TRY_ELSE)),
                    in_loop=in_loop,
                )
                visit_block(
                    node.finalbody,
                    ancestors,
                    exception_regions=(*exception_regions, region(ExceptionRegionKind.FINALLY)),
                    in_loop=in_loop,
                )
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                visit_block(
                    node.body,
                    ancestors,
                    exception_regions=exception_regions,
                    in_loop=True,
                )
                visit_block(
                    node.orelse,
                    ancestors,
                    exception_regions=exception_regions,
                    in_loop=in_loop,
                )
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                visit_block(
                    node.body,
                    ancestors,
                    exception_regions=exception_regions,
                    in_loop=in_loop,
                )

    visit_block(function.body, ())
    return tuple(result)


def _root_name(node: ast.AST | None) -> str | None:
    current = node
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _origin_for_expr(
    expression: ast.AST | None,
    origins: dict[str, ValueOrigin],
    module_state_names: frozenset[str],
) -> ValueOrigin:
    if expression is None:
        return ValueOrigin.UNKNOWN
    if isinstance(expression, ast.Await):
        return _origin_for_expr(expression.value, origins, module_state_names)
    if isinstance(expression, ast.Name):
        return origins.get(expression.id, ValueOrigin.UNKNOWN)
    if isinstance(expression, ast.Call):
        reference = reference_for(expression.func) or ""
        if reference.endswith(".body"):
            return ValueOrigin.RAW_WEBHOOK_BODY
        if reference.endswith(".json"):
            return ValueOrigin.PARSED_WEBHOOK_BODY
        if reference.endswith(".decode"):
            return _origin_for_expr(
                expression.func.value if isinstance(expression.func, ast.Attribute) else None,
                origins,
                module_state_names,
            )
        return ValueOrigin.UNKNOWN
    if isinstance(expression, (ast.Subscript, ast.Attribute)):
        key = (
            string_key(expression.slice)
            if isinstance(expression, ast.Subscript)
            else expression.attr.casefold()
        )
        root = _root_name(expression)
        base_origin = _origin_for_expr(expression.value, origins, module_state_names)
        key_origin = (
            _origin_for_expr(expression.slice, origins, module_state_names)
            if isinstance(expression, ast.Subscript)
            else ValueOrigin.UNKNOWN
        )
        if key == "x-razorpay-signature":
            return ValueOrigin.WEBHOOK_SIGNATURE
        if key == "x-razorpay-event-id":
            return ValueOrigin.WEBHOOK_EVENT_ID
        if key == "razorpay_payment_id":
            return ValueOrigin.CHECKOUT_PAYMENT_ID
        if key == "razorpay_signature":
            return ValueOrigin.CHECKOUT_SIGNATURE
        if key == "razorpay_order_id":
            if base_origin == ValueOrigin.MERCHANT_STATE_CARRIER:
                return ValueOrigin.SERVER_CONFIRMED_ORDER_ID
            if base_origin == ValueOrigin.UNCONFIRMED_MERCHANT_STATE:
                return ValueOrigin.UNKNOWN
            if root in module_state_names:
                return ValueOrigin.UNKNOWN
            return ValueOrigin.CLIENT_RETURNED_ORDER_ID
        if key in {"event", "status"}:
            return ValueOrigin.PAYMENT_EVENT_SELECTOR
        if base_origin != ValueOrigin.UNKNOWN:
            return base_origin
        if root in module_state_names and isinstance(expression, ast.Subscript):
            if isinstance(expression.slice, ast.Constant) or key_origin in {
                ValueOrigin.MERCHANT_STATE_CARRIER,
                ValueOrigin.SERVER_CONFIRMED_ORDER_ID,
            }:
                return ValueOrigin.MERCHANT_STATE_CARRIER
            return ValueOrigin.UNCONFIRMED_MERCHANT_STATE
    return ValueOrigin.UNKNOWN


def expression_origin(expression: ast.AST | None, model: FunctionControlModel) -> ValueOrigin:
    """Classify a bounded expression using one function's transient origin facts."""

    return _origin_for_expr(expression, model.name_origins, model.module.module_state_names)


def _infer_origins(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    module_state_names: frozenset[str],
) -> dict[str, ValueOrigin]:
    origins: dict[str, ValueOrigin] = {}
    arguments = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
    for argument in arguments:
        normalized = argument.arg.casefold()
        if normalized == "razorpay_payment_id":
            origins[argument.arg] = ValueOrigin.CHECKOUT_PAYMENT_ID
        elif normalized == "razorpay_order_id":
            origins[argument.arg] = ValueOrigin.CLIENT_RETURNED_ORDER_ID
        elif normalized == "razorpay_signature":
            origins[argument.arg] = ValueOrigin.CHECKOUT_SIGNATURE

    for _ in range(4):
        changed = False
        for node in ast.walk(function):
            targets: list[ast.expr] = []
            value: ast.AST | None = None
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
                value = node.value
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
                value = node.value
            elif isinstance(node, ast.NamedExpr):
                targets = [node.target]
                value = node.value
            if value is None:
                continue
            origin = _origin_for_expr(value, origins, module_state_names)
            for target in targets:
                if isinstance(target, ast.Name) and origins.get(target.id) != origin:
                    origins[target.id] = origin
                    changed = True
        if not changed:
            break
    return origins


def parse_indexed_functions(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    symbol_ids: set[SymbolId],
) -> ParsedProject:
    symbols = {
        item.symbol_id: item
        for item in source_index.symbols
        if item.symbol_id in symbol_ids
        and item.kind
        in {
            SymbolKind.FUNCTION,
            SymbolKind.ASYNC_FUNCTION,
            SymbolKind.METHOD,
            SymbolKind.ASYNC_METHOD,
        }
    }
    paths = {item.source_location.path for item in symbols.values()}
    records_by_path = {item.path: item for item in source_index.indexed_files}
    modules_by_path: dict[str, ModuleControlModel] = {}
    functions: dict[SymbolId, FunctionControlModel] = {}
    resolved_root = repository_root.resolve(strict=True)

    for path in sorted(paths):
        record = records_by_path[path]
        candidate = resolved_root / path
        if candidate.is_symlink():
            raise StaleSourceIndexError("indexed source path is now a symlink")
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(resolved_root)
            raw_bytes = resolved.read_bytes()
        except (OSError, ValueError) as exc:
            raise StaleSourceIndexError("indexed source path is missing or unreadable") from exc
        if (
            len(raw_bytes) != record.byte_size
            or sha256_digest(raw_bytes) != record.content_fingerprint
        ):
            raise StaleSourceIndexError("indexed source bytes changed; re-indexing is required")
        try:
            tree = ast.parse(
                _decode_python(raw_bytes),
                filename=path,
                mode="exec",
                type_comments=True,
                feature_version=(3, 11),
            )
        except (LookupError, SyntaxError, UnicodeDecodeError) as exc:
            raise ValueError("fresh indexed source could not be reparsed") from exc
        sdk_bindings, module_state = _module_properties(tree)
        module = ModuleControlModel(
            path=path,
            tree=tree,
            sdk_bindings=sdk_bindings,
            module_state_names=module_state,
        )
        modules_by_path[path] = module
        ast_functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        by_position = {
            (max(node.lineno, 1), max(node.col_offset, 0)): node for node in ast_functions
        }
        for symbol in symbols.values():
            if symbol.source_location.path != path:
                continue
            function = by_position.get(
                (symbol.source_location.line_start, symbol.source_location.column_start)
            )
            if function is None:
                raise ValueError("indexed function location could not be recovered")
            functions[symbol.symbol_id] = FunctionControlModel(
                symbol=symbol,
                function=function,
                module=module,
                statements=_collect_statements(symbol.symbol_id, function),
                name_origins=_infer_origins(function, module.module_state_names),
                unsupported_exception_flow=any(
                    isinstance(item, ast.TryStar) for item in ast.walk(function)
                ),
            )
    return ParsedProject(functions=functions, modules_by_path=modules_by_path)


def context_dominates(source: StatementContext, target: StatementContext) -> bool:
    if source.symbol_id != target.symbol_id or source.location_tuple >= target.location_tuple:
        return False
    if source.ancestors != target.ancestors[: len(source.ancestors)]:
        return False
    target_regions = {item.try_anchor: item for item in target.exception_regions}
    for source_region in source.exception_regions:
        target_region = target_regions.get(source_region.try_anchor)
        if target_region is not None:
            if source_region.kind == target_region.kind:
                if (
                    source_region.kind == ExceptionRegionKind.EXCEPT_HANDLER
                    and source_region.handler_index != target_region.handler_index
                ):
                    return False
                continue
            if (
                source_region.kind == ExceptionRegionKind.TRY_BODY
                and target_region.kind == ExceptionRegionKind.TRY_ELSE
            ):
                continue
            return False
        if source_region.kind in {
            ExceptionRegionKind.TRY_BODY,
            ExceptionRegionKind.TRY_ELSE,
        }:
            if source_region.handlers_allow_continuation or source_region.finally_terminates:
                return False
        elif source_region.kind == ExceptionRegionKind.EXCEPT_HANDLER:
            return False
        elif source_region.kind == ExceptionRegionKind.FINALLY:
            if source_region.finally_terminates:
                return False
    return True


def exception_propagates_from_function(context: StatementContext) -> bool:
    """Return whether failure at this statement is proven to escape its function."""

    for region in context.exception_regions:
        if region.kind != ExceptionRegionKind.TRY_BODY:
            continue
        if (
            region.handlers_allow_continuation
            or region.handlers_may_return
            or region.finally_may_return
        ):
            return False
    return True


def exception_failure_allows_continuation(context: StatementContext) -> bool:
    """Return whether a failure here can be swallowed before later local work."""

    return any(
        region.kind == ExceptionRegionKind.TRY_BODY
        and region.handlers_allow_continuation
        and not region.finally_terminates
        for region in context.exception_regions
    )


def branch_controls(source: StatementContext, target: StatementContext) -> BranchContext | None:
    if source.symbol_id != target.symbol_id:
        return None
    return next(
        (item for item in target.ancestors if item.gate_anchor == source.anchor),
        None,
    )
