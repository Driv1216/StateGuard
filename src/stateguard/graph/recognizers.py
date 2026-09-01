"""Conservative deterministic recognizers for Step 2 payment graph concepts."""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from dataclasses import dataclass, replace

from stateguard.contracts.common import MerchantStateCarrierId, SourceLocation, SymbolId
from stateguard.contracts.identity import merchant_state_carrier_id, structural_anchor
from stateguard.discovery.contracts import CallSiteRecord, RouteRecord, SourceIndexArtifact
from stateguard.graph.contracts import (
    AcknowledgementExitKind,
    AcknowledgementOutcome,
    CheckoutFieldBinding,
    CheckoutRequestBinding,
    CheckoutRequestTransport,
    EventIdentityStrategy,
    GraphCandidateKind,
    GraphDiagnosticCode,
    GraphDiagnosticImpact,
    GraphDiagnosticReason,
    GraphDiagnosticRecord,
    MerchantMutationKind,
    OrderIdentityOrigin,
    PaymentIngressKind,
    PaymentStateOperator,
    TrustGateKind,
    WebhookBodyOrigin,
)
from stateguard.graph.control_flow import (
    FunctionControlModel,
    ParsedProject,
    SdkBindingState,
    StatementContext,
    ValueOrigin,
    block_terminates,
    context_dominates,
    exception_failure_allows_continuation,
    exception_propagates_from_function,
    expression_origin,
    reference_for,
    source_location,
    string_key,
)
from stateguard.graph.razorpay_recognizers import CHECKOUT_IDENTIFIERS, PAYMENT_EVENTS
from stateguard.graph.reachability import ReachableRoute

_MERCHANT_STATE_FIELDS = frozenset(
    {"status", "paid", "payment_id", "razorpay_payment_id", "payment_status"}
)


@dataclass(frozen=True)
class TrustFact:
    symbol_id: SymbolId
    location: SourceLocation
    context: StatementContext
    trust_kind: TrustGateKind
    webhook_body_origin: WebhookBodyOrigin | None
    order_identity_origin: OrderIdentityOrigin | None
    route_guard_context: StatementContext | None = None


@dataclass(frozen=True)
class EventIdentityFact:
    symbol_id: SymbolId
    location: SourceLocation
    context: StatementContext
    strategy: EventIdentityStrategy


@dataclass(frozen=True)
class StateGateFact:
    symbol_id: SymbolId
    location: SourceLocation
    context: StatementContext
    operator: PaymentStateOperator
    states: tuple[str, ...]


@dataclass(frozen=True)
class MutationFact:
    symbol_id: SymbolId
    location: SourceLocation
    context: StatementContext
    mutation_kind: MerchantMutationKind
    carrier_reference: MerchantStateCarrierId
    assigned_payment_state: str | None


@dataclass(frozen=True)
class AcknowledgementFact:
    symbol_id: SymbolId
    location: SourceLocation
    context: StatementContext | None
    anchor: str
    exit_kind: AcknowledgementExitKind
    status_code: int | None
    outcome: AcknowledgementOutcome


@dataclass(frozen=True)
class RouteConceptAnalysis:
    ingress_kind: PaymentIngressKind | None
    evidence_families: tuple[str, ...]
    checkout_request_binding: CheckoutRequestBinding | None
    trust: tuple[TrustFact, ...]
    event_identity: tuple[EventIdentityFact, ...]
    state_gates: tuple[StateGateFact, ...]
    mutations: tuple[MutationFact, ...]
    acknowledgements: tuple[AcknowledgementFact, ...]
    call_paths: dict[SymbolId, tuple[CallSiteRecord, ...]]
    diagnostics: tuple[GraphDiagnosticRecord, ...]


def _all_strings(node: ast.AST) -> set[str]:
    return {
        item.value.strip().casefold()
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


def _resolved_call_graph(
    source_index: SourceIndexArtifact,
) -> dict[SymbolId, tuple[CallSiteRecord, ...]]:
    grouped: dict[SymbolId, list[CallSiteRecord]] = defaultdict(list)
    for call in source_index.call_sites:
        if call.callee_symbol_id is not None:
            grouped[call.caller_symbol_id].append(call)
    return {
        symbol: tuple(
            sorted(
                calls,
                key=lambda item: (
                    item.source_location.path,
                    item.source_location.line_start,
                    item.source_location.column_start,
                ),
            )
        )
        for symbol, calls in grouped.items()
    }


def resolved_call_paths(
    source_index: SourceIndexArtifact,
    root_symbol_id: SymbolId,
    parsed: ParsedProject,
) -> dict[SymbolId, tuple[CallSiteRecord, ...]]:
    graph = _resolved_call_graph(source_index)
    paths: dict[SymbolId, tuple[CallSiteRecord, ...]] = {root_symbol_id: ()}
    pending: deque[SymbolId] = deque([root_symbol_id])
    while pending:
        current = pending.popleft()
        for call in graph.get(current, ()):
            callee = call.callee_symbol_id
            if callee is None or callee not in parsed.functions or callee in paths:
                continue
            paths[callee] = (*paths[current], call)
            pending.append(callee)
    return paths


def _call_node(model: FunctionControlModel, call_site: CallSiteRecord) -> ast.Call | None:
    return next(
        (
            node
            for node in ast.walk(model.function)
            if isinstance(node, ast.Call)
            and max(getattr(node, "lineno", 1), 1) == call_site.source_location.line_start
            and max(getattr(node, "col_offset", 0), 0) == call_site.source_location.column_start
        ),
        None,
    )


def _models_with_forwarded_origins(
    paths: dict[SymbolId, tuple[CallSiteRecord, ...]],
    parsed: ParsedProject,
) -> dict[SymbolId, FunctionControlModel]:
    models = {
        symbol: replace(model, name_origins=dict(model.name_origins))
        for symbol, model in parsed.functions.items()
        if symbol in paths
    }
    for callee_symbol, path in sorted(paths.items(), key=lambda item: len(item[1])):
        if not path:
            continue
        call_site = path[-1]
        caller = models.get(call_site.caller_symbol_id)
        callee = models.get(callee_symbol)
        if caller is None or callee is None:
            continue
        call = _call_node(caller, call_site)
        if call is None:
            continue
        parameters = [
            *callee.function.args.posonlyargs,
            *callee.function.args.args,
            *callee.function.args.kwonlyargs,
        ]
        for parameter, argument in zip(parameters, call.args, strict=False):
            origin = expression_origin(argument, caller)
            if origin != ValueOrigin.UNKNOWN:
                callee.name_origins[parameter.arg] = origin
        parameters_by_name = {parameter.arg: parameter for parameter in parameters}
        for keyword in call.keywords:
            if keyword.arg in parameters_by_name:
                origin = expression_origin(keyword.value, caller)
                if origin != ValueOrigin.UNKNOWN:
                    callee.name_origins[keyword.arg] = origin
    return models


def _call_context(
    model: FunctionControlModel,
    call_site: CallSiteRecord,
) -> StatementContext | None:
    call = _call_node(model, call_site)
    return model.context_for(call) if call is not None else None


def _route_guard_context(
    fact: TrustFact,
    path: tuple[CallSiteRecord, ...],
    models: dict[SymbolId, FunctionControlModel],
) -> StatementContext | None:
    if not path:
        return fact.context
    trust_model = models.get(fact.symbol_id)
    if trust_model is None or not exception_propagates_from_function(fact.context):
        return None
    for call_site in path[1:]:
        caller = models.get(call_site.caller_symbol_id)
        if caller is None:
            return None
        context = _call_context(caller, call_site)
        if context is None or not exception_propagates_from_function(context):
            return None
    root_caller = models.get(path[0].caller_symbol_id)
    return _call_context(root_caller, path[0]) if root_caller is not None else None


def _origin_in_expression(expression: ast.AST, model: FunctionControlModel) -> set[ValueOrigin]:
    result = {expression_origin(expression, model)}
    for item in ast.walk(expression):
        if isinstance(item, ast.Name):
            result.add(model.name_origins.get(item.id, ValueOrigin.UNKNOWN))
        elif isinstance(item, (ast.Subscript, ast.Attribute, ast.Call, ast.Await)):
            result.add(expression_origin(item, model))
    return result


def _sdk_method_kind(call: ast.Call) -> TrustGateKind | None:
    reference = reference_for(call.func) or ""
    if reference.endswith(".utility.verify_webhook_signature"):
        return TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION
    if reference.endswith(".utility.verify_payment_signature"):
        return TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION
    return None


def _function_shadows_name(model: FunctionControlModel, name: str) -> bool:
    arguments = {
        item.arg
        for item in (
            *model.function.args.posonlyargs,
            *model.function.args.args,
            *model.function.args.kwonlyargs,
        )
    }
    if name in arguments:
        return True
    return any(
        name
        in {
            item.id
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            for item in ast.walk(target)
            if isinstance(item, ast.Name)
        }
        for node in ast.walk(model.function)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr))
    )


def _sdk_binding_proven(call: ast.Call, model: FunctionControlModel) -> bool:
    reference = reference_for(call.func) or ""
    root = reference.partition(".")[0]
    return model.module.sdk_bindings.get(
        root
    ) == SdkBindingState.RAZORPAY_CLIENT and not _function_shadows_name(model, root)


def _sdk_verifier(call: ast.Call, model: FunctionControlModel) -> TrustGateKind | None:
    kind = _sdk_method_kind(call)
    return kind if kind is not None and _sdk_binding_proven(call, model) else None


def _try_swallows(function: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call) -> bool:
    for node in ast.walk(function):
        if not isinstance(node, ast.Try):
            continue
        if any(item is call for statement in node.body for item in ast.walk(statement)):
            if any(not block_terminates(handler.body) for handler in node.handlers):
                return True
    return False


def _dict_for_call_argument(
    call: ast.Call,
    model: FunctionControlModel,
) -> ast.Dict | None:
    if not call.args:
        return None
    argument = call.args[0]
    if isinstance(argument, ast.Dict):
        return argument
    if not isinstance(argument, ast.Name):
        return None
    call_line = max(getattr(call, "lineno", 1), 1)
    candidates = [
        node.value
        for node in ast.walk(model.function)
        if isinstance(node, ast.Assign)
        and max(getattr(node, "lineno", 1), 1) < call_line
        and any(
            isinstance(target, ast.Name) and target.id == argument.id for target in node.targets
        )
        and isinstance(node.value, ast.Dict)
    ]
    return candidates[-1] if candidates else None


def _checkout_origins(
    call: ast.Call,
    model: FunctionControlModel,
) -> tuple[set[ValueOrigin], OrderIdentityOrigin]:
    mapping = _dict_for_call_argument(call, model)
    observed: set[ValueOrigin] = set()
    order = OrderIdentityOrigin.UNKNOWN
    if mapping is None:
        return observed, order
    for key_node, value in zip(mapping.keys, mapping.values, strict=True):
        key = string_key(key_node)
        if key not in CHECKOUT_IDENTIFIERS:
            continue
        origin = expression_origin(value, model)
        observed.add(origin)
        if key == "razorpay_order_id":
            if origin == ValueOrigin.CLIENT_RETURNED_ORDER_ID:
                order = OrderIdentityOrigin.CLIENT_RETURNED
            elif origin == ValueOrigin.SERVER_CONFIRMED_ORDER_ID:
                order = OrderIdentityOrigin.SERVER_STATE_CONFIRMED
            else:
                order = OrderIdentityOrigin.UNKNOWN
    return observed, order


def _hmac_message(expression: ast.AST) -> ast.AST | None:
    candidate = expression
    if isinstance(candidate, ast.Call) and isinstance(candidate.func, ast.Attribute):
        if candidate.func.attr == "hexdigest":
            candidate = candidate.func.value
    if not isinstance(candidate, ast.Call):
        return None
    reference = reference_for(candidate.func)
    if reference != "hmac.new":
        return None
    digest = next((item.value for item in candidate.keywords if item.arg == "digestmod"), None)
    if digest is None and len(candidate.args) >= 3:
        digest = candidate.args[2]
    if reference_for(digest) not in {"hashlib.sha256", "sha256"}:
        return None
    message = next((item.value for item in candidate.keywords if item.arg == "msg"), None)
    if message is None and len(candidate.args) >= 2:
        message = candidate.args[1]
    return message


def _direct_hmac_fact(
    context: StatementContext,
    model: FunctionControlModel,
) -> TrustFact | None:
    if not isinstance(context.node, ast.If):
        return None
    test = context.node.test
    negated = isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
    compare_call = test.operand if negated and isinstance(test, ast.UnaryOp) else test
    if not isinstance(compare_call, ast.Call):
        return None
    if reference_for(compare_call.func) not in {"hmac.compare_digest", "compare_digest"}:
        return None
    if len(compare_call.args) != 2:
        return None
    first_message = _hmac_message(compare_call.args[0])
    second_message = _hmac_message(compare_call.args[1])
    message = first_message or second_message
    signature_expr = compare_call.args[1] if first_message is not None else compare_call.args[0]
    if message is None:
        return None
    failure_block = context.node.body if negated else context.node.orelse
    if not block_terminates(failure_block):
        return None
    origins = _origin_in_expression(message, model)
    signature_origins = _origin_in_expression(signature_expr, model)
    if ValueOrigin.WEBHOOK_SIGNATURE in signature_origins:
        body = (
            WebhookBodyOrigin.RAW_PRESERVED
            if ValueOrigin.RAW_WEBHOOK_BODY in origins
            else WebhookBodyOrigin.PARSED
            if ValueOrigin.PARSED_WEBHOOK_BODY in origins
            else WebhookBodyOrigin.UNKNOWN
        )
        if body != WebhookBodyOrigin.RAW_PRESERVED:
            return None
        return TrustFact(
            symbol_id=model.symbol.symbol_id,
            location=source_location(model.module.path, context.node),
            context=context,
            trust_kind=TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION,
            webhook_body_origin=body,
            order_identity_origin=None,
        )
    if ValueOrigin.CHECKOUT_SIGNATURE in signature_origins:
        order = (
            OrderIdentityOrigin.SERVER_STATE_CONFIRMED
            if ValueOrigin.SERVER_CONFIRMED_ORDER_ID in origins
            else OrderIdentityOrigin.CLIENT_RETURNED
            if ValueOrigin.CLIENT_RETURNED_ORDER_ID in origins
            else OrderIdentityOrigin.UNKNOWN
        )
        return TrustFact(
            symbol_id=model.symbol.symbol_id,
            location=source_location(model.module.path, context.node),
            context=context,
            trust_kind=TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION,
            webhook_body_origin=None,
            order_identity_origin=order,
        )
    return None


def _recognize_trust(model: FunctionControlModel) -> tuple[TrustFact, ...]:
    result: list[TrustFact] = []
    seen: set[tuple[str, TrustGateKind]] = set()
    for context in model.statements:
        direct = _direct_hmac_fact(context, model)
        if direct is not None:
            key = (context.anchor, direct.trust_kind)
            if key not in seen:
                result.append(direct)
                seen.add(key)
            if (
                direct.trust_kind == TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION
                and direct.order_identity_origin == OrderIdentityOrigin.SERVER_STATE_CONFIRMED
            ):
                binding_key = (
                    context.anchor,
                    TrustGateKind.SERVER_ORDER_IDENTITY_BINDING,
                )
                if binding_key not in seen:
                    result.append(
                        replace(
                            direct,
                            trust_kind=TrustGateKind.SERVER_ORDER_IDENTITY_BINDING,
                        )
                    )
                    seen.add(binding_key)
        for call in (item for item in ast.walk(context.node) if isinstance(item, ast.Call)):
            kind = _sdk_verifier(call, model)
            if kind is None or _try_swallows(model.function, call):
                continue
            call_context = model.context_for(call) or context
            key = (call_context.anchor, kind)
            if key in seen:
                continue
            if kind == TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION:
                body_origin = (
                    expression_origin(call.args[0], model) if call.args else ValueOrigin.UNKNOWN
                )
                signature_origin = (
                    expression_origin(call.args[1], model)
                    if len(call.args) >= 2
                    else ValueOrigin.UNKNOWN
                )
                if (
                    body_origin != ValueOrigin.RAW_WEBHOOK_BODY
                    or signature_origin != ValueOrigin.WEBHOOK_SIGNATURE
                ):
                    continue
                result.append(
                    TrustFact(
                        symbol_id=model.symbol.symbol_id,
                        location=source_location(model.module.path, call),
                        context=call_context,
                        trust_kind=kind,
                        webhook_body_origin=WebhookBodyOrigin.RAW_PRESERVED,
                        order_identity_origin=None,
                    )
                )
            else:
                origins, order_origin = _checkout_origins(call, model)
                if not {
                    ValueOrigin.CHECKOUT_PAYMENT_ID,
                    ValueOrigin.CHECKOUT_SIGNATURE,
                }.issubset(origins):
                    continue
                result.append(
                    TrustFact(
                        symbol_id=model.symbol.symbol_id,
                        location=source_location(model.module.path, call),
                        context=call_context,
                        trust_kind=kind,
                        webhook_body_origin=None,
                        order_identity_origin=order_origin,
                    )
                )
                if order_origin == OrderIdentityOrigin.SERVER_STATE_CONFIRMED:
                    result.append(
                        TrustFact(
                            symbol_id=model.symbol.symbol_id,
                            location=source_location(model.module.path, call),
                            context=call_context,
                            trust_kind=TrustGateKind.SERVER_ORDER_IDENTITY_BINDING,
                            webhook_body_origin=None,
                            order_identity_origin=order_origin,
                        )
                    )
            seen.add(key)
    return tuple(result)


def _trust_candidate_diagnostics(
    model: FunctionControlModel,
    route: ReachableRoute,
) -> tuple[GraphDiagnosticRecord, ...]:
    result: list[GraphDiagnosticRecord] = []
    for call in (item for item in ast.walk(model.function) if isinstance(item, ast.Call)):
        method_kind = _sdk_method_kind(call)
        if method_kind is None:
            continue
        kind = _sdk_verifier(call, model)
        reason: GraphDiagnosticReason | None = None
        candidate = (
            GraphCandidateKind.WEBHOOK_SIGNATURE
            if method_kind == TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION
            else GraphCandidateKind.CHECKOUT_SIGNATURE
        )
        impact = GraphDiagnosticImpact.NOTICE
        if kind is None:
            reason = GraphDiagnosticReason.SDK_BINDING_UNRESOLVED
            impact = GraphDiagnosticImpact.COVERAGE_REDUCED
        elif kind == TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION:
            body = expression_origin(call.args[0], model) if call.args else ValueOrigin.UNKNOWN
            signature = (
                expression_origin(call.args[1], model)
                if len(call.args) >= 2
                else ValueOrigin.UNKNOWN
            )
            if signature != ValueOrigin.WEBHOOK_SIGNATURE:
                continue
            if body == ValueOrigin.PARSED_WEBHOOK_BODY:
                reason = GraphDiagnosticReason.PARSED_BODY_USED
            elif body != ValueOrigin.RAW_WEBHOOK_BODY:
                reason = GraphDiagnosticReason.RAW_BODY_UNRESOLVED
            elif _try_swallows(model.function, call):
                reason = GraphDiagnosticReason.VALIDATION_NOT_CONTROL_EFFECTIVE
        else:
            origins, _ = _checkout_origins(call, model)
            if {
                ValueOrigin.CHECKOUT_PAYMENT_ID,
                ValueOrigin.CHECKOUT_SIGNATURE,
            }.issubset(origins) and _try_swallows(model.function, call):
                reason = GraphDiagnosticReason.VALIDATION_NOT_CONTROL_EFFECTIVE
        if reason is not None:
            result.append(
                GraphDiagnosticRecord(
                    code=GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE,
                    impact=impact,
                    candidate_kind=candidate,
                    reason=reason,
                    symbol_id=model.symbol.symbol_id,
                    route_registration_id=route.registration.route_registration_id,
                    source_location=source_location(model.module.path, call),
                )
            )
    return tuple(result)


def _unresolved_call_diagnostics(
    model: FunctionControlModel,
    route: ReachableRoute,
    source_index: SourceIndexArtifact,
) -> tuple[GraphDiagnosticRecord, ...]:
    payment_relevant = bool(
        _all_strings(model.function)
        & (PAYMENT_EVENTS | CHECKOUT_IDENTIFIERS | {"x-razorpay-signature", "x-razorpay-event-id"})
    ) or any(origin != ValueOrigin.UNKNOWN for origin in model.name_origins.values())
    if not payment_relevant:
        return ()
    allowed_roots = {
        "request",
        "hmac",
        "hashlib",
        "JSONResponse",
        "Response",
        "HTTPException",
        "fastapi",
        "starlette",
        "set",
        "dict",
        "list",
        *(
            name
            for name, state in model.module.sdk_bindings.items()
            if state == SdkBindingState.RAZORPAY_CLIENT
        ),
        *model.module.module_state_names,
    }
    result: list[GraphDiagnosticRecord] = []
    for call_site in source_index.call_sites:
        if call_site.caller_symbol_id != model.symbol.symbol_id:
            continue
        if call_site.callee_symbol_id is not None:
            continue
        if call_site.callee_reference.endswith(
            (
                ".utility.verify_webhook_signature",
                ".utility.verify_payment_signature",
            )
        ):
            # Verifier-shaped calls are diagnosed by the binding-aware recognizer.
            continue
        root = call_site.callee_reference.partition(".")[0]
        if root in allowed_roots:
            continue
        result.append(
            GraphDiagnosticRecord(
                code=GraphDiagnosticCode.CALL_PATH_UNRESOLVED,
                impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
                symbol_id=model.symbol.symbol_id,
                source_location=call_site.source_location,
            )
        )
    return tuple(result)


def _literal_values(node: ast.AST) -> tuple[str, ...]:
    values = sorted(
        {
            item.value.strip().casefold()
            for item in ast.walk(node)
            if isinstance(item, ast.Constant)
            and isinstance(item.value, str)
            and item.value.strip().casefold() in PAYMENT_EVENTS
        }
    )
    return tuple(values)


def _state_condition(
    expression: ast.AST,
    model: FunctionControlModel,
) -> tuple[PaymentStateOperator, tuple[str, ...]] | None:
    states = _literal_values(expression)
    if not states or ValueOrigin.PAYMENT_EVENT_SELECTOR not in _origin_in_expression(
        expression, model
    ):
        return None
    if isinstance(expression, ast.Compare) and len(expression.ops) == 1:
        operator = expression.ops[0]
        mapping: dict[type[ast.cmpop], PaymentStateOperator] = {
            ast.Eq: PaymentStateOperator.EQUALS,
            ast.NotEq: PaymentStateOperator.NOT_EQUALS,
            ast.In: PaymentStateOperator.IN,
            ast.NotIn: PaymentStateOperator.NOT_IN,
        }
        matched = next(
            (value for kind, value in mapping.items() if isinstance(operator, kind)), None
        )
        if matched is not None:
            return matched, states
    if isinstance(expression, (ast.BoolOp, ast.UnaryOp)):
        return PaymentStateOperator.COMPOUND, states
    return None


def _recognize_state_gates(model: FunctionControlModel) -> tuple[StateGateFact, ...]:
    result: list[StateGateFact] = []
    for context in model.statements:
        if isinstance(context.node, ast.If):
            recognized = _state_condition(context.node.test, model)
            if recognized is not None:
                operator, states = recognized
                result.append(
                    StateGateFact(
                        symbol_id=model.symbol.symbol_id,
                        location=source_location(model.module.path, context.node.test),
                        context=context,
                        operator=operator,
                        states=states,
                    )
                )
        elif isinstance(context.node, ast.Match):
            if expression_origin(context.node.subject, model) != ValueOrigin.PAYMENT_EVENT_SELECTOR:
                continue
            states = _literal_values(context.node)
            if states:
                result.append(
                    StateGateFact(
                        symbol_id=model.symbol.symbol_id,
                        location=source_location(model.module.path, context.node.subject),
                        context=context,
                        operator=PaymentStateOperator.MATCH_CASE,
                        states=states,
                    )
                )
    return tuple(result)


def _target_root(target: ast.AST) -> str | None:
    current = target
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _target_field(target: ast.AST) -> str | None:
    if isinstance(target, ast.Attribute):
        return target.attr.casefold()
    if isinstance(target, ast.Subscript):
        return string_key(target.slice)
    return None


def _recognize_mutations(
    model: FunctionControlModel,
    state_gates: tuple[StateGateFact, ...],
    trust: tuple[TrustFact, ...],
) -> tuple[MutationFact, ...]:
    gate_anchors = {item.context.anchor for item in state_gates}
    result: list[MutationFact] = []
    for context in model.statements:
        targets: list[ast.expr] = []
        value: ast.AST | None = None
        if isinstance(context.node, ast.Assign):
            targets = list(context.node.targets)
            value = context.node.value
        elif isinstance(context.node, ast.AnnAssign):
            targets = [context.node.target]
            value = context.node.value
        elif isinstance(context.node, ast.AugAssign):
            targets = [context.node.target]
            value = context.node.value
        if not targets or value is None:
            continue
        value_origin = expression_origin(value, model)
        assigned_payment_state = (
            value.value.strip().casefold().removeprefix("payment.")
            if isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value.strip().casefold().removeprefix("payment.")
            in {"authorized", "captured"}
            else None
        )
        controlled = any(item.gate_anchor in gate_anchors for item in context.ancestors)
        trust_controlled = any(
            item.symbol_id == model.symbol.symbol_id
            and item.trust_kind
            in {
                TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION,
                TrustGateKind.SERVER_ORDER_IDENTITY_BINDING,
            }
            and context_dominates(item.context, context)
            for item in trust
        )
        for target in targets:
            if not isinstance(target, (ast.Attribute, ast.Subscript)):
                continue
            root = _target_root(target)
            field = _target_field(target)
            established_carrier = root in model.module.module_state_names
            payment_relevant = value_origin in {
                ValueOrigin.PAYMENT_EVENT_SELECTOR,
                ValueOrigin.CHECKOUT_PAYMENT_ID,
            } or ((controlled or trust_controlled) and field in _MERCHANT_STATE_FIELDS)
            if not established_carrier or not payment_relevant or root is None:
                continue
            result.append(
                MutationFact(
                    symbol_id=model.symbol.symbol_id,
                    location=source_location(model.module.path, target),
                    context=context,
                    mutation_kind=(
                        MerchantMutationKind.ATTRIBUTE_WRITE
                        if isinstance(target, ast.Attribute)
                        else MerchantMutationKind.SUBSCRIPT_WRITE
                    ),
                    carrier_reference=merchant_state_carrier_id(
                        model.symbol.source_file_id,
                        root,
                    ),
                    assigned_payment_state=assigned_payment_state,
                )
            )
    return tuple(result)


def _awaited_call(value: ast.AST | None) -> ast.Call | None:
    candidate = value.value if isinstance(value, ast.Await) else value
    return candidate if isinstance(candidate, ast.Call) else None


def _manual_payload_keys(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    payload_name: str,
) -> set[str] | None:
    """Return bounded direct payload keys, or None for unresolved payload use."""

    parents = {
        child: parent for parent in ast.walk(function) for child in ast.iter_child_nodes(parent)
    }
    observed: set[str] = set()
    for node in ast.walk(function):
        if not (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id == payload_name
        ):
            continue
        parent = parents.get(node)
        if isinstance(parent, ast.Subscript) and parent.value is node:
            key = string_key(parent.slice)
            if key is None:
                return None
            observed.add(key)
            continue
        if isinstance(parent, ast.Attribute) and parent.value is node and parent.attr == "get":
            call = parents.get(parent)
            if not isinstance(call, ast.Call) or call.func is not parent or not call.args:
                return None
            key_argument = call.args[0]
            if not isinstance(key_argument, ast.Constant) or not isinstance(
                key_argument.value, str
            ):
                return None
            continue
        return None
    return observed


def _framework_provided_parameter(argument: ast.arg) -> bool:
    annotation = reference_for(argument.annotation) if argument.annotation is not None else None
    return annotation is not None and annotation.endswith("Request")


def _unsupported_required_parameter(default: ast.AST | None) -> bool:
    if default is None:
        return True
    if not isinstance(default, ast.Call):
        return False
    reference = reference_for(default.func) or ""
    marker = reference.rpartition(".")[2]
    if marker in {"Depends", "Security", "Path"}:
        return True
    if marker not in {"Body", "Cookie", "Form", "Header", "Query"}:
        return False
    if not default.args:
        return True
    first = default.args[0]
    return isinstance(first, ast.Constant) and first.value is Ellipsis


def _parameter_defaults(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[list[ast.arg], dict[str, ast.AST | None]]:
    arguments = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    positional = [*function.args.posonlyargs, *function.args.args]
    defaults: dict[str, ast.AST | None] = {item.arg: None for item in arguments}
    start = len(positional) - len(function.args.defaults)
    for argument, positional_default in zip(
        positional[start:], function.args.defaults, strict=True
    ):
        defaults[argument.arg] = positional_default
    for argument, keyword_default in zip(
        function.args.kwonlyargs,
        function.args.kw_defaults,
        strict=True,
    ):
        defaults[argument.arg] = keyword_default
    return arguments, defaults


def _has_unsupported_required_parameters(
    arguments: list[ast.arg],
    defaults: dict[str, ast.AST | None],
    supported_names: set[str],
) -> bool:
    arguments_by_name = {item.arg: item for item in arguments}
    return any(
        name not in supported_names
        and not _framework_provided_parameter(arguments_by_name[name])
        and _unsupported_required_parameter(parameter_default)
        for name, parameter_default in defaults.items()
    )


def _checkout_request_binding(model: FunctionControlModel) -> CheckoutRequestBinding | None:
    """Recognize bounded FastAPI callback transports with exact field aliases."""

    canonical = (
        "razorpay_payment_id",
        "razorpay_order_id",
        "razorpay_signature",
    )
    arguments, defaults = _parameter_defaults(model.function)
    manual_transports: list[CheckoutRequestTransport] = []
    for statement in ast.walk(model.function):
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        call = _awaited_call(statement.value)
        reference = reference_for(call.func) if call is not None else None
        if reference is None or not reference.endswith((".json", ".form")):
            continue
        names = [item.id for item in targets if isinstance(item, ast.Name)]
        if len(names) != 1:
            continue
        payload_name = names[0]
        observed = _manual_payload_keys(model.function, payload_name)
        if observed is None or observed != set(canonical):
            continue
        manual_transports.append(
            CheckoutRequestTransport.JSON
            if reference.endswith(".json")
            else CheckoutRequestTransport.FORM_URLENCODED
        )
    if len(manual_transports) > 1:
        return None
    if manual_transports:
        if _has_unsupported_required_parameters(arguments, defaults, set()):
            return None
        return CheckoutRequestBinding(
            transport=manual_transports[0],
            fields=tuple(
                CheckoutFieldBinding(canonical_name=name, request_name=name) for name in canonical
            ),
        )

    if not set(canonical) <= {item.arg for item in arguments}:
        return None
    if _has_unsupported_required_parameters(arguments, defaults, set(canonical)):
        return None

    transports: set[CheckoutRequestTransport] = set()
    fields: list[CheckoutFieldBinding] = []
    for name in canonical:
        parameter_default = defaults[name]
        call = parameter_default if isinstance(parameter_default, ast.Call) else None
        reference = reference_for(call.func) if call is not None else None
        if reference is not None and reference.endswith("Form"):
            transport = CheckoutRequestTransport.FORM_URLENCODED
        elif reference is not None and reference.endswith("Body"):
            transport = CheckoutRequestTransport.JSON
        elif parameter_default is None:
            transport = CheckoutRequestTransport.QUERY
        else:
            return None
        alias = name
        if call is not None:
            alias_value = next(
                (item.value for item in call.keywords if item.arg == "alias"),
                None,
            )
            if isinstance(alias_value, ast.Constant) and isinstance(alias_value.value, str):
                alias = alias_value.value
            elif alias_value is not None:
                return None
        transports.add(transport)
        fields.append(CheckoutFieldBinding(canonical_name=name, request_name=alias))
    if len(transports) != 1:
        return None
    return CheckoutRequestBinding(transport=transports.pop(), fields=tuple(fields))


def _event_membership_test(
    expression: ast.AST,
    model: FunctionControlModel,
) -> str | None:
    if not isinstance(expression, ast.Compare) or len(expression.ops) != 1:
        return None
    if not isinstance(expression.ops[0], (ast.In, ast.NotIn)):
        return None
    if expression_origin(expression.left, model) != ValueOrigin.WEBHOOK_EVENT_ID:
        return None
    return _target_root(expression.comparators[0])


def _is_event_claim(node: ast.AST, event_names: set[str], carrier: str) -> bool:
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        call = node.value
        reference = reference_for(call.func) or ""
        if reference == f"{carrier}.add" and call.args:
            return isinstance(call.args[0], ast.Name) and call.args[0].id in event_names
    if isinstance(node, ast.Assign):
        return any(
            isinstance(target, ast.Subscript)
            and _target_root(target) == carrier
            and isinstance(target.slice, ast.Name)
            and target.slice.id in event_names
            for target in node.targets
        )
    return False


def _recognize_event_identity(
    model: FunctionControlModel,
    mutations: tuple[MutationFact, ...],
) -> tuple[EventIdentityFact, ...]:
    event_names = {
        name
        for name, origin in model.name_origins.items()
        if origin == ValueOrigin.WEBHOOK_EVENT_ID
    }
    if not event_names:
        return ()
    first_mutation_line = min((item.location.line_start for item in mutations), default=10**9)
    result: list[EventIdentityFact] = []
    for context in model.statements:
        if not isinstance(context.node, ast.If):
            continue
        carrier = _event_membership_test(context.node.test, model)
        if carrier is None or carrier not in model.module.module_state_names:
            continue
        duplicate_block = context.node.body
        if not block_terminates(duplicate_block):
            continue
        claims = [
            item
            for item in model.statements
            if item.location_tuple > context.location_tuple
            and _is_event_claim(item.node, event_names, carrier)
        ]
        claim = next(
            (
                item
                for item in claims
                if source_location(model.module.path, item.node).line_start < first_mutation_line
            ),
            None,
        )
        if claim is None:
            continue
        result.append(
            EventIdentityFact(
                symbol_id=model.symbol.symbol_id,
                location=source_location(model.module.path, context.node.test),
                context=context,
                strategy=EventIdentityStrategy.LOOKUP_AND_RECORD,
            )
        )
    return tuple(result)


def _literal_status(call: ast.Call) -> int | None:
    candidate = next((item.value for item in call.keywords if item.arg == "status_code"), None)
    if (
        candidate is None
        and call.args
        and (reference_for(call.func) or "").endswith("HTTPException")
    ):
        candidate = call.args[0]
    if isinstance(candidate, ast.Constant) and isinstance(candidate.value, int):
        return candidate.value if 100 <= candidate.value <= 599 else None
    return None


def _outcome(status: int | None) -> AcknowledgementOutcome:
    if status is None:
        return AcknowledgementOutcome.UNKNOWN
    return (
        AcknowledgementOutcome.SUCCESS_2XX
        if 200 <= status < 300
        else AcknowledgementOutcome.NON_SUCCESS
    )


def _route_default_status(model: FunctionControlModel) -> int:
    for decorator in model.function.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        candidate = next(
            (item.value for item in decorator.keywords if item.arg == "status_code"), None
        )
        if isinstance(candidate, ast.Constant) and isinstance(candidate.value, int):
            if 100 <= candidate.value <= 599:
                return candidate.value
    return 200


def _recognize_acknowledgements(model: FunctionControlModel) -> tuple[AcknowledgementFact, ...]:
    result: list[AcknowledgementFact] = []
    default_status = _route_default_status(model)
    for context in model.statements:
        if isinstance(context.node, ast.Return):
            value = context.node.value
            exit_kind = AcknowledgementExitKind.RETURN
            status: int | None = default_status
            if isinstance(value, ast.Call):
                reference = reference_for(value.func) or ""
                if reference.endswith(("Response", "JSONResponse")):
                    exit_kind = AcknowledgementExitKind.RESPONSE
                    status = _literal_status(value)
            result.append(
                AcknowledgementFact(
                    symbol_id=model.symbol.symbol_id,
                    location=source_location(model.module.path, context.node),
                    context=context,
                    anchor=context.anchor,
                    exit_kind=exit_kind,
                    status_code=status,
                    outcome=_outcome(status),
                )
            )
        elif isinstance(context.node, ast.Raise) and isinstance(context.node.exc, ast.Call):
            if (reference_for(context.node.exc.func) or "").endswith("HTTPException"):
                exception_status = _literal_status(context.node.exc)
                result.append(
                    AcknowledgementFact(
                        symbol_id=model.symbol.symbol_id,
                        location=source_location(model.module.path, context.node),
                        context=context,
                        anchor=context.anchor,
                        exit_kind=AcknowledgementExitKind.HTTP_EXCEPTION,
                        status_code=exception_status,
                        outcome=_outcome(exception_status),
                    )
                )
    if not block_terminates(model.function.body):
        anchor = structural_anchor(model.symbol.symbol_id, "IMPLICIT_RETURN")
        result.append(
            AcknowledgementFact(
                symbol_id=model.symbol.symbol_id,
                location=model.symbol.source_location,
                context=None,
                anchor=anchor,
                exit_kind=AcknowledgementExitKind.IMPLICIT_RETURN,
                status_code=default_status,
                outcome=_outcome(default_status),
            )
        )
    return tuple(result)


def analyze_route_concepts(
    route: ReachableRoute,
    source_index: SourceIndexArtifact,
    parsed: ParsedProject,
) -> RouteConceptAnalysis:
    paths = resolved_call_paths(source_index, route.owner_symbol_id, parsed)
    route_models = _models_with_forwarded_origins(paths, parsed)
    models = [route_models[symbol] for symbol in paths]
    trust: list[TrustFact] = []
    states: list[StateGateFact] = []
    mutations: list[MutationFact] = []
    identities: list[EventIdentityFact] = []
    all_strings: set[str] = set()
    all_origins: set[ValueOrigin] = set()
    diagnostics: list[GraphDiagnosticRecord] = []

    for model in models:
        all_strings.update(_all_strings(model.function))
        all_origins.update(model.name_origins.values())
        model_trust = tuple(
            replace(
                fact,
                route_guard_context=_route_guard_context(
                    fact,
                    paths[model.symbol.symbol_id],
                    route_models,
                ),
            )
            for fact in _recognize_trust(model)
        )
        model_states = _recognize_state_gates(model)
        model_mutations = _recognize_mutations(model, model_states, model_trust)
        model_identities = _recognize_event_identity(model, model_mutations)
        trust.extend(model_trust)
        states.extend(model_states)
        mutations.extend(model_mutations)
        identities.extend(model_identities)
        diagnostics.extend(_trust_candidate_diagnostics(model, route))
        diagnostics.extend(_unresolved_call_diagnostics(model, route, source_index))
        if model.unsupported_exception_flow:
            diagnostics.append(
                GraphDiagnosticRecord(
                    code=GraphDiagnosticCode.CONTROL_FLOW_UNSUPPORTED,
                    impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
                    symbol_id=model.symbol.symbol_id,
                    source_location=model.symbol.source_location,
                )
            )
        if model.symbol.symbol_id != route.owner_symbol_id:
            for fact in model_trust:
                if fact.route_guard_context is None or exception_failure_allows_continuation(
                    fact.route_guard_context
                ):
                    diagnostics.append(
                        GraphDiagnosticRecord(
                            code=GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE,
                            impact=GraphDiagnosticImpact.NOTICE,
                            candidate_kind=(
                                GraphCandidateKind.WEBHOOK_SIGNATURE
                                if fact.trust_kind == TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION
                                else GraphCandidateKind.CHECKOUT_SIGNATURE
                            ),
                            reason=GraphDiagnosticReason.VALIDATION_NOT_CONTROL_EFFECTIVE,
                            symbol_id=fact.symbol_id,
                            route_registration_id=route.registration.route_registration_id,
                            source_location=paths[fact.symbol_id][0].source_location,
                        )
                    )

    evidence: list[str] = []
    has_webhook_verifier = any(
        item.trust_kind == TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION for item in trust
    )
    if "x-razorpay-signature" in all_strings and has_webhook_verifier:
        evidence.append("WEBHOOK_SIGNATURE_PIPELINE")
    if "x-razorpay-event-id" in all_strings or ValueOrigin.WEBHOOK_EVENT_ID in all_origins:
        evidence.append("WEBHOOK_EVENT_ID")
    if states:
        evidence.append("PAYMENT_EVENT_BRANCH")

    checkout_identifiers = set(CHECKOUT_IDENTIFIERS & all_strings)
    for origin, name in {
        ValueOrigin.CHECKOUT_PAYMENT_ID: "razorpay_payment_id",
        ValueOrigin.CLIENT_RETURNED_ORDER_ID: "razorpay_order_id",
        ValueOrigin.CHECKOUT_SIGNATURE: "razorpay_signature",
    }.items():
        if origin in all_origins:
            checkout_identifiers.add(name)
    checkout_verifier = any(
        item.trust_kind == TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION for item in trust
    )
    checkout_binding = _checkout_request_binding(route_models[route.owner_symbol_id])

    ingress_kind: PaymentIngressKind | None = None
    if route.registration.method == "POST":
        webhook_families = set(evidence)
        if len(webhook_families) >= 2 and webhook_families & {
            "WEBHOOK_SIGNATURE_PIPELINE",
            "WEBHOOK_EVENT_ID",
        }:
            ingress_kind = PaymentIngressKind.WEBHOOK
        elif checkout_identifiers == CHECKOUT_IDENTIFIERS or (
            checkout_verifier
            and {"razorpay_payment_id", "razorpay_signature"}.issubset(checkout_identifiers)
        ):
            ingress_kind = PaymentIngressKind.CHECKOUT_CALLBACK

    if ingress_kind is None and (
        evidence or checkout_identifiers or has_webhook_verifier or checkout_verifier
    ):
        candidate = (
            GraphCandidateKind.WEBHOOK_INGRESS
            if evidence or has_webhook_verifier
            else GraphCandidateKind.CHECKOUT_CALLBACK_INGRESS
        )
        diagnostics.append(
            GraphDiagnosticRecord(
                code=GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE,
                impact=GraphDiagnosticImpact.NOTICE,
                candidate_kind=candidate,
                reason=GraphDiagnosticReason.INSUFFICIENT_CONVERGING_EVIDENCE,
                symbol_id=route.owner_symbol_id,
                route_registration_id=route.registration.route_registration_id,
                source_location=route.route_location,
            )
        )
    if (
        ingress_kind == PaymentIngressKind.WEBHOOK
        and ("x-razorpay-event-id" in all_strings or ValueOrigin.WEBHOOK_EVENT_ID in all_origins)
        and not identities
    ):
        diagnostics.append(
            GraphDiagnosticRecord(
                code=GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE,
                impact=GraphDiagnosticImpact.NOTICE,
                candidate_kind=GraphCandidateKind.EVENT_IDENTITY,
                reason=GraphDiagnosticReason.EVENT_ID_OBSERVED_ONLY,
                symbol_id=route.owner_symbol_id,
                route_registration_id=route.registration.route_registration_id,
                source_location=route.route_location,
            )
        )
    for item in trust:
        if (
            item.trust_kind == TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION
            and item.order_identity_origin == OrderIdentityOrigin.CLIENT_RETURNED
        ):
            diagnostics.append(
                GraphDiagnosticRecord(
                    code=GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE,
                    impact=GraphDiagnosticImpact.NOTICE,
                    candidate_kind=GraphCandidateKind.SERVER_ORDER_IDENTITY,
                    reason=GraphDiagnosticReason.CLIENT_ORDER_ID_USED,
                    symbol_id=item.symbol_id,
                    route_registration_id=route.registration.route_registration_id,
                    source_location=item.location,
                )
            )
        elif (
            item.trust_kind == TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION
            and item.order_identity_origin == OrderIdentityOrigin.UNKNOWN
        ):
            diagnostics.append(
                GraphDiagnosticRecord(
                    code=GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE,
                    impact=GraphDiagnosticImpact.NOTICE,
                    candidate_kind=GraphCandidateKind.SERVER_ORDER_IDENTITY,
                    reason=GraphDiagnosticReason.ORDER_IDENTITY_UNKNOWN,
                    symbol_id=item.symbol_id,
                    route_registration_id=route.registration.route_registration_id,
                    source_location=item.location,
                )
            )

    acknowledgements = (
        _recognize_acknowledgements(parsed.functions[route.owner_symbol_id])
        if ingress_kind == PaymentIngressKind.WEBHOOK
        else ()
    )
    families = tuple(
        sorted(evidence if ingress_kind == PaymentIngressKind.WEBHOOK else checkout_identifiers)
    )
    return RouteConceptAnalysis(
        ingress_kind=ingress_kind,
        evidence_families=families,
        checkout_request_binding=(
            checkout_binding if ingress_kind == PaymentIngressKind.CHECKOUT_CALLBACK else None
        ),
        trust=tuple(trust),
        event_identity=tuple(identities),
        state_gates=tuple(states),
        mutations=tuple(mutations),
        acknowledgements=tuple(acknowledgements),
        call_paths=paths,
        diagnostics=tuple(diagnostics),
    )


def unselected_route_candidate_diagnostics(
    routes: tuple[RouteRecord, ...],
    source_index: SourceIndexArtifact,
    parsed: ParsedProject,
) -> tuple[GraphDiagnosticRecord, ...]:
    """Inspect unresolved app-owned route candidates without creating graph facts."""

    result: list[GraphDiagnosticRecord] = []
    seen: set[SymbolId] = set()
    for route in routes:
        if route.owner_symbol_id in seen or route.owner_symbol_id not in parsed.functions:
            continue
        seen.add(route.owner_symbol_id)
        paths = resolved_call_paths(source_index, route.owner_symbol_id, parsed)
        models = _models_with_forwarded_origins(paths, parsed).values()
        strings = {value for model in models for value in _all_strings(model.function)}
        origins = {origin for model in models for origin in model.name_origins.values()}
        webhook = bool(
            strings & ({"x-razorpay-signature", "x-razorpay-event-id"} | PAYMENT_EVENTS)
            or origins
            & {
                ValueOrigin.WEBHOOK_SIGNATURE,
                ValueOrigin.WEBHOOK_EVENT_ID,
                ValueOrigin.PAYMENT_EVENT_SELECTOR,
            }
        )
        checkout = bool(
            strings & CHECKOUT_IDENTIFIERS
            or origins
            & {
                ValueOrigin.CHECKOUT_PAYMENT_ID,
                ValueOrigin.CLIENT_RETURNED_ORDER_ID,
                ValueOrigin.CHECKOUT_SIGNATURE,
            }
        )
        if not webhook and not checkout:
            continue
        result.append(
            GraphDiagnosticRecord(
                code=GraphDiagnosticCode.UNRESOLVED_STRUCTURAL_CANDIDATE,
                impact=GraphDiagnosticImpact.NOTICE,
                candidate_kind=(
                    GraphCandidateKind.WEBHOOK_INGRESS
                    if webhook
                    else GraphCandidateKind.CHECKOUT_CALLBACK_INGRESS
                ),
                reason=GraphDiagnosticReason.INSUFFICIENT_CONVERGING_EVIDENCE,
                symbol_id=route.owner_symbol_id,
                source_location=route.source_location,
            )
        )
    return tuple(result)
