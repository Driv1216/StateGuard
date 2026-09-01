from __future__ import annotations

import ast
from collections import defaultdict, deque
from typing import Any

from ..schemas import MapperKind, MappingEvidence, RoleCandidate, RoleMapping, SourceBundle
from ..source_index import identifier_tokens


POSITIVE_TERMS = {
    "fulfill", "fulfil", "ship", "deliver", "grant", "activate", "provision", "issue", "unlock"
}
EXCLUSION_TERMS = {
    "notify", "notification", "email", "sms", "analytic", "log", "persist", "save",
    "payment", "refund", "inventory", "cache", "webhook", "signature", "validate",
}
KNOWN_RAZORPAY_REFERENCES = {
    "razorpay", "razorpay.Client", "razorpay.utility.verify_webhook_signature",
    "razorpay.payment.fetch",
}
WEIGHTS = {
    "positive_identifier": 6,
    "positive_body": 3,
    "direct_captured": 5,
    "transitive_captured": 3,
    "webhook_reachable": 2,
    "stateful_effect": 2,
    "leaf_like": 1,
    "exclusion_identifier": -5,
    "authorized_only": -5,
    "route_or_parser": -3,
}
SELECTION_THRESHOLD = 9


def _nodes(bundle: SourceBundle) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    result: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for source_file in bundle.files:
        module = source_file.logical_path.removesuffix(".py").replace("/", ".")
        tree = ast.parse(source_file.content, filename=source_file.logical_path)
        class_stack: list[str] = []

        class Visitor(ast.NodeVisitor):
            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                class_stack.append(node.name)
                self.generic_visit(node)
                class_stack.pop()

            def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                result[".".join([module, *class_stack, node.name])] = node
                self.generic_visit(node)

            visit_FunctionDef = _function
            visit_AsyncFunctionDef = _function

        Visitor().visit(tree)
    return result


def _body_terms(node: ast.AST) -> set[str]:
    terms: set[str] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            for token in item.value.casefold().replace("-", "_").split("_"):
                terms.update(token.split())
    return terms


def _stateful(node: ast.AST) -> bool:
    for item in ast.walk(node):
        if isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            return True
        if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute):
            if item.func.attr.casefold() in {"append", "add", "insert", "create", "save", "write", "update"}:
                return True
    return False


def _reachable(starts: set[str], adjacency: dict[str, set[str]], max_depth: int | None = None) -> set[str]:
    seen: set[str] = set(starts)
    queue = deque((item, 0) for item in starts)
    while queue:
        current, depth = queue.popleft()
        if max_depth is not None and depth >= max_depth:
            continue
        for target in adjacency.get(current, set()):
            if target not in seen:
                seen.add(target)
                queue.append((target, depth + 1))
    return seen


def map_roles(bundle: SourceBundle, mapper_config: dict[str, Any] | None = None) -> RoleMapping:
    config = mapper_config or {}
    positive = set(config.get("positive_lexicon", POSITIVE_TERMS))
    exclusion = set(config.get("exclusion_lexicon", EXCLUSION_TERMS))
    weights = dict(WEIGHTS)
    weights.update(config.get("weights", {}))
    threshold = int(config.get("selection_threshold", SELECTION_THRESHOLD))
    nodes = _nodes(bundle)
    symbol_names = {symbol.qualified_name for symbol in bundle.symbols}
    path_by_symbol = {symbol.qualified_name: symbol for symbol in bundle.symbols}
    route_symbols = {route.symbol for route in bundle.routes}
    adjacency: dict[str, set[str]] = defaultdict(set)
    for edge in bundle.call_edges:
        if edge.callee in symbol_names:
            adjacency[edge.caller].add(edge.callee)
    route_reachable = _reachable(route_symbols, adjacency)
    direct_captured = {
        edge.callee for edge in bundle.call_edges
        if edge.payment_state == "captured" and edge.callee in symbol_names
    }
    transitive_captured = _reachable(direct_captured, adjacency, max_depth=3) - direct_captured
    direct_authorized = {
        edge.callee for edge in bundle.call_edges
        if edge.payment_state == "authorized" and edge.callee in symbol_names
    }
    candidates: list[RoleCandidate] = []
    score_metadata: dict[str, Any] = {}
    for symbol in bundle.symbols:
        name = symbol.qualified_name
        node = nodes[name]
        tokens = identifier_tokens(name)
        body_terms = _body_terms(node)
        contributions: dict[str, int] = {}
        if tokens & positive:
            contributions["positive_identifier"] = weights["positive_identifier"]
        if body_terms & positive:
            contributions["positive_body"] = weights["positive_body"]
        if name in direct_captured:
            contributions["direct_captured"] = weights["direct_captured"]
        elif name in transitive_captured:
            contributions["transitive_captured"] = weights["transitive_captured"]
        if name in route_reachable:
            contributions["webhook_reachable"] = weights["webhook_reachable"]
        if _stateful(node):
            contributions["stateful_effect"] = weights["stateful_effect"]
        internal_callees = adjacency.get(name, set())
        if len(internal_callees) <= 1:
            contributions["leaf_like"] = weights["leaf_like"]
        if tokens & exclusion:
            contributions["exclusion_identifier"] = weights["exclusion_identifier"]
        if name in direct_authorized and name not in direct_captured and name not in transitive_captured:
            contributions["authorized_only"] = weights["authorized_only"]
        if name in route_symbols or tokens & {"route", "parser", "handler", "validate", "webhook"}:
            contributions["route_or_parser"] = weights["route_or_parser"]
        score = sum(contributions.values())
        score_metadata[name] = {"score": score, "contributions": contributions}
        if score < threshold:
            continue
        explanation = "; ".join(f"{key}={value:+d}" for key, value in sorted(contributions.items()))
        candidates.append(RoleCandidate(
            role="IRREVERSIBLE_FULFILMENT",
            symbol=name,
            confidence=max(0.0, min(1.0, score / 16)),
            evidence=[MappingEvidence(
                kind="BODY",
                source_path=symbol.path,
                line_start=symbol.line_start,
                line_end=symbol.line_end,
                explanation=f"Frozen static score {score}: {explanation}",
            )],
        ))
    razorpay_references = sorted(
        reference for reference in KNOWN_RAZORPAY_REFERENCES
        if any(item == reference or item.startswith(reference + ".") for item in bundle.imports)
    )
    return RoleMapping(
        application_id=bundle.application_id,
        mapper_kind=MapperKind.STATIC_BASELINE,
        candidates=sorted(candidates, key=lambda candidate: candidate.symbol),
        metadata={
            "algorithm": "frozen_ast_static_v1",
            "selection_threshold": threshold,
            "scores": score_metadata,
            "razorpay_references": razorpay_references,
        },
    )

