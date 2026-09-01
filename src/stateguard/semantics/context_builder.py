"""Deterministic construction of relevance-scoped customer-value context."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

from stateguard.contracts.common import SymbolId
from stateguard.contracts.identity import fingerprint_json, sha256_digest
from stateguard.discovery.contracts import (
    CallSiteRecord,
    DiagnosticImpact,
    SourceIndexArtifact,
    SymbolKind,
    SymbolRecord,
)
from stateguard.discovery.service import StaleSourceIndexError, validate_indexed_source_snapshot
from stateguard.graph.contracts import (
    GraphDiagnosticCode,
    GraphDiagnosticImpact,
    GraphNodeKind,
    PaymentSafetyGraphArtifact,
)

from .contracts import (
    BundleCompleteness,
    CustomerValueMappingInput,
    SemanticCatalogEntry,
    SemanticContextDescriptor,
    SemanticContextDiagnostic,
    SemanticContextEvidence,
    SemanticContextEvidenceKind,
    SemanticDiagnosticCode,
    SourceExcerpt,
    SourceExcerptPurpose,
)
from .policy import DEFAULT_SEMANTIC_BUNDLE_POLICY, SemanticBundlePolicy

_CALLABLE_KINDS = frozenset(
    {SymbolKind.FUNCTION, SymbolKind.ASYNC_FUNCTION, SymbolKind.METHOD, SymbolKind.ASYNC_METHOD}
)
_GLOBAL_SEED_DIAGNOSTICS = frozenset(
    {
        GraphDiagnosticCode.APP_TARGET_UNSELECTED,
        GraphDiagnosticCode.ROUTE_COMPOSITION_UNRESOLVED,
        GraphDiagnosticCode.ROUTE_COMPOSITION_CYCLE,
    }
)


@dataclass(frozen=True)
class SemanticContextBuild:
    descriptor: SemanticContextDescriptor
    mapping_input: CustomerValueMappingInput | None
    call_paths: dict[SymbolId, tuple[CallSiteRecord, ...]]
    policy: SemanticBundlePolicy


def _symbol_source(repository_root: Path, symbol: SymbolRecord) -> str:
    path = repository_root / symbol.source_location.path
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise StaleSourceIndexError("indexed semantic source is unavailable") from exc
    lines = source.splitlines(keepends=True)
    excerpt = "".join(
        lines[symbol.source_location.line_start - 1 : symbol.source_location.line_end]
    )
    if not excerpt.strip():
        raise StaleSourceIndexError("indexed semantic source span is unavailable")
    return excerpt


def _diagnostic(
    code: SemanticDiagnosticCode,
    reference: str,
    *,
    symbol_id: SymbolId | None = None,
    path: str | None = None,
) -> SemanticContextDiagnostic:
    return SemanticContextDiagnostic(
        code=code,
        reference=reference,
        affected_symbol_id=symbol_id,
        affected_path=path,
        fingerprint=fingerprint_json(
            {"code": code, "reference": reference, "symbol_id": symbol_id, "path": path}
        ),
    )


def build_semantic_context(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    structural_graph: PaymentSafetyGraphArtifact,
    *,
    policy: SemanticBundlePolicy = DEFAULT_SEMANTIC_BUNDLE_POLICY,
) -> SemanticContextBuild:
    """Build full relevance first, then a deterministic bounded provider view."""

    if source_index.project_id != structural_graph.project_id:
        raise ValueError("source index and graph project IDs must match")
    if source_index.source_index_fingerprint != structural_graph.source_index_fingerprint:
        raise ValueError("structural graph must be built from the supplied source index")
    validate_indexed_source_snapshot(repository_root, source_index)

    symbol_by_id = {item.symbol_id: item for item in source_index.symbols}
    route_owner_ids = {item.owner_symbol_id for item in source_index.routes}
    ingress_nodes = tuple(
        item for item in structural_graph.nodes if item.kind == GraphNodeKind.PAYMENT_INGRESS
    )
    seed_ids = tuple(
        sorted({item.backing_symbol_id for item in ingress_nodes if item.backing_symbol_id})
    )

    outgoing: dict[SymbolId, list[CallSiteRecord]] = defaultdict(list)
    for call in source_index.call_sites:
        if call.callee_symbol_id is not None:
            outgoing[call.caller_symbol_id].append(call)
    for calls in outgoing.values():
        calls.sort(key=lambda item: (item.callee_symbol_id or "", item.callee_reference))

    distances: dict[SymbolId, int] = {}
    paths: dict[SymbolId, tuple[CallSiteRecord, ...]] = {}
    queue: deque[SymbolId] = deque()
    for seed in seed_ids:
        if seed in symbol_by_id and symbol_by_id[seed].kind in _CALLABLE_KINDS:
            distances[seed] = 0
            paths[seed] = ()
            queue.append(seed)
    while queue:
        caller = queue.popleft()
        for call in outgoing.get(caller, []):
            callee = call.callee_symbol_id
            if callee is None or callee not in symbol_by_id:
                continue
            if symbol_by_id[callee].kind not in _CALLABLE_KINDS or callee in distances:
                continue
            distances[callee] = distances[caller] + 1
            paths[callee] = (*paths[caller], call)
            queue.append(callee)

    relevant_ids = tuple(sorted(distances))
    candidate_ids = tuple(
        sorted(
            (item for item in relevant_ids if item not in route_owner_ids),
            key=lambda item: (distances[item], item),
        )
    )
    relevant_paths = {symbol_by_id[item].source_location.path for item in relevant_ids}
    relevant_route_ids = {
        item.details.registration.route_registration_id
        for item in ingress_nodes
        if item.details is not None and item.details.detail_kind == "PAYMENT_INGRESS"
    }

    diagnostics: list[SemanticContextDiagnostic] = []
    for item in source_index.diagnostics:
        path = item.path or (
            item.source_location.path if item.source_location is not None else None
        )
        if item.impact == DiagnosticImpact.COVERAGE_REDUCED and path in relevant_paths:
            diagnostics.append(
                _diagnostic(
                    SemanticDiagnosticCode.RELEVANT_SOURCE_DIAGNOSTIC,
                    f"source-diagnostic:{item.code.value}",
                    path=path,
                )
            )
    for graph_diagnostic in structural_graph.diagnostics:
        relevant = (
            graph_diagnostic.symbol_id in set(relevant_ids)
            or graph_diagnostic.route_registration_id in relevant_route_ids
            or (not seed_ids and graph_diagnostic.code in _GLOBAL_SEED_DIAGNOSTICS)
        )
        if graph_diagnostic.impact == GraphDiagnosticImpact.COVERAGE_REDUCED and relevant:
            diagnostics.append(
                _diagnostic(
                    SemanticDiagnosticCode.RELEVANT_GRAPH_DIAGNOSTIC,
                    f"graph-diagnostic:{graph_diagnostic.code.value}",
                    symbol_id=graph_diagnostic.symbol_id,
                    path=(
                        graph_diagnostic.source_location.path
                        if graph_diagnostic.source_location is not None
                        else None
                    ),
                )
            )

    known_simple_names = {
        item.qualified_name.rsplit(".", 1)[-1]
        for item in source_index.symbols
        if item.kind in _CALLABLE_KINDS
    }
    for call in source_index.call_sites:
        if (
            call.caller_symbol_id in set(relevant_ids)
            and call.callee_symbol_id is None
            and call.callee_reference.rsplit(".", 1)[-1] in known_simple_names
        ):
            diagnostics.append(
                _diagnostic(
                    SemanticDiagnosticCode.RELEVANT_CALL_UNRESOLVED,
                    f"unresolved-call:{call.caller_symbol_id}:{call.callee_reference}",
                    symbol_id=call.caller_symbol_id,
                    path=call.source_location.path,
                )
            )

    source_text: dict[SymbolId, str] = {}
    for symbol_id in relevant_ids:
        try:
            source_text[symbol_id] = _symbol_source(repository_root, symbol_by_id[symbol_id])
        except StaleSourceIndexError:
            symbol = symbol_by_id[symbol_id]
            diagnostics.append(
                _diagnostic(
                    SemanticDiagnosticCode.RELEVANT_SOURCE_UNAVAILABLE,
                    f"source-unavailable:{symbol_id}",
                    symbol_id=symbol_id,
                    path=symbol.source_location.path,
                )
            )

    source_evidence = tuple(
        SemanticContextEvidence(
            kind=SemanticContextEvidenceKind.SOURCE_EXCERPT,
            reference=f"symbol-definition:{symbol_id}",
            fingerprint=fingerprint_json(
                {
                    "symbol_id": symbol_id,
                    "qualified_name": symbol_by_id[symbol_id].qualified_name,
                    "kind": symbol_by_id[symbol_id].kind,
                    "content": source_text.get(symbol_id, "<unavailable>"),
                }
            ),
        )
        for symbol_id in relevant_ids
    )
    call_evidence = tuple(
        SemanticContextEvidence(
            kind=SemanticContextEvidenceKind.PAYMENT_CALL,
            reference=(
                f"resolved-call:{symbol_by_id[item.caller_symbol_id].qualified_name}"
                f"->{symbol_by_id[item.callee_symbol_id].qualified_name}"
                f"@{item.source_location.path}:{item.source_location.line_start}:"
                f"{item.source_location.column_start}"
            ),
            fingerprint=fingerprint_json(
                {
                    "caller": item.caller_symbol_id,
                    "callee": item.callee_symbol_id,
                    "reference": item.callee_reference,
                    "source_location": item.source_location,
                }
            ),
        )
        for item in source_index.call_sites
        if item.caller_symbol_id in set(relevant_ids) and item.callee_symbol_id in set(relevant_ids)
    )
    graph_evidence = tuple(
        SemanticContextEvidence(
            kind=SemanticContextEvidenceKind.GRAPH_FACT,
            reference=f"graph-fact:{item.kind.value}:{item.backing_symbol_id}",
            fingerprint=fingerprint_json(
                {
                    "kind": item.kind,
                    "backing_symbol_id": item.backing_symbol_id,
                    "label": item.label,
                    "details": item.details,
                }
            ),
        )
        for item in structural_graph.nodes
        if item.backing_symbol_id in set(relevant_ids)
        or (
            item.details is not None
            and hasattr(item.details, "route_registration_id")
            and item.details.route_registration_id in relevant_route_ids
        )
    )

    presented: list[SymbolId] = []
    excerpt_bytes = 0
    supporting_ids = sorted(
        (symbol_id for symbol_id in relevant_ids if symbol_id in route_owner_ids),
        key=lambda symbol_id: (distances[symbol_id], symbol_id),
    )
    for symbol_id in supporting_ids:
        content = source_text.get(symbol_id)
        if content is None:
            continue
        size = len(content.encode("utf-8"))
        if excerpt_bytes + size > policy.max_excerpt_bytes:
            diagnostics.append(
                _diagnostic(
                    SemanticDiagnosticCode.EXCERPT_BYTE_LIMIT_REACHED,
                    f"supporting-excerpt-omitted:{symbol_id}",
                    symbol_id=symbol_id,
                )
            )
        else:
            excerpt_bytes += size
    for symbol_id in candidate_ids:
        content = source_text.get(symbol_id)
        if content is None:
            continue
        if len(presented) >= policy.max_presented_candidates:
            diagnostics.append(
                _diagnostic(
                    SemanticDiagnosticCode.CANDIDATE_LIMIT_REACHED,
                    f"candidate-omitted:{symbol_id}",
                    symbol_id=symbol_id,
                )
            )
            continue
        size = len(content.encode("utf-8"))
        if excerpt_bytes + size > policy.max_excerpt_bytes:
            diagnostics.append(
                _diagnostic(
                    SemanticDiagnosticCode.EXCERPT_BYTE_LIMIT_REACHED,
                    f"candidate-excerpt-omitted:{symbol_id}",
                    symbol_id=symbol_id,
                )
            )
            continue
        excerpt_bytes += size
        presented.append(symbol_id)

    diagnostic_tuple = tuple(
        sorted(set(diagnostics), key=lambda item: (item.code.value, item.reference))
    )
    completeness = (
        BundleCompleteness.BUNDLE_PARTIAL
        if diagnostic_tuple
        else BundleCompleteness.BUNDLE_COMPLETE
    )
    descriptor = SemanticContextDescriptor(
        payment_ingress_symbol_ids=seed_ids,
        relevant_symbol_ids=relevant_ids,
        presented_symbol_ids=tuple(presented),
        bundle_completeness=completeness,
        diagnostics=diagnostic_tuple,
        source_excerpts=source_evidence,
        payment_calls=call_evidence,
        graph_neighborhood=graph_evidence,
    )
    if not seed_ids:
        return SemanticContextBuild(descriptor, None, paths, policy)

    excerpts: list[SourceExcerpt] = []
    included_supporting = set()
    consumed = 0
    for symbol_id in supporting_ids:
        content = source_text.get(symbol_id)
        if content is None or consumed + len(content.encode("utf-8")) > policy.max_excerpt_bytes:
            continue
        consumed += len(content.encode("utf-8"))
        included_supporting.add(symbol_id)
        symbol = symbol_by_id[symbol_id]
        excerpts.append(
            SourceExcerpt(
                excerpt_reference=f"src_{symbol_id[6:]}",
                purpose=SourceExcerptPurpose.SUPPORTING,
                symbol_id=symbol_id,
                source_location=symbol.source_location,
                content_fingerprint=sha256_digest(content),
                content=content,
            )
        )
    catalog: list[SemanticCatalogEntry] = []
    for ordinal, symbol_id in enumerate(presented, 1):
        content = source_text[symbol_id]
        symbol = symbol_by_id[symbol_id]
        reference = f"src_{symbol_id[6:]}"
        excerpts.append(
            SourceExcerpt(
                excerpt_reference=reference,
                purpose=SourceExcerptPurpose.CANDIDATE,
                symbol_id=symbol_id,
                source_location=symbol.source_location,
                content_fingerprint=sha256_digest(content),
                content=content,
            )
        )
        catalog.append(
            SemanticCatalogEntry(
                catalog_reference=f"candidate_{ordinal:03d}",
                symbol_id=symbol_id,
                qualified_name=symbol.qualified_name,
                symbol_kind=symbol.kind,
                excerpt_references=(reference,),
            )
        )
    mapping_input = CustomerValueMappingInput(
        project_id=source_index.project_id,
        project_source_fingerprint=source_index.project_source_fingerprint,
        source_index_fingerprint=source_index.source_index_fingerprint,
        graph_fingerprint=structural_graph.graph_fingerprint,
        semantic_context=descriptor,
        catalog=tuple(catalog),
        excerpts=tuple(excerpts),
    )
    return SemanticContextBuild(descriptor, mapping_input, paths, policy)


def build_manual_semantic_context(
    repository_root: Path,
    source_index: SourceIndexArtifact,
    structural_graph: PaymentSafetyGraphArtifact,
    selected_symbol_id: SymbolId,
) -> SemanticContextDescriptor:
    """Build a full deterministic call neighborhood around an exact manual target."""

    validate_indexed_source_snapshot(repository_root, source_index)
    symbols = {item.symbol_id: item for item in source_index.symbols}
    if selected_symbol_id not in symbols:
        raise ValueError("manual semantic target is not indexed")
    adjacent: dict[SymbolId, set[SymbolId]] = defaultdict(set)
    for call in source_index.call_sites:
        if call.callee_symbol_id is not None:
            adjacent[call.caller_symbol_id].add(call.callee_symbol_id)
            adjacent[call.callee_symbol_id].add(call.caller_symbol_id)
    relevant = {selected_symbol_id}
    pending = [selected_symbol_id]
    while pending:
        current = pending.pop()
        for peer in adjacent.get(current, set()):
            if peer not in relevant and peer in symbols and symbols[peer].kind in _CALLABLE_KINDS:
                relevant.add(peer)
                pending.append(peer)
    relevant_ids = tuple(sorted(relevant))
    route_owners = {item.owner_symbol_id for item in source_index.routes}
    ingress_ids = tuple(
        sorted(
            {
                item.backing_symbol_id
                for item in structural_graph.nodes
                if item.kind == GraphNodeKind.PAYMENT_INGRESS
                and item.backing_symbol_id in relevant
                and item.backing_symbol_id in route_owners
            }
        )
    )
    source_evidence = []
    for symbol_id in relevant_ids:
        symbol = symbols[symbol_id]
        content = _symbol_source(repository_root, symbol)
        source_evidence.append(
            SemanticContextEvidence(
                kind=SemanticContextEvidenceKind.SOURCE_EXCERPT,
                reference=f"symbol-definition:{symbol_id}",
                fingerprint=fingerprint_json(
                    {
                        "symbol_id": symbol_id,
                        "qualified_name": symbol.qualified_name,
                        "kind": symbol.kind,
                        "content": content,
                    }
                ),
            )
        )
    calls = tuple(
        SemanticContextEvidence(
            kind=SemanticContextEvidenceKind.PAYMENT_CALL,
            reference=(
                f"resolved-call:{item.caller_symbol_id}:{item.callee_symbol_id}:"
                f"{item.callee_reference}@{item.source_location.path}:"
                f"{item.source_location.line_start}:{item.source_location.column_start}"
            ),
            fingerprint=fingerprint_json(
                {
                    "caller": item.caller_symbol_id,
                    "callee": item.callee_symbol_id,
                    "reference": item.callee_reference,
                    "source_location": item.source_location,
                }
            ),
        )
        for item in source_index.call_sites
        if item.caller_symbol_id in relevant and item.callee_symbol_id in relevant
    )
    graph_facts = tuple(
        SemanticContextEvidence(
            kind=SemanticContextEvidenceKind.GRAPH_FACT,
            reference=f"graph-node:{item.node_id}",
            fingerprint=fingerprint_json(
                {
                    "kind": item.kind,
                    "backing_symbol_id": item.backing_symbol_id,
                    "label": item.label,
                    "details": item.details,
                }
            ),
        )
        for item in structural_graph.nodes
        if item.backing_symbol_id in relevant
    )
    return SemanticContextDescriptor(
        payment_ingress_symbol_ids=ingress_ids,
        relevant_symbol_ids=relevant_ids,
        presented_symbol_ids=(),
        bundle_completeness=BundleCompleteness.BUNDLE_COMPLETE,
        source_excerpts=tuple(source_evidence),
        payment_calls=calls,
        graph_neighborhood=graph_facts,
    )
