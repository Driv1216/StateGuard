"""Step 3 customer-value semantic resolution use cases."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from stateguard import __version__
from stateguard.contracts.common import Sha256Digest
from stateguard.contracts.config import (
    ConfirmedCustomerValueConfig,
    HumanResolutionBasis,
    StateGuardConfig,
)
from stateguard.discovery.contracts import SourceIndexArtifact, SymbolKind, SymbolRecord
from stateguard.discovery.service import discover_and_index_project
from stateguard.graph.contracts import PaymentSafetyGraphArtifact
from stateguard.graph.semantic_projection import project_customer_value
from stateguard.graph.service import construct_payment_safety_graph
from stateguard.model_providers.factory import create_model_provider
from stateguard.model_providers.protocol import ModelProviderError
from stateguard.semantics.context import (
    resolution_fingerprint,
    semantic_context_fingerprint,
)
from stateguard.semantics.context_builder import (
    SemanticContextBuild,
    build_manual_semantic_context,
    build_semantic_context,
)
from stateguard.semantics.contracts import (
    BundleCompleteness,
    CustomerValueResolution,
    CustomerValueSemanticArtifact,
    HumanResolutionAudit,
    ModelAttemptAudit,
    NormalizedProviderFailure,
    RejectedSemanticCandidate,
    ResolutionBasis,
    ResolutionState,
    SemanticBundleAudit,
    SemanticCandidate,
    SemanticContextDescriptor,
)
from stateguard.semantics.mapper import (
    SemanticMappingResult,
    map_customer_value,
    prepare_semantic_request,
)
from stateguard.workspace.config import load_config
from stateguard.workspace.config_edit import write_customer_value_confirmation
from stateguard.workspace.semantic_artifacts import (
    load_semantic_artifact,
    write_semantic_artifact,
)

_ELIGIBLE_KINDS = frozenset(
    {SymbolKind.FUNCTION, SymbolKind.ASYNC_FUNCTION, SymbolKind.METHOD, SymbolKind.ASYNC_METHOD}
)


class SemanticSelectionError(ValueError):
    """A requested customer-value symbol is not an eligible current selection."""


def _bundle_audit(context_build: SemanticContextBuild) -> SemanticBundleAudit:
    policy = context_build.policy
    return SemanticBundleAudit(
        policy_version=policy.version,
        max_presented_candidates=policy.max_presented_candidates,
        max_excerpt_bytes=policy.max_excerpt_bytes,
        max_output_tokens=policy.max_output_tokens,
        max_response_bytes=policy.max_response_bytes,
    )


@dataclass(frozen=True)
class SemanticUseCaseResult:
    source_index: SourceIndexArtifact
    structural_graph: PaymentSafetyGraphArtifact
    graph: PaymentSafetyGraphArtifact
    artifact: CustomerValueSemanticArtifact


@dataclass(frozen=True)
class CurrentSemanticSnapshot:
    """Fresh deterministic inputs plus only a current persisted semantic decision."""

    source_index: SourceIndexArtifact
    structural_graph: PaymentSafetyGraphArtifact
    graph: PaymentSafetyGraphArtifact
    artifact: CustomerValueSemanticArtifact | None
    resolution: CustomerValueResolution | None
    resolution_fingerprint: Sha256Digest | None


@dataclass(frozen=True)
class _ReusableAIEvidence:
    candidates: tuple[SemanticCandidate, ...]
    provider_bundle_fingerprint: Sha256Digest
    model_attempt: ModelAttemptAudit


def _fresh_pipeline(
    repository_root: Path,
    config: StateGuardConfig,
    timestamp: datetime,
) -> tuple[SourceIndexArtifact, PaymentSafetyGraphArtifact, SemanticContextBuild]:
    source_index = discover_and_index_project(
        repository_root, config, generated_at=timestamp
    ).source_index
    graph = construct_payment_safety_graph(repository_root, source_index, generated_at=timestamp)
    return source_index, graph, build_semantic_context(repository_root, source_index, graph)


def _reusable_ai_evidence(
    config: StateGuardConfig,
    context_build: SemanticContextBuild,
    descriptor: SemanticContextDescriptor,
    semantic_fingerprint: Sha256Digest,
    prior: CustomerValueSemanticArtifact | None,
) -> _ReusableAIEvidence | None:
    """Return prior candidates only for the same exact provider request identity."""

    if (
        prior is None
        or prior.semantic_context_fingerprint != semantic_fingerprint
        or descriptor != context_build.descriptor
        or config.ai is None
        or context_build.mapping_input is None
        or prior.provider_bundle_fingerprint is None
        or prior.model_attempt is None
    ):
        return None
    prepared = prepare_semantic_request(
        context_build.mapping_input,
        model=config.ai.model,
        policy=context_build.policy,
    )
    attempt = prior.model_attempt
    if (
        attempt.provider_id != config.ai.provider
        or attempt.model != config.ai.model
        or attempt.request_fingerprint != prepared.request_fingerprint
        or prior.provider_bundle_fingerprint != prepared.provider_bundle_fingerprint
    ):
        return None
    candidates = (*prior.valid_candidates, *prior.partial_bundle_suggestions)
    if not candidates:
        return None
    return _ReusableAIEvidence(
        candidates=candidates,
        provider_bundle_fingerprint=prior.provider_bundle_fingerprint,
        model_attempt=attempt,
    )


def _eligible_symbol(
    source_index: SourceIndexArtifact,
    symbol_id: str,
) -> SymbolRecord | None:
    route_owners = {item.owner_symbol_id for item in source_index.routes}
    return next(
        (
            item
            for item in source_index.symbols
            if item.symbol_id == symbol_id
            and item.kind in _ELIGIBLE_KINDS
            and item.symbol_id not in route_owners
        ),
        None,
    )


def _current_human_resolution(
    repository_root: Path,
    config: StateGuardConfig,
    source_index: SourceIndexArtifact,
    graph: PaymentSafetyGraphArtifact,
    context_build: SemanticContextBuild,
    timestamp: datetime,
    prior_artifact: CustomerValueSemanticArtifact | None,
) -> (
    tuple[
        CustomerValueResolution,
        SemanticContextDescriptor,
        Sha256Digest,
        HumanResolutionAudit,
    ]
    | None
):
    confirmation = config.semantics.customer_value if config.semantics is not None else None
    if confirmation is None:
        return None
    symbol = _eligible_symbol(source_index, confirmation.symbol_id)
    if symbol is None:
        return None
    descriptor = (
        context_build.descriptor
        if symbol.symbol_id in set(context_build.descriptor.relevant_symbol_ids)
        else build_manual_semantic_context(repository_root, source_index, graph, symbol.symbol_id)
    )
    fingerprint = semantic_context_fingerprint(descriptor)
    if fingerprint != confirmation.semantic_context_fingerprint:
        return None
    basis = ResolutionBasis(confirmation.basis.value)
    resolution = CustomerValueResolution(
        state=ResolutionState.UNIQUE,
        basis=basis,
        selected_symbol_id=symbol.symbol_id,
    )
    audit = HumanResolutionAudit(
        selected_symbol_id=symbol.symbol_id,
        basis=basis,
        acted_at=timestamp,
    )
    if (
        prior_artifact is not None
        and prior_artifact.semantic_context_fingerprint == fingerprint
        and prior_artifact.resolution == resolution
        and prior_artifact.human_audit is not None
    ):
        audit = prior_artifact.human_audit
    return (
        resolution,
        descriptor,
        resolution_fingerprint(resolution, fingerprint),
        audit,
    )


async def resolve_customer_value(
    repository_root: Path,
    config_path: Path,
    *,
    generated_at: datetime | None = None,
) -> SemanticUseCaseResult:
    """Rebuild evidence and resolve without overriding a current human decision."""

    timestamp = generated_at or datetime.now(UTC)
    config = load_config(config_path)
    source_index, structural_graph, context_build = _fresh_pipeline(
        repository_root, config, timestamp
    )
    semantic_fp = semantic_context_fingerprint(context_build.descriptor)
    prior_artifact = load_semantic_artifact(repository_root)
    current_human = _current_human_resolution(
        repository_root,
        config,
        source_index,
        structural_graph,
        context_build,
        timestamp,
        prior_artifact,
    )
    if current_human is not None:
        human_resolution, descriptor, human_resolution_fp, audit = current_human
        artifact = CustomerValueSemanticArtifact(
            producer_version=__version__,
            generated_at=timestamp,
            project_id=source_index.project_id,
            project_source_fingerprint=source_index.project_source_fingerprint,
            source_index_fingerprint=source_index.source_index_fingerprint,
            structural_graph_fingerprint=structural_graph.graph_fingerprint,
            context=descriptor,
            semantic_context_fingerprint=semantic_context_fingerprint(descriptor),
            bundle_policy=_bundle_audit(context_build),
            resolution=human_resolution,
            resolution_fingerprint=human_resolution_fp,
            human_audit=audit,
        )
        projected = project_customer_value(
            structural_graph,
            source_index,
            human_resolution,
            human_resolution_fp,
            repository_root=repository_root,
        )
        write_semantic_artifact(repository_root, artifact)
        return SemanticUseCaseResult(source_index, structural_graph, projected, artifact)

    mapping = context_build.mapping_input
    mapping_result: SemanticMappingResult | None = None
    provider_failure: NormalizedProviderFailure | None = None
    model_attempt: ModelAttemptAudit | None = None
    bundle_fp = None
    if config.ai is not None and mapping is not None:
        prepared = prepare_semantic_request(
            mapping, model=config.ai.model, policy=context_build.policy
        )
        bundle_fp = prepared.provider_bundle_fingerprint
        try:
            provider = create_model_provider(config.ai)
            try:
                mapping_result = await map_customer_value(
                    provider,
                    mapping,
                    model=config.ai.model,
                    policy=context_build.policy,
                )
            finally:
                close = getattr(provider, "aclose", None)
                if close is not None:
                    await close()
        except ModelProviderError as exc:
            provider_failure = NormalizedProviderFailure(
                code=exc.code,
                status_code=exc.status_code,
            )
            model_attempt = ModelAttemptAudit(
                provider_id=config.ai.provider,
                model=config.ai.model,
                request_fingerprint=prepared.request_fingerprint,
                attempt_count=1,
            )
        else:
            assert mapping_result is not None
            model_attempt = ModelAttemptAudit(
                provider_id=mapping_result.provider_result.provider_id,
                model=mapping_result.provider_result.model,
                request_fingerprint=mapping_result.prepared.request_fingerprint,
                attempt_count=1,
                latency_ms=mapping_result.provider_result.latency_ms,
                token_usage=mapping_result.provider_result.token_usage,
            )

    valid_candidates: tuple[SemanticCandidate, ...] = ()
    rejected_candidates: tuple[RejectedSemanticCandidate, ...] = ()
    suggestions: tuple[SemanticCandidate, ...] = ()
    resolution: CustomerValueResolution | None = None
    resolution_fp: Sha256Digest | None = None
    if mapping_result is not None:
        rejected_candidates = mapping_result.classification.rejected_candidates
        if context_build.descriptor.bundle_completeness == BundleCompleteness.BUNDLE_PARTIAL:
            suggestions = mapping_result.classification.valid_candidates
        else:
            valid_candidates = mapping_result.classification.valid_candidates
            decision = mapping_result.decision
            assert decision is not None
            resolution = CustomerValueResolution(
                state=decision.state,
                basis=decision.basis,
                selected_symbol_id=decision.selected_symbol_id,
            )
            resolution_fp = resolution_fingerprint(resolution, semantic_fp)
    artifact = CustomerValueSemanticArtifact(
        producer_version=__version__,
        generated_at=timestamp,
        project_id=source_index.project_id,
        project_source_fingerprint=source_index.project_source_fingerprint,
        source_index_fingerprint=source_index.source_index_fingerprint,
        structural_graph_fingerprint=structural_graph.graph_fingerprint,
        context=context_build.descriptor,
        semantic_context_fingerprint=semantic_fp,
        bundle_policy=_bundle_audit(context_build),
        provider_bundle_fingerprint=bundle_fp,
        model_attempt=model_attempt,
        provider_failure=provider_failure,
        valid_candidates=valid_candidates,
        rejected_candidates=rejected_candidates,
        partial_bundle_suggestions=suggestions,
        resolution=resolution,
        resolution_fingerprint=resolution_fp,
    )
    projected = (
        project_customer_value(
            structural_graph,
            source_index,
            resolution,
            resolution_fp,
            repository_root=repository_root,
        )
        if resolution is not None
        and resolution.state == ResolutionState.UNIQUE
        and resolution_fp is not None
        else structural_graph
    )
    write_semantic_artifact(repository_root, artifact)
    return SemanticUseCaseResult(source_index, structural_graph, projected, artifact)


async def confirm_customer_value(
    repository_root: Path,
    config_path: Path,
    symbol_reference: str,
    *,
    generated_at: datetime | None = None,
) -> SemanticUseCaseResult:
    """Persist an exact current non-route callable as human semantic authority."""

    timestamp = generated_at or datetime.now(UTC)
    config = load_config(config_path)
    source_index, structural_graph, context_build = _fresh_pipeline(
        repository_root, config, timestamp
    )
    exact_id = [item for item in source_index.symbols if item.symbol_id == symbol_reference]
    exact_name = [item for item in source_index.symbols if item.qualified_name == symbol_reference]
    matches = exact_id or exact_name
    if len(matches) != 1:
        raise SemanticSelectionError("--symbol must identify exactly one current indexed callable")
    symbol = matches[0]
    route_owners = {item.owner_symbol_id for item in source_index.routes}
    if symbol.symbol_id in route_owners:
        raise SemanticSelectionError(
            "route handlers are unsupported inline customer-value actions in Step 3"
        )
    if symbol.kind not in _ELIGIBLE_KINDS:
        raise SemanticSelectionError("customer value must be a current function or method")
    descriptor = (
        context_build.descriptor
        if symbol.symbol_id in set(context_build.descriptor.relevant_symbol_ids)
        else build_manual_semantic_context(
            repository_root, source_index, structural_graph, symbol.symbol_id
        )
    )
    semantic_fp = semantic_context_fingerprint(descriptor)
    prior = load_semantic_artifact(repository_root)
    reusable_ai = _reusable_ai_evidence(
        config,
        context_build,
        descriptor,
        semantic_fp,
        prior,
    )
    prior_candidates = reusable_ai.candidates if reusable_ai is not None else ()
    basis = (
        ResolutionBasis.HUMAN_CONFIRMED
        if symbol.symbol_id in {item.symbol_id for item in prior_candidates}
        else ResolutionBasis.MANUAL_SELECTION
    )
    resolution = CustomerValueResolution(
        state=ResolutionState.UNIQUE,
        basis=basis,
        selected_symbol_id=symbol.symbol_id,
    )
    resolution_fp = resolution_fingerprint(resolution, semantic_fp)
    audit = HumanResolutionAudit(
        selected_symbol_id=symbol.symbol_id,
        basis=basis,
        acted_at=timestamp,
    )
    artifact = CustomerValueSemanticArtifact(
        producer_version=__version__,
        generated_at=timestamp,
        project_id=source_index.project_id,
        project_source_fingerprint=source_index.project_source_fingerprint,
        source_index_fingerprint=source_index.source_index_fingerprint,
        structural_graph_fingerprint=structural_graph.graph_fingerprint,
        context=descriptor,
        semantic_context_fingerprint=semantic_fp,
        bundle_policy=_bundle_audit(context_build),
        provider_bundle_fingerprint=(
            reusable_ai.provider_bundle_fingerprint if reusable_ai is not None else None
        ),
        model_attempt=reusable_ai.model_attempt if reusable_ai is not None else None,
        valid_candidates=(
            prior_candidates
            if basis == ResolutionBasis.HUMAN_CONFIRMED
            and descriptor.bundle_completeness == BundleCompleteness.BUNDLE_COMPLETE
            else ()
        ),
        partial_bundle_suggestions=(
            prior_candidates
            if basis == ResolutionBasis.HUMAN_CONFIRMED
            and descriptor.bundle_completeness == BundleCompleteness.BUNDLE_PARTIAL
            else ()
        ),
        resolution=resolution,
        resolution_fingerprint=resolution_fp,
        human_audit=audit,
    )
    confirmation = ConfirmedCustomerValueConfig(
        symbol_id=symbol.symbol_id,
        semantic_context_fingerprint=semantic_fp,
        basis=HumanResolutionBasis(basis.value),
    )
    write_customer_value_confirmation(config_path, confirmation)
    write_semantic_artifact(repository_root, artifact)
    projected = project_customer_value(
        structural_graph,
        source_index,
        resolution,
        resolution_fp,
        repository_root=repository_root,
    )
    return SemanticUseCaseResult(source_index, structural_graph, projected, artifact)


def rebuild_current_semantic_snapshot(
    repository_root: Path,
    config: StateGuardConfig,
    *,
    generated_at: datetime | None = None,
) -> CurrentSemanticSnapshot:
    """Rebuild static truth without calling a provider or mutating persisted state."""

    timestamp = generated_at or datetime.now(UTC)
    source_index, structural_graph, context_build = _fresh_pipeline(
        repository_root, config, timestamp
    )
    prior = load_semantic_artifact(repository_root)
    current_human = _current_human_resolution(
        repository_root,
        config,
        source_index,
        structural_graph,
        context_build,
        timestamp,
        prior,
    )
    if current_human is not None:
        resolution, descriptor, resolution_fp, _ = current_human
        graph = project_customer_value(
            structural_graph,
            source_index,
            resolution,
            resolution_fp,
            repository_root=repository_root,
        )
        current_artifact = prior
        if (
            current_artifact is None
            or current_artifact.resolution != resolution
            or current_artifact.semantic_context_fingerprint
            != semantic_context_fingerprint(descriptor)
        ):
            current_artifact = None
        return CurrentSemanticSnapshot(
            source_index,
            structural_graph,
            graph,
            current_artifact,
            resolution,
            resolution_fp,
        )

    current_context_fp = semantic_context_fingerprint(context_build.descriptor)
    current = (
        prior
        if prior is not None
        and prior.project_id == source_index.project_id
        and prior.project_source_fingerprint == source_index.project_source_fingerprint
        and prior.source_index_fingerprint == source_index.source_index_fingerprint
        and prior.structural_graph_fingerprint == structural_graph.graph_fingerprint
        and prior.semantic_context_fingerprint == current_context_fp
        else None
    )
    if (
        current is None
        or current.resolution is None
        or current.resolution.state != ResolutionState.UNIQUE
        or current.resolution_fingerprint is None
    ):
        return CurrentSemanticSnapshot(
            source_index,
            structural_graph,
            structural_graph,
            current,
            current.resolution if current is not None else None,
            current.resolution_fingerprint if current is not None else None,
        )
    graph = project_customer_value(
        structural_graph,
        source_index,
        current.resolution,
        current.resolution_fingerprint,
        repository_root=repository_root,
    )
    return CurrentSemanticSnapshot(
        source_index,
        structural_graph,
        graph,
        current,
        current.resolution,
        current.resolution_fingerprint,
    )
