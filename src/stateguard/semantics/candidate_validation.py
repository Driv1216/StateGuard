"""Exact deterministic validation of untrusted model candidate references."""

from __future__ import annotations

from dataclasses import dataclass

from stateguard.contracts.common import SymbolId

from .contracts import (
    BundleCompleteness,
    CandidateClassification,
    CandidateRejectionReason,
    RawCustomerValueOutput,
    RejectedSemanticCandidate,
    ResolutionBasis,
    ResolutionState,
    SemanticCandidate,
    SemanticCatalogEntry,
)


@dataclass(frozen=True)
class ModelResolutionDecision:
    state: ResolutionState
    basis: ResolutionBasis
    selected_symbol_id: SymbolId | None


def classify_candidates(
    raw_output: RawCustomerValueOutput,
    catalog: tuple[SemanticCatalogEntry, ...],
) -> CandidateClassification:
    catalogue = {entry.catalog_reference: entry for entry in catalog}
    seen_references: set[str] = set()
    valid: list[SemanticCandidate] = []
    rejected: list[RejectedSemanticCandidate] = []

    for raw in raw_output.candidates:
        reasons: list[CandidateRejectionReason] = []
        entry = catalogue.get(raw.symbol_reference)
        if raw.symbol_reference in seen_references:
            reasons.append(CandidateRejectionReason.DUPLICATE_CANDIDATE)
        seen_references.add(raw.symbol_reference)
        if entry is None:
            reasons.append(CandidateRejectionReason.UNKNOWN_SYMBOL_REFERENCE)
        elif not set(raw.excerpt_references) <= set(entry.excerpt_references):
            reasons.append(CandidateRejectionReason.UNKNOWN_EXCERPT_REFERENCE)

        if reasons:
            rejected.append(RejectedSemanticCandidate(raw_candidate=raw, reasons=tuple(reasons)))
            continue
        assert entry is not None
        valid.append(
            SemanticCandidate(
                catalog_reference=entry.catalog_reference,
                symbol_id=entry.symbol_id,
                rationale=raw.rationale,
                excerpt_references=raw.excerpt_references,
                provider_confidence=raw.provider_confidence,
            )
        )

    return CandidateClassification(
        valid_candidates=tuple(valid), rejected_candidates=tuple(rejected)
    )


def resolve_model_candidates(
    classification: CandidateClassification,
    bundle_completeness: BundleCompleteness = BundleCompleteness.BUNDLE_COMPLETE,
) -> ModelResolutionDecision | None:
    if bundle_completeness == BundleCompleteness.BUNDLE_PARTIAL:
        return None
    candidates = classification.valid_candidates
    if not candidates:
        return ModelResolutionDecision(ResolutionState.UNMAPPED, ResolutionBasis.UNRESOLVED, None)
    if len(candidates) == 1:
        return ModelResolutionDecision(
            ResolutionState.UNIQUE,
            ResolutionBasis.MODEL_UNIQUE,
            candidates[0].symbol_id,
        )
    return ModelResolutionDecision(ResolutionState.AMBIGUOUS, ResolutionBasis.UNRESOLVED, None)
