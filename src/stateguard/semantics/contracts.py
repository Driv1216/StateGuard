"""Contracts for bounded customer-value semantic mapping and resolution."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from stateguard.contracts.common import (
    ArtifactFields,
    ProjectId,
    Sha256Digest,
    SourceLocation,
    SymbolId,
)
from stateguard.discovery.contracts import SymbolKind
from stateguard.model_providers.bounds import DEFAULT_STRUCTURED_GENERATION_BOUNDS
from stateguard.model_providers.protocol import ProviderFailureCode, TokenUsage

MAX_RETURNED_CANDIDATES = DEFAULT_STRUCTURED_GENERATION_BOUNDS.max_structured_items
MAX_RATIONALE_CHARACTERS = DEFAULT_STRUCTURED_GENERATION_BOUNDS.max_explanation_characters
MAX_REFERENCES_PER_CANDIDATE = DEFAULT_STRUCTURED_GENERATION_BOUNDS.max_references_per_item
MAX_REFERENCE_CHARACTERS = DEFAULT_STRUCTURED_GENERATION_BOUNDS.max_reference_characters

_ELIGIBLE_SYMBOL_KINDS = frozenset(
    {SymbolKind.FUNCTION, SymbolKind.ASYNC_FUNCTION, SymbolKind.METHOD, SymbolKind.ASYNC_METHOD}
)


class SemanticBoundaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BundleCompleteness(StrEnum):
    BUNDLE_COMPLETE = "BUNDLE_COMPLETE"
    BUNDLE_PARTIAL = "BUNDLE_PARTIAL"


class SourceExcerptPurpose(StrEnum):
    CANDIDATE = "CANDIDATE"
    SUPPORTING = "SUPPORTING"


class SemanticDiagnosticCode(StrEnum):
    CANDIDATE_LIMIT_REACHED = "CANDIDATE_LIMIT_REACHED"
    EXCERPT_BYTE_LIMIT_REACHED = "EXCERPT_BYTE_LIMIT_REACHED"
    RELEVANT_SOURCE_DIAGNOSTIC = "RELEVANT_SOURCE_DIAGNOSTIC"
    RELEVANT_GRAPH_DIAGNOSTIC = "RELEVANT_GRAPH_DIAGNOSTIC"
    RELEVANT_CALL_UNRESOLVED = "RELEVANT_CALL_UNRESOLVED"
    PAYMENT_INGRESS_UNDETERMINED = "PAYMENT_INGRESS_UNDETERMINED"
    RELEVANT_SOURCE_UNAVAILABLE = "RELEVANT_SOURCE_UNAVAILABLE"
    UNSUPPORTED_INLINE_ACTION = "UNSUPPORTED_INLINE_ACTION"


class SemanticContextDiagnostic(SemanticBoundaryModel):
    code: SemanticDiagnosticCode
    reference: str = Field(min_length=1, max_length=512)
    affected_symbol_id: SymbolId | None = None
    affected_path: str | None = Field(default=None, min_length=1, max_length=2048)
    fingerprint: Sha256Digest

    @field_validator("reference", "affected_path")
    @classmethod
    def strip_optional_text(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None


class SemanticCatalogEntry(SemanticBoundaryModel):
    catalog_reference: str = Field(min_length=1, max_length=MAX_REFERENCE_CHARACTERS)
    symbol_id: SymbolId
    qualified_name: str = Field(min_length=1, max_length=512)
    symbol_kind: SymbolKind
    excerpt_references: tuple[str, ...] = Field(default=(), max_length=MAX_REFERENCES_PER_CANDIDATE)

    @field_validator("catalog_reference", "qualified_name")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_entry(self) -> SemanticCatalogEntry:
        if self.symbol_kind not in _ELIGIBLE_SYMBOL_KINDS:
            raise ValueError("semantic catalog entries must be functions or methods")
        if len(self.excerpt_references) != len(set(self.excerpt_references)):
            raise ValueError("catalog excerpt references must be unique")
        if any(
            not item.strip() or len(item) > MAX_REFERENCE_CHARACTERS
            for item in self.excerpt_references
        ):
            raise ValueError("catalog excerpt references must be bounded and non-blank")
        return self


class SourceExcerpt(SemanticBoundaryModel):
    excerpt_reference: str = Field(min_length=1, max_length=MAX_REFERENCE_CHARACTERS)
    purpose: SourceExcerptPurpose
    symbol_id: SymbolId
    source_location: SourceLocation
    content_fingerprint: Sha256Digest
    content: str = Field(min_length=1)

    @field_validator("excerpt_reference")
    @classmethod
    def normalize_excerpt_reference(cls, value: str) -> str:
        return value.strip()

    @field_validator("content")
    @classmethod
    def preserve_non_blank_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("excerpt fields must not be blank")
        return value


class SemanticContextEvidenceKind(StrEnum):
    SOURCE_EXCERPT = "SOURCE_EXCERPT"
    PAYMENT_CALL = "PAYMENT_CALL"
    GRAPH_FACT = "GRAPH_FACT"


class SemanticContextEvidence(SemanticBoundaryModel):
    kind: SemanticContextEvidenceKind
    reference: str = Field(min_length=1, max_length=1024)
    fingerprint: Sha256Digest

    @field_validator("reference")
    @classmethod
    def strip_reference(cls, value: str) -> str:
        return value.strip()


class SemanticContextDescriptor(SemanticBoundaryModel):
    schema_version: Literal[2] = 2
    payment_ingress_symbol_ids: tuple[SymbolId, ...] = ()
    relevant_symbol_ids: tuple[SymbolId, ...]
    presented_symbol_ids: tuple[SymbolId, ...]
    bundle_completeness: BundleCompleteness
    diagnostics: tuple[SemanticContextDiagnostic, ...] = ()
    source_excerpts: tuple[SemanticContextEvidence, ...] = ()
    payment_calls: tuple[SemanticContextEvidence, ...] = ()
    graph_neighborhood: tuple[SemanticContextEvidence, ...] = ()

    @model_validator(mode="after")
    def validate_context(self) -> SemanticContextDescriptor:
        groups = (
            self.payment_ingress_symbol_ids,
            self.relevant_symbol_ids,
            self.presented_symbol_ids,
        )
        if any(len(group) != len(set(group)) for group in groups):
            raise ValueError("semantic-context symbol collections must be unique")
        relevant = set(self.relevant_symbol_ids)
        if not set(self.payment_ingress_symbol_ids) <= relevant:
            raise ValueError("payment ingress symbols must be relevant")
        if not set(self.presented_symbol_ids) <= relevant:
            raise ValueError("presented symbols must be relevant")
        if set(self.payment_ingress_symbol_ids) & set(self.presented_symbol_ids):
            raise ValueError("payment ingress route owners cannot be presented candidates")
        if self.bundle_completeness == BundleCompleteness.BUNDLE_COMPLETE and self.diagnostics:
            raise ValueError("complete semantic bundles cannot contain known omissions")
        if self.bundle_completeness == BundleCompleteness.BUNDLE_PARTIAL and not self.diagnostics:
            raise ValueError("partial semantic bundles require omission diagnostics")
        evidence_groups = (
            (self.source_excerpts, SemanticContextEvidenceKind.SOURCE_EXCERPT),
            (self.payment_calls, SemanticContextEvidenceKind.PAYMENT_CALL),
            (self.graph_neighborhood, SemanticContextEvidenceKind.GRAPH_FACT),
        )
        for records, expected_kind in evidence_groups:
            if any(record.kind != expected_kind for record in records):
                raise ValueError(f"semantic-context evidence must be {expected_kind.value}")
            keys = [(record.reference, record.fingerprint) for record in records]
            if len(keys) != len(set(keys)):
                raise ValueError("semantic-context evidence records must be unique")
        return self


class CustomerValueMappingInput(SemanticBoundaryModel):
    project_id: ProjectId
    project_source_fingerprint: Sha256Digest
    source_index_fingerprint: Sha256Digest
    graph_fingerprint: Sha256Digest
    semantic_context: SemanticContextDescriptor
    catalog: tuple[SemanticCatalogEntry, ...]
    excerpts: tuple[SourceExcerpt, ...]

    @model_validator(mode="after")
    def validate_mapping_input(self) -> CustomerValueMappingInput:
        catalog_refs = [item.catalog_reference for item in self.catalog]
        symbol_ids = [item.symbol_id for item in self.catalog]
        excerpt_refs = [item.excerpt_reference for item in self.excerpts]
        if len(catalog_refs) != len(set(catalog_refs)):
            raise ValueError("semantic catalog references must be unique")
        if len(symbol_ids) != len(set(symbol_ids)):
            raise ValueError("semantic catalog symbol IDs must be unique")
        if len(excerpt_refs) != len(set(excerpt_refs)):
            raise ValueError("source excerpt references must be unique")
        if set(symbol_ids) != set(self.semantic_context.presented_symbol_ids):
            raise ValueError("semantic catalog must match presented context symbols")
        if set(symbol_ids) & set(self.semantic_context.payment_ingress_symbol_ids):
            raise ValueError("route owners cannot be customer-value candidates")
        known_excerpts = {item.excerpt_reference: item for item in self.excerpts}
        for entry in self.catalog:
            if not set(entry.excerpt_references) <= set(known_excerpts):
                raise ValueError("catalog entry refers to an unknown excerpt")
            if any(
                known_excerpts[reference].purpose != SourceExcerptPurpose.CANDIDATE
                or known_excerpts[reference].symbol_id != entry.symbol_id
                for reference in entry.excerpt_references
            ):
                raise ValueError("catalog entries may cite only their candidate excerpts")
        for excerpt in self.excerpts:
            if excerpt.purpose == SourceExcerptPurpose.CANDIDATE:
                if excerpt.symbol_id not in set(symbol_ids):
                    raise ValueError("candidate excerpt refers outside the catalog")
            elif excerpt.symbol_id not in set(self.semantic_context.relevant_symbol_ids):
                raise ValueError("supporting excerpt refers outside relevant context")
        return self


class RawCustomerValueCandidate(SemanticBoundaryModel):
    symbol_reference: str = Field(min_length=1, max_length=MAX_REFERENCE_CHARACTERS)
    rationale: str = Field(min_length=1, max_length=MAX_RATIONALE_CHARACTERS)
    excerpt_references: tuple[str, ...] = Field(max_length=MAX_REFERENCES_PER_CANDIDATE)
    provider_confidence: float | None = Field(ge=0.0, le=1.0)

    @field_validator("symbol_reference", "rationale")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()

    @field_validator("excerpt_references")
    @classmethod
    def validate_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() or len(item) > MAX_REFERENCE_CHARACTERS for item in value):
            raise ValueError("candidate references must be bounded and non-blank")
        return value


class RawCustomerValueOutput(SemanticBoundaryModel):
    candidates: tuple[RawCustomerValueCandidate, ...] = Field(max_length=MAX_RETURNED_CANDIDATES)


class SemanticCandidate(SemanticBoundaryModel):
    catalog_reference: str = Field(min_length=1, max_length=MAX_REFERENCE_CHARACTERS)
    symbol_id: SymbolId
    rationale: str = Field(min_length=1, max_length=MAX_RATIONALE_CHARACTERS)
    excerpt_references: tuple[str, ...] = Field(max_length=MAX_REFERENCES_PER_CANDIDATE)
    provider_confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("catalog_reference", "rationale")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def validate_excerpt_references(self) -> SemanticCandidate:
        if len(self.excerpt_references) != len(set(self.excerpt_references)):
            raise ValueError("semantic candidate excerpt references must be unique")
        if any(
            not item.strip() or len(item) > MAX_REFERENCE_CHARACTERS
            for item in self.excerpt_references
        ):
            raise ValueError("semantic candidate references must be bounded and non-blank")
        return self


class CandidateRejectionReason(StrEnum):
    UNKNOWN_SYMBOL_REFERENCE = "UNKNOWN_SYMBOL_REFERENCE"
    UNKNOWN_EXCERPT_REFERENCE = "UNKNOWN_EXCERPT_REFERENCE"
    DUPLICATE_CANDIDATE = "DUPLICATE_CANDIDATE"


class RejectedSemanticCandidate(SemanticBoundaryModel):
    raw_candidate: RawCustomerValueCandidate
    reasons: tuple[CandidateRejectionReason, ...] = Field(min_length=1)


class CandidateClassification(SemanticBoundaryModel):
    valid_candidates: tuple[SemanticCandidate, ...]
    rejected_candidates: tuple[RejectedSemanticCandidate, ...]


class ResolutionState(StrEnum):
    UNIQUE = "UNIQUE"
    AMBIGUOUS = "AMBIGUOUS"
    UNMAPPED = "UNMAPPED"


class ResolutionBasis(StrEnum):
    MODEL_UNIQUE = "MODEL_UNIQUE"
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"
    MANUAL_SELECTION = "MANUAL_SELECTION"
    UNRESOLVED = "UNRESOLVED"


class CustomerValueResolution(SemanticBoundaryModel):
    state: ResolutionState
    basis: ResolutionBasis
    selected_symbol_id: SymbolId | None = None

    @model_validator(mode="after")
    def validate_resolution(self) -> CustomerValueResolution:
        if self.state == ResolutionState.UNIQUE:
            if self.selected_symbol_id is None or self.basis == ResolutionBasis.UNRESOLVED:
                raise ValueError("UNIQUE requires a selected symbol and resolved basis")
        elif self.selected_symbol_id is not None or self.basis != ResolutionBasis.UNRESOLVED:
            raise ValueError("unresolved states cannot select a symbol or resolved basis")
        return self


class HumanResolutionAudit(SemanticBoundaryModel):
    selected_symbol_id: SymbolId
    basis: Literal[ResolutionBasis.HUMAN_CONFIRMED, ResolutionBasis.MANUAL_SELECTION]
    acted_at: datetime

    @field_validator("acted_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("human audit time must be timezone-aware")
        return value


class ModelAttemptAudit(SemanticBoundaryModel):
    provider_id: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=512)
    request_fingerprint: Sha256Digest
    attempt_count: int = Field(ge=1)
    latency_ms: int | None = Field(default=None, ge=0)
    token_usage: TokenUsage | None = None


class NormalizedProviderFailure(SemanticBoundaryModel):
    code: ProviderFailureCode
    status_code: int | None = Field(default=None, ge=100, le=599)


class SemanticBundleAudit(SemanticBoundaryModel):
    policy_version: str = Field(min_length=1, max_length=128)
    max_presented_candidates: int = Field(gt=0)
    max_excerpt_bytes: int = Field(gt=0)
    max_output_tokens: int = Field(gt=0)
    max_response_bytes: int = Field(gt=0)


class CustomerValueSemanticArtifact(ArtifactFields):
    artifact_type: Literal["CUSTOMER_VALUE_SEMANTICS"] = "CUSTOMER_VALUE_SEMANTICS"
    schema_version: Literal[2] = 2
    project_id: ProjectId
    project_source_fingerprint: Sha256Digest
    source_index_fingerprint: Sha256Digest
    structural_graph_fingerprint: Sha256Digest
    context: SemanticContextDescriptor
    semantic_context_fingerprint: Sha256Digest
    bundle_policy: SemanticBundleAudit
    provider_bundle_fingerprint: Sha256Digest | None = None
    model_attempt: ModelAttemptAudit | None = None
    provider_failure: NormalizedProviderFailure | None = None
    valid_candidates: tuple[SemanticCandidate, ...] = ()
    rejected_candidates: tuple[RejectedSemanticCandidate, ...] = ()
    partial_bundle_suggestions: tuple[SemanticCandidate, ...] = ()
    resolution: CustomerValueResolution | None = None
    resolution_fingerprint: Sha256Digest | None = None
    human_audit: HumanResolutionAudit | None = None

    @model_validator(mode="after")
    def validate_artifact(self) -> CustomerValueSemanticArtifact:
        groups = (self.valid_candidates, self.partial_bundle_suggestions)
        if any(len(group) != len({item.symbol_id for item in group}) for group in groups):
            raise ValueError("semantic candidates must be unique by symbol")
        if self.context.bundle_completeness == BundleCompleteness.BUNDLE_PARTIAL:
            if self.valid_candidates:
                raise ValueError("partial bundles cannot contain authoritative valid candidates")
            if self.resolution is not None and self.resolution.basis in {
                ResolutionBasis.MODEL_UNIQUE,
                ResolutionBasis.UNRESOLVED,
            }:
                raise ValueError("partial bundles cannot create automatic resolution")
        if self.provider_failure is not None and self.model_attempt is None:
            raise ValueError("provider failure requires a recorded model attempt")
        if self.resolution is None:
            if self.resolution_fingerprint is not None or self.human_audit is not None:
                raise ValueError("resolution evidence requires a resolution")
        else:
            if self.resolution_fingerprint is None:
                raise ValueError("resolved semantic artifacts require a resolution fingerprint")
            human_basis = self.resolution.basis in {
                ResolutionBasis.HUMAN_CONFIRMED,
                ResolutionBasis.MANUAL_SELECTION,
            }
            if human_basis != (self.human_audit is not None):
                raise ValueError("human resolution and audit metadata must appear together")
            if self.human_audit is not None and (
                self.human_audit.selected_symbol_id != self.resolution.selected_symbol_id
                or self.human_audit.basis != self.resolution.basis
            ):
                raise ValueError("human audit must match the authoritative resolution")
        return self
