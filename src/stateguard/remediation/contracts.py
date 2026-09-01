"""Ephemeral Step 10 remediation and exact comparison contracts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from stateguard.contracts.common import (
    FindingOccurrenceId,
    Sha256Digest,
    VerificationCheckId,
    VerificationCheckKey,
    VerificationRunId,
    normalize_relative_path,
)
from stateguard.evidence.contracts import VerificationRun
from stateguard.model_providers.bounds import DEFAULT_STRUCTURED_GENERATION_BOUNDS

_BOUNDS = DEFAULT_STRUCTURED_GENERATION_BOUNDS


class RemediationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AssistanceMode(StrEnum):
    CURRENT_SOURCE_REMEDIATION = "CURRENT_SOURCE_REMEDIATION"
    HISTORICAL_EXPLANATION_ONLY = "HISTORICAL_EXPLANATION_ONLY"


class ProposalState(StrEnum):
    PROPOSED = "PROPOSED"
    NO_SAFE_PROPOSAL = "NO_SAFE_PROPOSAL"
    BLOCKED_CURRENT_SOURCE_AUTHORITY = "BLOCKED_CURRENT_SOURCE_AUTHORITY"


class ProposalVerificationState(StrEnum):
    AI_GENERATED_NOT_VERIFIED = "AI_GENERATED_NOT_VERIFIED"


class EditableRegionKind(StrEnum):
    FULL_SYMBOL = "FULL_SYMBOL"
    IMPORT_REGION = "IMPORT_REGION"
    INSERTION_ANCHOR = "INSERTION_ANCHOR"


class GroundingReference(RemediationModel):
    reference: str = Field(min_length=1, max_length=_BOUNDS.max_reference_characters)
    description: str = Field(min_length=1, max_length=_BOUNDS.max_explanation_characters)


class GroundedClaim(RemediationModel):
    text: str = Field(min_length=1, max_length=_BOUNDS.max_explanation_characters)
    references: tuple[str, ...] = Field(
        min_length=1,
        max_length=_BOUNDS.max_references_per_item,
    )

    @field_validator("text")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class RawStructuredEdit(RemediationModel):
    region_reference: str = Field(
        min_length=1,
        max_length=_BOUNDS.max_reference_characters,
    )
    replacement_content: str = Field(min_length=1)


class RawRemediationOutput(RemediationModel):
    causal_summary: str = Field(min_length=1, max_length=_BOUNDS.max_explanation_characters)
    grounded_claims: tuple[GroundedClaim, ...] = Field(
        min_length=1,
        max_length=_BOUNDS.max_structured_items,
    )
    remediation_rationale: str | None = Field(
        default=None,
        max_length=_BOUNDS.max_explanation_characters,
    )
    proposal_state: ProposalState
    edits: tuple[RawStructuredEdit, ...] = Field(
        default=(),
        max_length=_BOUNDS.max_structured_items,
    )
    limitations: tuple[str, ...] = Field(
        default=(),
        max_length=_BOUNDS.max_structured_items,
    )

    @model_validator(mode="after")
    def validate_proposal_shape(self) -> RawRemediationOutput:
        if self.proposal_state == ProposalState.PROPOSED:
            if not self.edits or self.remediation_rationale is None:
                raise ValueError("proposed remediation requires edits and rationale")
        elif self.edits:
            raise ValueError("non-proposal output cannot contain edits")
        if len({item.region_reference for item in self.edits}) != len(self.edits):
            raise ValueError("one replacement is allowed per editable region")
        if any(
            not item.strip() or len(item) > _BOUNDS.max_explanation_characters
            for item in self.limitations
        ):
            raise ValueError("limitations must be bounded and non-blank")
        return self


class EditableRegion(RemediationModel):
    region_reference: str = Field(
        min_length=1,
        max_length=_BOUNDS.max_reference_characters,
    )
    kind: EditableRegionKind
    path: str
    start_offset: int = Field(ge=0)
    end_offset: int = Field(ge=0)
    file_fingerprint: Sha256Digest
    region_fingerprint: Sha256Digest
    content: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        path = normalize_relative_path(value)
        if not path.endswith(".py"):
            raise ValueError("editable regions require Python source")
        return path

    @model_validator(mode="after")
    def validate_offsets(self) -> EditableRegion:
        if self.end_offset < self.start_offset:
            raise ValueError("editable region end cannot precede start")
        return self


class StructuredEditPreview(RemediationModel):
    region_reference: str
    path: str
    kind: EditableRegionKind
    original_region_fingerprint: Sha256Digest
    replacement_fingerprint: Sha256Digest


class PatchPreview(RemediationModel):
    verification_state: ProposalVerificationState = (
        ProposalVerificationState.AI_GENERATED_NOT_VERIFIED
    )
    diff: str = Field(min_length=1)
    edits: tuple[StructuredEditPreview, ...] = Field(min_length=1)


class DriftDiagnostic(RemediationModel):
    dimension: str = Field(min_length=1, max_length=128)
    historical_fingerprint: Sha256Digest | None = None
    current_fingerprint: Sha256Digest | None = None
    blocking: bool


class RemediationAssistance(RemediationModel):
    run_id: VerificationRunId
    occurrence_id: FindingOccurrenceId
    check_id: VerificationCheckId
    check_key: VerificationCheckKey
    invariant_id: str
    invariant_version: int
    mode: AssistanceMode
    mode_label: str = Field(min_length=1, max_length=512)
    historical_relevant_authority_fingerprint: Sha256Digest | None = None
    current_relevant_authority_fingerprint: Sha256Digest | None = None
    drift: tuple[DriftDiagnostic, ...] = ()
    causal_summary: str
    grounded_claims: tuple[GroundedClaim, ...]
    proposal_state: ProposalState
    remediation_rationale: str | None = None
    patch: PatchPreview | None = None
    limitations: tuple[str, ...] = ()
    provider_id: str | None = None
    model: str | None = None

    @model_validator(mode="after")
    def validate_mode(self) -> RemediationAssistance:
        if self.mode == AssistanceMode.HISTORICAL_EXPLANATION_ONLY and self.patch is not None:
            raise ValueError("historical explanation cannot contain a patch")
        if (self.proposal_state == ProposalState.PROPOSED) != (self.patch is not None):
            raise ValueError("only a validated proposal may contain a patch")
        return self


class ComparisonOutcome(StrEnum):
    PROVEN_RESOLVED = "PROVEN_RESOLVED"
    STILL_VERIFIED_FAIL = "STILL_VERIFIED_FAIL"
    NOT_PROVEN = "NOT_PROVEN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_DIRECTLY_COMPARABLE = "NOT_DIRECTLY_COMPARABLE"


class FindingComparison(RemediationModel):
    historical_run_id: VerificationRunId
    current_run_id: VerificationRunId
    check_key: VerificationCheckKey
    outcome: ComparisonOutcome
    current_check_id: VerificationCheckId | None = None
    changed_dimension: str | None = Field(default=None, max_length=128)


class ReverificationResult(RemediationModel):
    run: VerificationRun
    comparison: FindingComparison
