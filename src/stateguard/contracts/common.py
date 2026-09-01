"""Small shared primitives used by persisted StateGuard artifacts."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

ProjectId = Annotated[str, StringConstraints(pattern=r"^sgproj_[0-9a-f]{32}$")]
SourceFileId = Annotated[str, StringConstraints(pattern=r"^sgfile_[0-9a-f]{32}$")]
SymbolId = Annotated[str, StringConstraints(pattern=r"^sgsym_[0-9a-f]{32}$")]
FrameworkInstanceId = Annotated[str, StringConstraints(pattern=r"^sgfw_[0-9a-f]{32}$")]
RouteRegistrationId = Annotated[str, StringConstraints(pattern=r"^sgroute_[0-9a-f]{32}$")]
MerchantStateCarrierId = Annotated[str, StringConstraints(pattern=r"^sgcarrier_[0-9a-f]{32}$")]
GraphNodeId = Annotated[str, StringConstraints(pattern=r"^sgnode_[0-9a-f]{32}$")]
GraphEdgeId = Annotated[str, StringConstraints(pattern=r"^sgedge_[0-9a-f]{32}$")]
NormalControlId = Annotated[str, StringConstraints(pattern=r"^sgcontrol_[0-9a-f]{32}$")]
ScenarioInstanceId = Annotated[str, StringConstraints(pattern=r"^sgscenario_[0-9a-f]{32}$")]
AssertionId = Annotated[str, StringConstraints(pattern=r"^sgassert_[0-9a-f]{32}$")]
ScenarioExecutionId = Annotated[str, StringConstraints(pattern=r"^sgexec_[0-9a-f]{32}$")]
VerificationRunId = Annotated[str, StringConstraints(pattern=r"^sgvrun_[0-9a-f]{32}$")]
VerificationCheckId = Annotated[str, StringConstraints(pattern=r"^sgcheck_[0-9a-f]{32}$")]
VerificationCheckKey = Annotated[str, StringConstraints(pattern=r"^sgcheckkey_[0-9a-f]{32}$")]
FindingOccurrenceId = Annotated[str, StringConstraints(pattern=r"^sgfinding_[0-9a-f]{32}$")]
FindingKey = Annotated[str, StringConstraints(pattern=r"^sgfindingkey_[0-9a-f]{32}$")]
RuntimeSessionId = Annotated[str, StringConstraints(pattern=r"^sgrun_[0-9a-f]{32}$")]
RuntimeRequestId = Annotated[str, StringConstraints(pattern=r"^sgreq_[0-9a-f]{32}$")]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


def is_cross_platform_absolute_path(value: str) -> bool:
    """Recognize POSIX and Windows rooted/drive paths on every host OS."""

    candidate = value.strip()
    posix_path = PurePosixPath(candidate.replace("\\", "/"))
    windows_path = PureWindowsPath(candidate)
    return bool(
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or windows_path.root
    )


def normalize_relative_path(value: str) -> str:
    """Return a portable project-relative POSIX path or raise ValueError."""

    normalized = value.strip().replace("\\", "/")
    if not normalized:
        raise ValueError("path must not be empty")
    path = PurePosixPath(normalized)
    if is_cross_platform_absolute_path(value) or ".." in path.parts:
        raise ValueError("path must be project-relative and must not traverse parents")
    result = path.as_posix()
    return "." if result in {"", "."} else result


class PersistedArtifactModel(BaseModel):
    """Base only for immutable persisted domain artifacts and their records."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceLocation(PersistedArtifactModel):
    path: str
    line_start: int = Field(ge=1)
    column_start: int = Field(ge=0)
    line_end: int = Field(ge=1)
    column_end: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return normalize_relative_path(value)

    @model_validator(mode="after")
    def validate_span(self) -> SourceLocation:
        start = (self.line_start, self.column_start)
        end = (self.line_end, self.column_end)
        if end < start:
            raise ValueError("source location end must not precede its start")
        return self


class ProvenanceKind(StrEnum):
    STATIC = "STATIC"
    AI_INFERRED = "AI_INFERRED"
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"
    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"


class ProvenanceRecord(PersistedArtifactModel):
    kind: ProvenanceKind
    reference: str = Field(min_length=1)
    source_location: SourceLocation | None = None
    supporting_fingerprint: Sha256Digest | None = None

    @field_validator("reference")
    @classmethod
    def strip_reference(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("provenance reference must not be blank")
        return stripped


class ArtifactFields(PersistedArtifactModel):
    """Reusable field validation, not a generic artifact identity/envelope."""

    producer_version: str = Field(min_length=1)
    generated_at: datetime

    @field_validator("producer_version")
    @classmethod
    def strip_producer_version(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("producer version must not be blank")
        return stripped

    @field_validator("generated_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value
