from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MapperKind(str, Enum):
    STATIC_BASELINE = "STATIC_BASELINE"
    GEMINI = "GEMINI"


class ResolutionState(str, Enum):
    UNIQUE = "UNIQUE"
    UNMAPPED = "UNMAPPED"
    AMBIGUOUS = "AMBIGUOUS"


class SourceFile(StrictModel):
    logical_path: str
    content: str
    sha256: str


class SymbolInfo(StrictModel):
    qualified_name: str
    kind: Literal["function", "async_function", "method", "async_method"]
    path: str
    signature: str
    line_start: int
    line_end: int


class CallEdge(StrictModel):
    caller: str
    callee: str
    payment_state: Literal["captured", "authorized"] | None = None
    line: int


class RouteInfo(StrictModel):
    symbol: str
    method: str
    path: str


class SourceBundle(StrictModel):
    application_id: str
    files: list[SourceFile]
    symbols: list[SymbolInfo]
    call_edges: list[CallEdge]
    routes: list[RouteInfo]
    payment_literals: list[str]
    imports: list[str]


class MappingEvidence(StrictModel):
    kind: Literal["IDENTIFIER", "BODY", "CALLER", "CALLEE", "ROUTE", "PAYMENT_STATE", "IMPORT"]
    source_path: str
    line_start: int
    line_end: int
    explanation: str


class RoleCandidate(StrictModel):
    role: Literal["IRREVERSIBLE_FULFILMENT"]
    symbol: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[MappingEvidence] = Field(min_length=1)


class RoleMapping(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    application_id: str
    mapper_kind: MapperKind
    candidates: list[RoleCandidate]
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_duplicate_symbols(self) -> "RoleMapping":
        symbols = [candidate.symbol for candidate in self.candidates]
        if len(symbols) != len(set(symbols)):
            raise ValueError("duplicate role-candidate symbols are forbidden")
        return self


class MappingResolutionTrace(StrictModel):
    mapper_kind: MapperKind
    family_id: str
    mapping_hash: str
    source_bundle_hash: str
    contract_hash: str
    raw_candidate_count: int
    valid_symbols: list[str]
    hallucinated_symbols: list[str]
    resolution: ResolutionState
    selected_symbol: str | None = None
    explanation: str


class ScenarioEvent(StrictModel):
    id: str
    type: Literal["payment.captured", "payment.authorized"]
    payment: dict[str, Any]


class Scenario(StrictModel):
    id: Literal["S1", "S2", "S3"]
    name: str
    events: list[ScenarioEvent]


class CallRecord(StrictModel):
    sequence: int
    symbol: str
    event_id: str
    payment_id: str


class RuntimeObservation(StrictModel):
    mapper_kind: MapperKind
    mapping_hash: str
    family_id: str
    fixture_id: str
    selected_symbol: str
    scenario_id: str
    scenario_hash: str
    fixture_source_hash: str
    contract_hash: str
    input_events: list[dict[str, str]]
    calls: list[CallRecord]
    observed_count: int


class InvariantResult(StrictModel):
    invariant_id: Literal["SG-01", "SG-02", "SG-03"]
    scenario_id: Literal["S1", "S2", "S3"]
    comparator: Literal["==", "<="]
    expected: int
    observed: int
    result: Literal["PASS", "FAIL"]
    trace_hash: str

