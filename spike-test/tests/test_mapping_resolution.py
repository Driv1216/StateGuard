from state_guard_spike.contract import ROOT
from state_guard_spike.runtime.traces import resolve_mapping
from state_guard_spike.schemas import MapperKind, MappingEvidence, ResolutionState, RoleCandidate, RoleMapping
from state_guard_spike.source_index import build_source_bundle


def candidate(symbol: str) -> RoleCandidate:
    return RoleCandidate(
        role="IRREVERSIBLE_FULFILMENT", symbol=symbol, confidence=0.8,
        evidence=[MappingEvidence(kind="IDENTIFIER", source_path="app/domain.py", line_start=1, line_end=1, explanation="test")],
    )


def mapping(family: str, symbols: list[str]) -> RoleMapping:
    return RoleMapping(application_id=family, mapper_kind=MapperKind.GEMINI, candidates=[candidate(item) for item in symbols])


def test_resolution_states_and_hallucinations() -> None:
    bundle = build_source_bundle("ecommerce", ROOT / "benchmarks" / "ecommerce" / "family_source")
    role = "app.domain.ship_order"
    unmapped = resolve_mapping(mapping("ecommerce", []), bundle, "contract")
    ambiguous = resolve_mapping(mapping("ecommerce", [role, "app.domain.persist_payment_record"]), bundle, "contract")
    unique_with_hallucination = resolve_mapping(mapping("ecommerce", [role, "app.domain.invented"]), bundle, "contract")
    assert unmapped.resolution == ResolutionState.UNMAPPED
    assert ambiguous.resolution == ResolutionState.AMBIGUOUS and ambiguous.selected_symbol is None
    assert unique_with_hallucination.resolution == ResolutionState.UNIQUE
    assert unique_with_hallucination.selected_symbol == role
    assert unique_with_hallucination.hallucinated_symbols == ["app.domain.invented"]

