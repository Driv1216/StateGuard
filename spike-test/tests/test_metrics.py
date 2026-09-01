from state_guard_spike.evaluation.metrics import pass_conditions, resolution_metrics
from state_guard_spike.runtime.traces import resolve_mapping
from state_guard_spike.schemas import MapperKind, MappingEvidence, RoleCandidate, RoleMapping
from state_guard_spike.contract import ROOT
from state_guard_spike.source_index import build_source_bundle


def test_resolution_diagnostics_add_no_gate() -> None:
    bundle = build_source_bundle("ecommerce", ROOT / "benchmarks" / "ecommerce" / "family_source")
    mapping = RoleMapping(application_id="ecommerce", mapper_kind=MapperKind.GEMINI, candidates=[])
    metrics = resolution_metrics({"ecommerce": resolve_mapping(mapping, bundle, "contract")})
    assert metrics["unmapped_family_count"] == 1
    gates = pass_conditions(
        {"true_positives": 5, "false_positives": 0, "non_obvious_true_positives": 2, "hallucinated_symbol_count": 0},
        {"evidence_trace_completeness": 1.0}, 10, 7, 0, 6, True,
    )
    assert len(gates) == 10
    assert all(gates.values())


def test_lift_boundary_is_exactly_three_defects() -> None:
    common = ({"true_positives": 5, "false_positives": 0, "non_obvious_true_positives": 2, "hallucinated_symbol_count": 0}, {"evidence_trace_completeness": 1.0})
    assert pass_conditions(*common, 10, 7, 0, 6, True)["MATERIAL_AI_LIFT"] is True
    assert pass_conditions(*common, 10, 8, 0, 6, True)["MATERIAL_AI_LIFT"] is False

