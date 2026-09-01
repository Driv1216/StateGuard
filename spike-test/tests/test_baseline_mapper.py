from state_guard_spike.contract import ROOT
from state_guard_spike.mappers.baseline import map_roles
from state_guard_spike.runtime.traces import resolve_mapping
from state_guard_spike.schemas import ResolutionState
from state_guard_spike.source_index import build_source_bundle


def test_calibration_selects_positive_action_and_rejects_refund() -> None:
    document = build_source_bundle("document_export", ROOT / "tests" / "calibration_fixtures" / "document_export")
    device = build_source_bundle("device_enrollment", ROOT / "tests" / "calibration_fixtures" / "device_enrollment")
    assert "app.actions.deliver_export_bundle" in {item.symbol for item in map_roles(document).candidates}
    device_symbols = {item.symbol for item in map_roles(device).candidates}
    assert "app.operations.activate_device_profile" in device_symbols
    assert "app.operations.issue_refund_record" not in device_symbols


def test_non_obvious_static_mapping_is_ambiguous_not_a_finding() -> None:
    for family in ("ticketing", "workspace", "licensing"):
        bundle = build_source_bundle(family, ROOT / "benchmarks" / family / "family_source")
        mapping = map_roles(bundle)
        trace = resolve_mapping(mapping, bundle, "contract")
        assert trace.resolution == ResolutionState.AMBIGUOUS
        assert len(trace.valid_symbols) >= 4
        assert trace.selected_symbol is None

