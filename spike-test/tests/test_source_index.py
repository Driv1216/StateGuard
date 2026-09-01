from state_guard_spike.contract import ROOT
from state_guard_spike.source_index import PREDICATE_ORACLE_NAMES, build_source_bundle


def test_source_index_captures_routes_calls_states_and_imports() -> None:
    bundle = build_source_bundle("ticketing", ROOT / "benchmarks" / "ticketing" / "family_source")
    assert any(route.symbol == "app.main.receive_webhook" and route.method == "POST" for route in bundle.routes)
    assert {"payment.captured", "payment.authorized"} <= set(bundle.payment_literals)
    assert any(edge.callee == "app.domain.mint_admission_pass" and edge.payment_state == "captured" for edge in bundle.call_edges)
    assert "fastapi.FastAPI" in bundle.imports
    assert all(predicate not in file.content for predicate in PREDICATE_ORACLE_NAMES for file in bundle.files)

