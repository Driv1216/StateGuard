from __future__ import annotations

from ..contract import sha256_json
from ..schemas import InvariantResult, RuntimeObservation


INVARIANT_BY_SCENARIO = {
    "S1": ("SG-01", "==", 1),
    "S2": ("SG-02", "<=", 1),
    "S3": ("SG-03", "==", 0),
}


def evaluate_invariant(observation: RuntimeObservation) -> InvariantResult:
    invariant_id, comparator, expected = INVARIANT_BY_SCENARIO[observation.scenario_id]
    passed = observation.observed_count == expected if comparator == "==" else observation.observed_count <= expected
    return InvariantResult(
        invariant_id=invariant_id,
        scenario_id=observation.scenario_id,
        comparator=comparator,
        expected=expected,
        observed=observation.observed_count,
        result="PASS" if passed else "FAIL",
        trace_hash=sha256_json(observation),
    )

