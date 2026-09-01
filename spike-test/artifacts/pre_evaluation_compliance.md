# StateGuard Pre-Evaluation Compliance Report

Status: **READY FOR HUMAN PRE-EVALUATION REVIEW — FROZEN EVALUATION NOT RUN**

Contract SHA-256: `3454f599945434d7dfbe3cf0eb42ad504bb007f63305453095ce38d07c73e62a`

No Gemini request was made. `evaluation_approval.json` and `artifacts/evaluation/` are absent.

| Requirement | Status | Implementation and focused evidence |
|---|---|---|
| Frozen benchmark inventory | PASS | experiment_contract.json; tests/test_fixture_structure.py |
| Exact mutation distribution | PASS | evaluation_only/mutation_ground_truth.json; tests/test_fixture_structure.py |
| Strong frozen AST baseline | PASS | state_guard_spike/mappers/baseline.py; tests/test_baseline_mapper.py |
| Calibration isolation | PASS | tests/calibration_fixtures; tests/test_baseline_mapper.py |
| Structural non-oracle | PASS | state_guard_spike/evaluation/compliance_audit.py; tests/test_fixture_structure.py |
| No LLM or embedding baseline dependency | PASS | state_guard_spike/mappers/baseline.py; tests/test_truth_isolation.py |
| Evaluator-only role and mutation truth | PASS | state_guard_spike/evaluation/truth_loader.py; tests/test_truth_isolation.py |
| Business-value predicates excluded from mapper inputs | PASS | state_guard_spike/source_index.py; tests/test_truth_isolation.py |
| UNIQUE-only invariant execution | PASS | state_guard_spike/evaluation/evaluator.py; tests/test_mapping_resolution.py |
| Uncertainty produces UNVERIFIED, never PASS/FAIL | PASS | state_guard_spike/runtime/traces.py; tests/test_mapping_resolution.py |
| Same scenarios, harness, and invariants | PASS | state_guard_spike/evaluation/evaluator.py; tests/test_chaos_runner.py |
| Invariant engine owns PASS/FAIL | PASS | state_guard_spike/runtime/invariants.py; tests/test_invariants.py |
| Mapping once per family and reused | PASS | state_guard_spike/evaluation/evaluator.py; tests/test_mapping_resolution.py |
| All ten gates frozen | PASS | experiment_contract.json; tests/test_metrics.py |
| Gemini is approval-gated and offline tests use fakes | PASS | state_guard_spike/mappers/gemini.py; tests/test_ai_mapper_offline.py |
| No final evaluation result exists | PASS | state_guard_spike/evaluation/approval_gate.py; tests/test_approval_gate.py |

## Structural Non-Oracle Evidence

- `ticketing`: 3 hard distractors; structural parity=True; baseline resolution=AMBIGUOUS.
- `workspace`: 3 hard distractors; structural parity=True; baseline resolution=AMBIGUOUS.
- `licensing`: 3 hard distractors; structural parity=True; baseline resolution=AMBIGUOUS.

The detailed score vectors, SourceBundle checks, fixture hashes, and calibration-isolation results are in `artifacts/structural_validation.json`.

## Required Stop

Implementation stops here. The approval record has not been created, Gemini has not been called, and the frozen benchmark has not been executed.
