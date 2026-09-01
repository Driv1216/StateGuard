from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..contract import ROOT, load_contract, sha256_file, sha256_json
from ..mappers.baseline import map_roles as baseline_map_roles
from ..mappers.gemini import map_roles as gemini_map_roles
from ..runtime.chaos_runner import run_scenario_subprocess
from ..runtime.invariants import evaluate_invariant
from ..runtime.traces import resolve_mapping
from ..schemas import MapperKind, MappingResolutionTrace, ResolutionState, RoleMapping, Scenario
from ..source_index import build_source_bundle
from .approval_gate import require_evaluation_approval
from .metrics import defect_metrics, pass_conditions, resolution_metrics, semantic_metrics
from .truth_loader import load_mutation_truth, load_role_truth


def _contract_hash() -> str:
    return (ROOT / "contract.sha256").read_text(encoding="utf-8").strip()


def scenarios_from_contract(contract: dict[str, Any]) -> list[Scenario]:
    return [Scenario.model_validate(item) for item in contract["scenarios"]]


def execute_mapping_set(
    mappings: dict[str, RoleMapping],
    bundles: dict[str, Any],
    contract: dict[str, Any],
    contract_hash: str,
) -> dict[str, Any]:
    resolutions: dict[str, MappingResolutionTrace] = {
        family: resolve_mapping(mapping, bundles[family], contract_hash)
        for family, mapping in mappings.items()
    }
    observations: list[dict[str, Any]] = []
    invariant_results: list[dict[str, Any]] = []
    scenarios = scenarios_from_contract(contract)
    for family, resolution in resolutions.items():
        if resolution.resolution != ResolutionState.UNIQUE:
            continue
        assert resolution.selected_symbol is not None
        for fixture_id in ("fixture_01", "fixture_02", "fixture_03"):
            fixture_root = ROOT / "benchmarks" / family / "variants" / fixture_id
            for scenario in scenarios:
                observation = run_scenario_subprocess(
                    fixture_root=fixture_root,
                    family_id=family,
                    fixture_id=fixture_id,
                    selected_symbol=resolution.selected_symbol,
                    scenario=scenario,
                    mapper_kind=mappings[family].mapper_kind,
                    mapping_hash=resolution.mapping_hash,
                    contract_hash=contract_hash,
                )
                invariant = evaluate_invariant(observation)
                observations.append(observation.model_dump(mode="json"))
                invariant_results.append({
                    "family_id": family,
                    "fixture_id": fixture_id,
                    **invariant.model_dump(mode="json"),
                })
    return {
        "mappings": {family: mapping.model_dump(mode="json") for family, mapping in mappings.items()},
        "resolutions": {family: trace.model_dump(mode="json") for family, trace in resolutions.items()},
        "observations": observations,
        "invariant_results": invariant_results,
    }


def score_mapping_set(
    execution: dict[str, Any],
    mappings: dict[str, RoleMapping],
    bundles: dict[str, Any],
) -> dict[str, Any]:
    role_truth = load_role_truth()
    mutation_truth = load_mutation_truth()
    resolutions = {
        family: MappingResolutionTrace.model_validate(trace)
        for family, trace in execution["resolutions"].items()
    }
    semantic = semantic_metrics(
        mappings,
        role_truth,
        {family: {symbol.qualified_name for symbol in bundle.symbols} for family, bundle in bundles.items()},
    )
    result_index = {
        (item["family_id"], item["fixture_id"], item["invariant_id"]): item
        for item in execution["invariant_results"]
    }
    defect_records: list[dict[str, Any]] = []
    for family in role_truth:
        control = result_index.get((family, "fixture_01", "SG-01"))
        control_passed = bool(control and control["result"] == "PASS")
        for fixture_id, mutation in mutation_truth.items():
            if mutation == "CORRECT":
                continue
            target = "SG-02" if mutation == "DUPLICATE_SIDE_EFFECT" else "SG-03"
            item = result_index.get((family, fixture_id, target))
            family_results = [
                result for key, result in result_index.items()
                if key[0] == family and key[1] == fixture_id
            ]
            failed = bool(item and item["result"] == "FAIL")
            defect_records.append({
                "family_id": family,
                "fixture_id": fixture_id,
                "target_invariant_failed": failed,
                "any_invariant_failed": any(result["result"] == "FAIL" for result in family_results),
                "correct_control_passed": control_passed,
                "trace_complete": bool(item and item.get("trace_hash")),
                "is_finding": failed,
            })
    defects = defect_metrics(defect_records, resolutions)
    correct_results = [item for item in execution["invariant_results"] if item["fixture_id"] == "fixture_01"]
    false_critical = sum(item["result"] == "FAIL" for item in correct_results)
    correct_normal = sum(
        item["result"] == "PASS" and item["invariant_id"] == "SG-01"
        for item in correct_results
    )
    correct_full = sum(
        all(result_index.get((family, "fixture_01", invariant), {}).get("result") == "PASS" for invariant in ("SG-01", "SG-02", "SG-03"))
        for family in role_truth
    )
    return {
        "semantic": semantic,
        "resolution": resolution_metrics(resolutions),
        "defects": defects,
        "false_critical_findings": false_critical,
        "correct_normal_capture_passes": correct_normal,
        "correct_integration_pass_rate": correct_full / 6,
        "defect_records": defect_records,
    }


def run_frozen_evaluation() -> dict[str, Any]:
    contract = load_contract()
    contract_hash = _contract_hash()
    compliance_path = ROOT / "artifacts" / "pre_evaluation_compliance.md"
    approval_path = ROOT / "artifacts" / "evaluation_approval.json"
    require_evaluation_approval(approval_path, contract_hash, sha256_file(compliance_path))
    bundles = {
        family["id"]: build_source_bundle(family["id"], ROOT / "benchmarks" / family["id"] / "family_source")
        for family in contract["benchmarks"]
    }
    baseline_mappings = {
        family: baseline_map_roles(bundle, contract["baseline"])
        for family, bundle in bundles.items()
    }
    ai_mappings = {
        family: gemini_map_roles(bundle, approved=True)
        for family, bundle in bundles.items()
    }
    baseline_execution = execute_mapping_set(baseline_mappings, bundles, contract, contract_hash)
    ai_execution = execute_mapping_set(ai_mappings, bundles, contract, contract_hash)
    baseline_scores = score_mapping_set(baseline_execution, baseline_mappings, bundles)
    ai_scores = score_mapping_set(ai_execution, ai_mappings, bundles)
    gates = pass_conditions(
        ai_scores["semantic"],
        ai_scores["defects"],
        ai_scores["defects"]["seeded_defects_detected"],
        baseline_scores["defects"]["seeded_defects_detected"],
        ai_scores["false_critical_findings"],
        ai_scores["correct_normal_capture_passes"],
        authority_separation=True,
    )
    result = {
        "contract_hash": contract_hash,
        "baseline": {"execution": baseline_execution, "scores": baseline_scores},
        "ai": {"execution": ai_execution, "scores": ai_scores},
        "pass_conditions": gates,
        "overall": "GO" if all(gates.values()) else "NO_GO",
    }
    artifact_dir = ROOT / "artifacts" / "evaluation"
    artifact_dir.mkdir(parents=True, exist_ok=False)
    (artifact_dir / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result

