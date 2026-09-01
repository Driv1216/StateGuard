from __future__ import annotations

from collections import Counter
from typing import Any

from ..schemas import MappingResolutionTrace, ResolutionState, RoleMapping


NON_OBVIOUS = {"ticketing", "workspace", "licensing"}


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def semantic_metrics(
    mappings: dict[str, RoleMapping],
    role_truth: dict[str, dict[str, Any]],
    catalogues: dict[str, set[str]],
) -> dict[str, Any]:
    tp = fp = hallucinations = non_obvious_tp = 0
    for family, mapping in mappings.items():
        truth = role_truth[family]["role_symbol"]
        predicted = {candidate.symbol for candidate in mapping.candidates}
        tp += int(truth in predicted)
        fp += len(predicted - {truth})
        hallucinations += len(predicted - catalogues[family])
        if family in NON_OBVIOUS:
            non_obvious_tp += int(truth in predicted)
    fn = len(role_truth) - tp
    precision = _rate(tp, tp + fp)
    recall = _rate(tp, len(role_truth))
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "non_obvious_true_positives": non_obvious_tp,
        "non_obvious_recall": _rate(non_obvious_tp, 3),
        "hallucinated_symbol_count": hallucinations,
    }


def resolution_metrics(resolutions: dict[str, MappingResolutionTrace]) -> dict[str, Any]:
    counts = Counter(trace.resolution for trace in resolutions.values())
    return {
        "unique_mapping_coverage": _rate(counts[ResolutionState.UNIQUE], 6),
        "unique_family_count": counts[ResolutionState.UNIQUE],
        "ambiguous_family_count": counts[ResolutionState.AMBIGUOUS],
        "unmapped_family_count": counts[ResolutionState.UNMAPPED],
    }


def defect_metrics(records: list[dict[str, Any]], resolutions: dict[str, MappingResolutionTrace]) -> dict[str, Any]:
    detected = sum(
        bool(record["target_invariant_failed"] and record["correct_control_passed"] and record["trace_complete"])
        for record in records
        if resolutions[record["family_id"]].resolution == ResolutionState.UNIQUE
    )
    killed = sum(
        bool(record["any_invariant_failed"] and record["correct_control_passed"] and record["trace_complete"])
        for record in records
        if resolutions[record["family_id"]].resolution == ResolutionState.UNIQUE
    )
    findings = [record for record in records if record.get("is_finding")]
    complete_findings = sum(bool(record.get("trace_complete")) for record in findings)
    return {
        "seeded_defects_detected": detected,
        "seeded_defect_recall": _rate(detected, 12),
        "mutants_killed": killed,
        "mutation_kill_rate": _rate(killed, 12),
        "evidence_trace_completeness": _rate(complete_findings, len(findings)) if findings else 1.0,
    }


def pass_conditions(
    semantic: dict[str, Any],
    defects: dict[str, Any],
    ai_detected: int,
    baseline_detected: int,
    false_critical_findings: int,
    correct_normal_capture_passes: int,
    authority_separation: bool,
) -> dict[str, bool]:
    tp = semantic["true_positives"]
    fp = semantic["false_positives"]
    lift_count = ai_detected - baseline_detected
    return {
        "AI_ROLE_RECALL_AT_LEAST_5_OF_6": tp >= 5,
        "AI_NON_OBVIOUS_RECALL_AT_LEAST_2_OF_3": semantic["non_obvious_true_positives"] >= 2,
        "AI_CRITICAL_ROLE_PRECISION_AT_LEAST_90_PERCENT": tp + fp > 0 and 10 * tp >= 9 * (tp + fp),
        "AI_HALLUCINATED_SYMBOL_COUNT_ZERO": semantic["hallucinated_symbol_count"] == 0,
        "AI_DEFECT_RECALL_AT_LEAST_10_OF_12": ai_detected >= 10,
        "MATERIAL_AI_LIFT": 4 * lift_count >= 12 or lift_count >= 3,
        "FALSE_CRITICAL_FINDINGS_ZERO": false_critical_findings == 0,
        "ALL_CORRECT_NORMAL_CAPTURE_PASS": correct_normal_capture_passes == 6,
        "ALL_DEFECT_FINDINGS_HAVE_COMPLETE_TRACES": defects["evidence_trace_completeness"] == 1.0,
        "INVARIANT_ENGINE_HAS_EXCLUSIVE_PASS_FAIL_AUTHORITY": authority_separation,
    }

