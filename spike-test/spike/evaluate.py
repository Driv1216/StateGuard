from __future__ import annotations

import argparse
import importlib.metadata
import json
import platform
from pathlib import Path
from typing import Any

from .baseline_matcher import generate_baseline_candidates
from .generate_dataset import DATASET_SEED, FIXTURES_DIR
from .models import Candidate, Decision, DecisionStatus, group_settlements
from .normalize import (
    BANK_DATE_WINDOW_DAYS,
    DATE_WINDOW_DAYS,
    FUZZY_REFERENCE_THRESHOLD,
    load_bank_statement,
    load_merchant_ledger,
    load_recon_components,
)
from .semantic_matcher import DEVICE, MODEL_NAME, SEMANTIC_TOP_K, generate_semantic_candidates, load_model
from .verifier import verify_all


ARTIFACT_PATH = Path(__file__).resolve().parent / "artifacts" / "metrics.json"


def _correct_candidate_present(candidates: list[Candidate], truth: dict) -> bool:
    return any(
        candidate.settlement_id == truth["settlement_id"]
        and candidate.bank_id == truth["bank_id"]
        for candidate in candidates
    )


def _decision_correct(decision: Decision, truth: dict) -> bool:
    if decision.status.value != truth["expected_status"]:
        return False
    if decision.status != DecisionStatus.VERIFIED:
        return True
    selected = decision.selected_candidate
    return bool(
        selected
        and selected.settlement_id == truth["settlement_id"]
        and selected.bank_id == truth["bank_id"]
    )


def _trace_complete(decision: Decision) -> bool:
    serialized = decision.to_dict()
    if not all(key in serialized for key in ("ledger_id", "status", "reason", "candidate_evidence")):
        return False
    return all(
        evidence.get("candidate")
        and isinstance(evidence.get("checks"), list)
        and evidence.get("reason")
        and all(
            all(key in check for key in ("name", "passed", "kind", "detail"))
            for check in evidence["checks"]
        )
        for evidence in serialized["candidate_evidence"]
    )


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _system_metrics(
    candidates_by_ledger: dict[str, list[Candidate]],
    decisions: dict[str, Decision],
    truth_cases: list[dict],
) -> dict[str, Any]:
    by_category = {
        category: [case for case in truth_cases if case["category"] == category]
        for category in {case["category"] for case in truth_cases}
    }
    candidate_hits = {
        case["case_id"]: _correct_candidate_present(candidates_by_ledger.get(case["ledger_id"], []), case)
        for case in truth_cases
    }
    verified_cases = [
        case for case in truth_cases if decisions[case["ledger_id"]].status == DecisionStatus.VERIFIED
    ]
    correct_verified = [
        case
        for case in verified_cases
        if _decision_correct(decisions[case["ledger_id"]], case)
    ]
    false_verified = [case for case in verified_cases if case not in correct_verified]
    expected_verified = [case for case in truth_cases if case["expected_status"] == "VERIFIED"]
    normalized = by_category["normalized"]
    semantic = by_category["semantic"]
    messy = normalized + semantic
    ambiguous = by_category["ambiguous"]
    corrupted = by_category["corrupted"]

    return {
        "case_count": len(truth_cases),
        "candidate_recall": _rate(sum(candidate_hits.values()), len(truth_cases)),
        "normalized_candidate_recall": _rate(sum(candidate_hits[c["case_id"]] for c in normalized), len(normalized)),
        "semantic_candidate_recall": _rate(sum(candidate_hits[c["case_id"]] for c in semantic), len(semantic)),
        "combined_messy_candidate_recall": _rate(sum(candidate_hits[c["case_id"]] for c in messy), len(messy)),
        "safe_auto_close_coverage": _rate(len(correct_verified), len(truth_cases)),
        "match_precision": _rate(len(correct_verified), len(verified_cases)),
        "match_recall": _rate(len(correct_verified), len(expected_verified)),
        "false_auto_close_count": len(false_verified),
        "false_auto_close_rate": _rate(len(false_verified), len(verified_cases)),
        "ambiguity_detection": _rate(
            sum(decisions[c["ledger_id"]].status == DecisionStatus.REVIEW for c in ambiguous),
            len(ambiguous),
        ),
        "corruption_detection": _rate(
            sum(decisions[c["ledger_id"]].status == DecisionStatus.EXCEPTION for c in corrupted),
            len(corrupted),
        ),
        "clean_correctly_resolved": sum(
            _decision_correct(decisions[c["ledger_id"]], c) for c in by_category["clean"]
        ),
        "messy_safely_resolved": sum(
            _decision_correct(decisions[c["ledger_id"]], c)
            and decisions[c["ledger_id"]].status == DecisionStatus.VERIFIED
            for c in messy
        ),
        "trace_completeness": _rate(sum(_trace_complete(d) for d in decisions.values()), len(decisions)),
        "candidate_hits": candidate_hits,
        "decisions": [
            {
                "case_id": case["case_id"],
                "category": case["category"],
                "expected_status": case["expected_status"],
                "correct": _decision_correct(decisions[case["ledger_id"]], case),
                **decisions[case["ledger_id"]].to_dict(),
            }
            for case in truth_cases
        ],
    }


def _model_revision(model: Any) -> str | None:
    try:
        transformer = model._first_module()
        return getattr(transformer.auto_model.config, "_commit_hash", None)
    except (AttributeError, KeyError):
        return None


def _ai_verified_independently(hybrid_metrics: dict[str, Any]) -> bool:
    for decision in hybrid_metrics["decisions"]:
        selected = decision.get("selected_candidate")
        if decision["status"] != "VERIFIED" or not selected or selected["source"] != "semantic":
            continue
        selected_evidence = next(
            evidence
            for evidence in decision["candidate_evidence"]
            if evidence["candidate"]["settlement_id"] == selected["settlement_id"]
            and evidence["candidate"]["bank_id"] == selected["bank_id"]
        )
        hard_passed = all(
            check["passed"] for check in selected_evidence["checks"] if check["kind"] == "hard"
        )
        deterministic_support = any(
            check["passed"]
            for check in selected_evidence["checks"]
            if check["name"] in {"reference_evidence", "financial_uniqueness"}
        )
        if not (selected_evidence["sufficient"] and hard_passed and deterministic_support):
            return False
    return True


def evaluate(fixtures_dir: Path = FIXTURES_DIR, artifact_path: Path = ARTIFACT_PATH) -> dict[str, Any]:
    ledger = load_merchant_ledger(fixtures_dir / "merchant_ledger.csv")
    components = load_recon_components(fixtures_dir / "razorpay_recon.csv")
    banks = load_bank_statement(fixtures_dir / "bank_statement.csv")
    settlements = group_settlements(components)
    with (fixtures_dir / "ground_truth.json").open(encoding="utf-8") as handle:
        truth = json.load(handle)

    baseline_candidates = generate_baseline_candidates(ledger, settlements, banks)
    baseline_decisions = verify_all(ledger, baseline_candidates, settlements, banks)
    unresolved = {
        ledger_id
        for ledger_id, decision in baseline_decisions.items()
        if decision.status == DecisionStatus.REVIEW
    }

    model = load_model()
    semantic_candidates = generate_semantic_candidates(
        ledger, settlements, banks, unresolved, model, top_k=SEMANTIC_TOP_K
    )
    hybrid_candidates = {
        record.ledger_id: list(baseline_candidates.get(record.ledger_id, []))
        + [
            candidate
            for candidate in semantic_candidates.get(record.ledger_id, [])
            if candidate.identity
            not in {existing.identity for existing in baseline_candidates.get(record.ledger_id, [])}
        ]
        for record in ledger
    }
    hybrid_decisions = verify_all(ledger, hybrid_candidates, settlements, banks)

    baseline_metrics = _system_metrics(baseline_candidates, baseline_decisions, truth["cases"])
    hybrid_metrics = _system_metrics(hybrid_candidates, hybrid_decisions, truth["cases"])
    coverage_lift = round(
        hybrid_metrics["safe_auto_close_coverage"] - baseline_metrics["safe_auto_close_coverage"],
        6,
    )
    additional_messy = hybrid_metrics["messy_safely_resolved"] - baseline_metrics["messy_safely_resolved"]

    clean_pass = baseline_metrics["clean_correctly_resolved"] == 15 and hybrid_metrics["clean_correctly_resolved"] == 15
    ambiguity_pass = all(
        decision["status"] != "VERIFIED"
        for decision in hybrid_metrics["decisions"]
        if decision["category"] == "ambiguous"
    )
    corruption_pass = all(
        decision["status"] != "VERIFIED"
        for decision in hybrid_metrics["decisions"]
        if decision["category"] == "corrupted"
    )
    ai_independent = _ai_verified_independently(hybrid_metrics)
    pass_conditions = {
        "clean_cases_100_percent_correct": clean_pass,
        "zero_ambiguous_auto_closed": ambiguity_pass,
        "zero_corrupted_auto_closed": corruption_pass,
        "zero_total_false_auto_closes": hybrid_metrics["false_auto_close_count"] == 0,
        "combined_messy_candidate_recall_at_least_80_percent": hybrid_metrics["combined_messy_candidate_recall"] >= 0.8,
        "all_decisions_have_structured_traces": baseline_metrics["trace_completeness"] == 1.0 and hybrid_metrics["trace_completeness"] == 1.0,
        "material_hybrid_lift": coverage_lift >= 0.10 or additional_messy >= 3,
        "ai_verified_candidates_have_independent_deterministic_evidence": ai_independent,
    }

    result = {
        "schema_version": 1,
        "reproducibility": {
            "python_version": platform.python_version(),
            "sentence_transformers_version": importlib.metadata.version("sentence-transformers"),
            "embedding_model": MODEL_NAME,
            "model_revision": _model_revision(model),
            "dataset_seed": truth.get("dataset_seed", DATASET_SEED),
            "device": DEVICE,
            "semantic_top_k": SEMANTIC_TOP_K,
            "thresholds": {
                "fuzzy_reference": FUZZY_REFERENCE_THRESHOLD,
                "ledger_settlement_date_window_days": DATE_WINDOW_DAYS,
                "settlement_bank_date_window_days": BANK_DATE_WINDOW_DAYS,
                "semantic_similarity": None,
            },
            "normalization": "Unicode NFKC, casefold, whitespace collapse; references strip non-alphanumerics",
        },
        "definitions": {
            "messy_cases": ["normalized", "semantic"],
            "messy_case_count": 10,
            "safe_auto_close_coverage": "correct VERIFIED decisions / all 30 cases",
            "match_recall": "correct VERIFIED decisions / 25 expected-VERIFIED cases",
        },
        "baseline": baseline_metrics,
        "hybrid": hybrid_metrics,
        "comparison": {
            "safe_auto_close_coverage_lift": coverage_lift,
            "safe_auto_close_coverage_lift_percentage_points": round(coverage_lift * 100, 2),
            "additional_messy_cases_safely_resolved": additional_messy,
        },
        "pass_conditions": pass_conditions,
        "result": "GO" if all(pass_conditions.values()) else "NO-GO",
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    with artifact_path.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the frozen CloseProof spike benchmark")
    parser.add_argument("--fixtures", type=Path, default=FIXTURES_DIR)
    parser.add_argument("--output", type=Path, default=ARTIFACT_PATH)
    args = parser.parse_args()
    result = evaluate(args.fixtures, args.output)
    print(json.dumps({"result": result["result"], "comparison": result["comparison"]}, indent=2))


if __name__ == "__main__":
    main()

