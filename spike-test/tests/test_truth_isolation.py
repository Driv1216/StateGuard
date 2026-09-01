import ast

from state_guard_spike.contract import ROOT
from state_guard_spike.mappers.prompt import build_prompt
from state_guard_spike.source_index import PREDICATE_ORACLE_NAMES, build_source_bundle


def test_mapper_modules_do_not_import_evaluator_or_truth() -> None:
    for path in (ROOT / "state_guard_spike" / "mappers").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        assert all("evaluation" not in item and "truth" not in item for item in imports)


def test_truth_and_business_predicates_are_absent_from_mapper_payloads() -> None:
    truth_text = (ROOT / "evaluation_only" / "role_ground_truth.json").read_text(encoding="utf-8")
    for family in ("ecommerce", "saas", "course", "ticketing", "workspace", "licensing"):
        bundle = build_source_bundle(family, ROOT / "benchmarks" / family / "family_source")
        prompt = build_prompt(bundle)
        assert "evaluation_only" not in prompt
        assert truth_text not in prompt
        assert all(predicate not in prompt for predicate in PREDICATE_ORACLE_NAMES)

