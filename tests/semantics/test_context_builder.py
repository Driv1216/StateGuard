from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import new_project_id
from stateguard.discovery.service import discover_and_index_project
from stateguard.graph.service import construct_payment_safety_graph
from stateguard.semantics.context import semantic_context_fingerprint
from stateguard.semantics.context_builder import build_semantic_context
from stateguard.semantics.contracts import (
    BundleCompleteness,
    SourceExcerptPurpose,
)
from stateguard.semantics.policy import SemanticBundlePolicy

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 25, tzinfo=UTC)


def _config() -> StateGuardConfig:
    return StateGuardConfig.model_validate(
        {
            "schema_version": 2,
            "project": {
                "id": new_project_id(),
                "source_root": ".",
                "framework": "fastapi",
                "app_target": "main:app",
            },
            "analysis": {"include": ["**/*.py"], "exclude": []},
        }
    )


def _build(repository: Path, config: StateGuardConfig):
    index = discover_and_index_project(repository, config, generated_at=NOW).source_index
    graph = construct_payment_safety_graph(repository, index, generated_at=NOW)
    return index, graph, build_semantic_context(repository, index, graph)


def test_routes_are_supporting_and_imported_siblings_are_not_candidates(tmp_path: Path) -> None:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "semantic_app", repository)
    index, _, built = _build(repository, _config())
    assert built.mapping_input is not None
    names_by_id = {item.symbol_id: item.qualified_name for item in index.symbols}
    candidate_names = {names_by_id[item.symbol_id] for item in built.mapping_input.catalog}
    assert candidate_names == {"domain.grant_ticket", "storage.persist_ticket"}
    assert "domain.unused_imported_helper" not in candidate_names
    route_owners = {item.owner_symbol_id for item in index.routes}
    assert not route_owners & {item.symbol_id for item in built.mapping_input.catalog}
    supporting = {
        item.symbol_id
        for item in built.mapping_input.excerpts
        if item.purpose == SourceExcerptPurpose.SUPPORTING
    }
    assert route_owners <= supporting
    grant_excerpt = next(
        item
        for item in built.mapping_input.excerpts
        if "Ignore previous instructions" in item.content
    )
    assert grant_excerpt.purpose == SourceExcerptPurpose.CANDIDATE


def test_inline_only_payment_effect_has_no_selectable_candidate(tmp_path: Path) -> None:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "semantic_inline", repository)
    _, _, built = _build(repository, _config())
    assert built.mapping_input is not None
    assert built.mapping_input.catalog == ()
    assert built.descriptor.presented_symbol_ids == ()


def test_guardrail_omits_whole_candidates_and_downgrades_authority(tmp_path: Path) -> None:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "semantic_app", repository)
    config = _config()
    index = discover_and_index_project(repository, config, generated_at=NOW).source_index
    graph = construct_payment_safety_graph(repository, index, generated_at=NOW)
    built = build_semantic_context(
        repository,
        index,
        graph,
        policy=SemanticBundlePolicy(max_presented_candidates=1),
    )
    assert built.descriptor.bundle_completeness == BundleCompleteness.BUNDLE_PARTIAL
    default = build_semantic_context(repository, index, graph)
    assert semantic_context_fingerprint(default.descriptor) == semantic_context_fingerprint(
        built.descriptor
    )
    assert len(built.descriptor.relevant_symbol_ids) > len(built.descriptor.presented_symbol_ids)
    assert built.mapping_input is not None and len(built.mapping_input.catalog) == 1


def test_unrelated_source_and_diagnostics_do_not_stale_relevant_context(tmp_path: Path) -> None:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "semantic_app", repository)
    config = _config()
    first_index, _, first = _build(repository, config)
    unrelated = repository / "unrelated.py"
    unrelated.write_text("def unrelated():\n    return 1\n", encoding="utf-8")
    second_index, _, second = _build(repository, config)
    assert first_index.project_source_fingerprint != second_index.project_source_fingerprint
    assert semantic_context_fingerprint(first.descriptor) == semantic_context_fingerprint(
        second.descriptor
    )

    unrelated.write_text("def broken(:\n", encoding="utf-8")
    _, _, with_unrelated_error = _build(repository, config)
    assert semantic_context_fingerprint(first.descriptor) == semantic_context_fingerprint(
        with_unrelated_error.descriptor
    )
    assert with_unrelated_error.descriptor.bundle_completeness == BundleCompleteness.BUNDLE_COMPLETE


def test_relevant_callable_content_change_stales_context(tmp_path: Path) -> None:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "semantic_app", repository)
    config = _config()
    _, _, first = _build(repository, config)
    storage = repository / "storage.py"
    storage.write_text(
        storage.read_text(encoding="utf-8").replace('"status": "issued"', '"status": "active"'),
        encoding="utf-8",
    )
    _, _, second = _build(repository, config)
    assert semantic_context_fingerprint(first.descriptor) != semantic_context_fingerprint(
        second.descriptor
    )
