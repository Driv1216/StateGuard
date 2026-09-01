from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from stateguard.applicability.contracts import ApplicabilityState, ScenarioId
from stateguard.application.applicability import (
    confirm_merchant_policy,
)
from stateguard.application.semantics import confirm_customer_value
from stateguard.contracts.config import FulfilmentPolicy
from stateguard.discovery.service import discover_and_index_project
from stateguard.graph.contracts import (
    GraphEdgeKind,
    GraphNodeKind,
    PaymentIngressDetails,
    TrustGateDetails,
    TrustGateKind,
)
from stateguard.graph.service import construct_payment_safety_graph
from stateguard.semantics.context_builder import build_semantic_context
from stateguard.workspace.config import load_config

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "ticketing_merchant"
NOW = datetime(2026, 8, 31, tzinfo=UTC)


def _copy_example(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "ticketing_merchant"
    shutil.copytree(EXAMPLE, repository)
    return repository, repository / "stateguard.yaml"


def _scenario(artifact, scenario_id: ScenarioId):
    return next(item for item in artifact.scenarios if item.scenario_id == scenario_id)


def _confirm_authority(repository: Path, config_path: Path):
    semantic = asyncio.run(
        confirm_customer_value(
            repository,
            config_path,
            "app.domain.mint_admission_pass",
            generated_at=NOW,
        )
    )
    return confirm_merchant_policy(
        repository,
        config_path,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    ), semantic


def test_ticketing_example_exposes_authentic_webhook_checkout_and_ambiguity(
    tmp_path: Path,
) -> None:
    repository, config_path = _copy_example(tmp_path)
    config = load_config(config_path)
    index = discover_and_index_project(repository, config, generated_at=NOW).source_index
    graph = construct_payment_safety_graph(repository, index, generated_at=NOW)
    ingress_by_path = {
        item.details.registration.effective_path: item
        for item in graph.nodes
        if isinstance(item.details, PaymentIngressDetails)
    }
    assert set(ingress_by_path) == {"/webhooks/razorpay", "/checkout/complete"}

    route_paths = {
        item.details.registration.route_registration_id: path
        for path, item in ingress_by_path.items()
    }
    trust = {
        (route_paths[item.details.route_registration_id], item.details.trust_kind)
        for item in graph.nodes
        if isinstance(item.details, TrustGateDetails)
    }
    assert {
        ("/webhooks/razorpay", TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION),
        ("/checkout/complete", TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION),
        ("/checkout/complete", TrustGateKind.SERVER_ORDER_IDENTITY_BINDING),
    } <= trust

    context = build_semantic_context(repository, index, graph).descriptor
    names_by_id = {item.symbol_id: item.qualified_name for item in index.symbols}
    relevant_names = {names_by_id[item] for item in context.relevant_symbol_ids}
    assert {
        "app.domain.bind_attendee_roster_row",
        "app.domain.mint_admission_pass",
    } <= relevant_names


def test_ticketing_applicability_keeps_checkout_out_of_sg01(
    tmp_path: Path,
) -> None:
    repository, config_path = _copy_example(tmp_path)
    result, semantic = _confirm_authority(repository, config_path)
    assert semantic.artifact.resolution is not None
    assert semantic.artifact.resolution.selected_symbol_id is not None

    ingress_paths = {
        item.node_id: item.details.registration.effective_path
        for item in result.snapshot.graph.nodes
        if isinstance(item.details, PaymentIngressDetails)
    }
    controls_by_path = {
        ingress_paths[item.ingress_node_id]: item for item in result.artifact.normal_controls
    }
    assert set(controls_by_path) == {"/webhooks/razorpay", "/checkout/complete"}

    sg01 = _scenario(result.artifact, ScenarioId.SG_01)
    assert {
        ingress_paths[item.ingress_node_id]
        for item in sg01.instances
        if item.ingress_node_id is not None
    } == {"/webhooks/razorpay"}
    assert sg01.state == ApplicabilityState.APPLICABLE
    for scenario_id in (
        ScenarioId.SG_02,
        ScenarioId.SG_03,
        ScenarioId.SG_04,
        ScenarioId.SG_05,
        ScenarioId.SG_06,
        ScenarioId.SG_07,
    ):
        assert _scenario(result.artifact, scenario_id).state == ApplicabilityState.APPLICABLE
    assert _scenario(result.artifact, ScenarioId.SG_08).state == (ApplicabilityState.NOT_APPLICABLE)


def test_ticketing_fix_preserves_structural_customer_call_edges(
    tmp_path: Path,
) -> None:
    repository, config_path = _copy_example(tmp_path)
    shutil.copyfile(
        repository / "templates" / "main.vulnerable.py",
        repository / "app" / "main.py",
    )
    vulnerable, _ = _confirm_authority(repository, config_path)
    customer_ids = {
        item.node_id
        for item in vulnerable.snapshot.graph.nodes
        if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
    }
    before = {
        item.source_node_id: item.edge_id
        for item in vulnerable.snapshot.graph.edges
        if item.kind == GraphEdgeKind.CALLS and item.target_node_id in customer_ids
    }

    shutil.copyfile(repository / "templates" / "main.fixed.py", repository / "app" / "main.py")
    fixed_semantic = asyncio.run(
        confirm_customer_value(
            repository,
            config_path,
            "app.domain.mint_admission_pass",
            generated_at=NOW,
        )
    )
    fixed = confirm_merchant_policy(
        repository,
        config_path,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    )
    fixed_customer_ids = {
        item.node_id
        for item in fixed.snapshot.graph.nodes
        if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
    }
    after = {
        item.source_node_id: item.edge_id
        for item in fixed.snapshot.graph.edges
        if item.kind == GraphEdgeKind.CALLS and item.target_node_id in fixed_customer_ids
    }

    assert fixed_semantic.artifact.resolution_fingerprint != (
        vulnerable.snapshot.resolution_fingerprint
    )
    assert before == after
    assert vulnerable.snapshot.graph.graph_fingerprint != fixed.snapshot.graph.graph_fingerprint


def test_reset_is_bounded_repeatable_and_does_not_read_provider_key(
    tmp_path: Path,
) -> None:
    repository, _ = _copy_example(tmp_path)
    secret = "provider-secret-must-not-appear"
    environment = {**os.environ, "GEMINI_API_KEY": secret}

    fixed = subprocess.run(
        [sys.executable, "reset_demo.py", "fixed"],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert secret not in fixed.stdout + fixed.stderr
    assert (repository / "app" / "main.py").read_bytes() == (
        repository / "templates" / "main.fixed.py"
    ).read_bytes()

    first = (repository / "app" / "main.py").read_bytes()
    subprocess.run(
        [sys.executable, "reset_demo.py", "fixed"],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
    )
    assert (repository / "app" / "main.py").read_bytes() == first

    subprocess.run(
        [sys.executable, "reset_demo.py", "vulnerable"],
        cwd=repository,
        env=environment,
        check=True,
        capture_output=True,
    )
    assert (repository / "app" / "main.py").read_bytes() == (
        repository / "templates" / "main.vulnerable.py"
    ).read_bytes()
    assert "mint_admission_pass(payment_id)" in (repository / "app" / "main.py").read_text(
        encoding="utf-8"
    )
