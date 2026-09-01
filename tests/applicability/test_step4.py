from __future__ import annotations

import asyncio
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from stateguard.applicability.contracts import (
    SG04_CUSTOMER_VALUE_ASSERTION_KEY,
    SG04_STATE_REGRESSION_ASSERTION_KEY,
    SG08_CAPTURE_ASSERTION_KEY,
    SG08_LATE_POLICY_ASSERTION_KEY,
    SG08_PRECAPTURE_ASSERTION_KEY,
    ApplicabilityReason,
    ApplicabilityReasonCode,
    ApplicabilityState,
    AssertionApplicability,
    AssertionRole,
    EvidenceReferenceKind,
    PolicyEvidenceStatus,
    ScenarioApplicability,
    ScenarioApplicabilityArtifact,
    ScenarioId,
    ScenarioInstance,
    roll_up_assertions,
)
from stateguard.applicability.engine import customer_value_allowed, evaluate_applicability
from stateguard.application.applicability import (
    analyze_applicability,
    confirm_merchant_policy,
)
from stateguard.application.semantics import confirm_customer_value, resolve_customer_value
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy
from stateguard.contracts.identity import (
    assertion_id,
    new_project_id,
    scenario_instance_id,
    sha256_digest,
)
from stateguard.graph.contracts import (
    BranchDisposition,
    GraphDiagnosticCode,
    GraphDiagnosticImpact,
    GraphDiagnosticRecord,
    GraphEdgeKind,
    GraphNodeKind,
    PaymentIngressDetails,
    PaymentSafetyGraphArtifact,
    PaymentStateGateDetails,
    graph_completeness_for,
    graph_fingerprint,
)
from stateguard.graph.reachability import compose_effective_routes
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint
from stateguard.workspace.applicability_artifacts import load_applicability_artifact
from stateguard.workspace.config import load_config

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 25, tzinfo=UTC)


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    shutil.copytree(FIXTURES / "policy_app", repository)
    config = repository / "stateguard.yaml"
    config.write_text(
        f"""# keep merchant comment
schema_version: 2
project:
  id: {new_project_id()}
  app_target: main:app
analysis:
  include: ["**/*.py"]
  exclude: []
""",
        encoding="utf-8",
    )
    return repository, config


def _source_repository(
    tmp_path: Path,
    *,
    main_source: str,
    domain_source: str = "def grant_ticket(payment_id):\n    return payment_id\n",
) -> tuple[Path, Path]:
    repository = tmp_path / "merchant"
    repository.mkdir()
    (repository / "main.py").write_text(main_source, encoding="utf-8")
    (repository / "domain.py").write_text(domain_source, encoding="utf-8")
    config = repository / "stateguard.yaml"
    config.write_text(
        f"""schema_version: 2
project:
  id: {new_project_id()}
  app_target: main:app
analysis:
  include: ["**/*.py"]
  exclude: []
""",
        encoding="utf-8",
    )
    return repository, config


def _resolve_and_confirm(repository: Path, config: Path) -> None:
    result = asyncio.run(resolve_customer_value(repository, config, generated_at=NOW))
    selected = next(
        item.symbol_id
        for item in result.source_index.symbols
        if item.qualified_name == "domain.grant_ticket"
    )
    asyncio.run(confirm_customer_value(repository, config, selected, generated_at=NOW))


def _scenario(
    artifact: ScenarioApplicabilityArtifact, scenario_id: ScenarioId
) -> ScenarioApplicability:
    return next(item for item in artifact.scenarios if item.scenario_id == scenario_id)


def test_policy_composition_never_lets_fulfil_later_lower_capture_threshold() -> None:
    assert not customer_value_allowed(
        FulfilmentPolicy.CAPTURE_REQUIRED,
        LateAuthorisationPolicy.FULFIL_LATER,
        payment_is_late_authorised=True,
        payment_state="payment.authorized",
    )
    assert customer_value_allowed(
        FulfilmentPolicy.CAPTURE_REQUIRED,
        LateAuthorisationPolicy.FULFIL_LATER,
        payment_is_late_authorised=True,
        payment_state="payment.captured",
    )
    assert not customer_value_allowed(
        FulfilmentPolicy.AUTHORIZED_ALLOWED,
        LateAuthorisationPolicy.DO_NOT_FULFIL,
        payment_is_late_authorised=True,
        payment_state="captured",
    )
    assert customer_value_allowed(
        FulfilmentPolicy.AUTHORIZED_ALLOWED,
        LateAuthorisationPolicy.FULFIL_LATER,
        payment_is_late_authorised=True,
        payment_state="authorized",
    )


def test_exact_controls_and_only_required_customer_value_relationships(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path)
    _resolve_and_confirm(repository, config)
    result = analyze_applicability(repository, config, generated_at=NOW)
    artifact = result.artifact

    assert len(artifact.normal_controls) == 3
    assert len({item.control_id for item in artifact.normal_controls}) == 3
    assert len({item.route_registration_id for item in artifact.normal_controls}) == 3
    customer_ids = {
        item.node_id
        for item in result.snapshot.graph.nodes
        if item.kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
    }
    customer_edges = [
        item for item in result.snapshot.graph.edges if item.target_node_id in customer_ids
    ]
    assert {GraphEdgeKind.BRANCHES_TO, GraphEdgeKind.ACKNOWLEDGES_AFTER} <= {
        item.kind for item in customer_edges
    }
    assert not any(item.kind == GraphEdgeKind.GUARDS for item in customer_edges)
    assert artifact.policy.fulfilment.evidence_status == PolicyEvidenceStatus.INSUFFICIENT_EVIDENCE
    assert artifact.policy.fulfilment.suggested_policy is None

    sg01 = _scenario(artifact, ScenarioId.SG_01)
    assert len(sg01.instances) == 2
    for instance in sg01.instances:
        assert instance.normal_control_id is not None
        control = next(
            item
            for item in artifact.normal_controls
            if item.control_id == instance.normal_control_id
        )
        assert control.ingress_kind.value == "WEBHOOK"
        assert all(
            assertion.normal_control_id == instance.normal_control_id
            for assertion in instance.assertions
        )


def test_sg01_requires_current_capture_threshold_authority(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path)
    _resolve_and_confirm(repository, config)
    confirmed = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    )
    ingress_paths = {
        item.node_id: item.details.registration.effective_path
        for item in confirmed.snapshot.graph.nodes
        if isinstance(item.details, PaymentIngressDetails)
    }
    sg01 = _scenario(confirmed.artifact, ScenarioId.SG_01)
    states_by_path = {
        ingress_paths[instance.ingress_node_id]: instance.state
        for instance in sg01.instances
        if instance.ingress_node_id is not None
    }
    assert states_by_path == {
        "/webhooks/captured": ApplicabilityState.APPLICABLE,
        "/webhooks/authorized": ApplicabilityState.INDETERMINATE,
    }
    captured = next(
        item
        for item in sg01.instances
        if ingress_paths.get(item.ingress_node_id) == "/webhooks/captured"
    )
    captured_control = next(
        item
        for item in confirmed.artifact.normal_controls
        if item.control_id == captured.normal_control_id
    )
    captured_control_edges = tuple(
        edge
        for edge in confirmed.snapshot.graph.edges
        if edge.kind == GraphEdgeKind.BRANCHES_TO
        and edge.target_node_id == captured_control.customer_value_node_id
        and edge.branch is not None
        and edge.branch.disposition == BranchDisposition.MATCHED
        and "payment.captured" in edge.branch.states
    )
    assert captured_control_edges
    assert captured.assertions[0].reasons[0].code == (
        ApplicabilityReasonCode.NORMAL_CAPTURE_THRESHOLD_AVAILABLE
    )
    unresolved = tuple(item for item in sg01.instances if item.instance_id != captured.instance_id)
    assert all(
        item.assertions[0].reasons[0].code
        == ApplicabilityReasonCode.NORMAL_CAPTURE_THRESHOLD_UNPROVEN
        for item in unresolved
    )

    sg02 = _scenario(confirmed.artifact, ScenarioId.SG_02)
    sg02_states_by_path = {
        ingress_paths[instance.ingress_node_id]: instance.state
        for instance in sg02.instances
        if instance.ingress_node_id is not None
    }
    assert sg02_states_by_path == {
        "/webhooks/captured": ApplicabilityState.APPLICABLE,
        "/webhooks/authorized": ApplicabilityState.INDETERMINATE,
    }
    sg02_captured = next(
        item
        for item in sg02.instances
        if ingress_paths.get(item.ingress_node_id) == "/webhooks/captured"
    )
    assert sg02_captured.assertions[0].reasons[0].code == (
        ApplicabilityReasonCode.CAPTURED_EVENT_TARGET_AVAILABLE
    )
    assert (
        sg02_captured.assertions[0].reasons[0].evidence
        == captured.assertions[0].reasons[0].evidence
    )


def test_sg01_and_sg02_reject_same_route_captured_state_unrelated_to_exact_control(
    tmp_path: Path,
) -> None:
    repository, config = _source_repository(
        tmp_path,
        main_source="""import razorpay
from domain import grant_ticket
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))
orders = {"merchant-order": {"status": "pending"}}

@app.post("/webhook-mixed")
async def mixed_webhook(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
    if payload["event"] == "payment.authorized":
        grant_ticket(payload["payment_id"])
    return {"ok": True}
""",
    )
    _resolve_and_confirm(repository, config)
    confirmed = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    )
    graph = confirmed.snapshot.graph
    control = confirmed.artifact.normal_controls[0]
    nodes = {item.node_id: item for item in graph.nodes}
    captured_gate_ids = {
        item.node_id
        for item in graph.nodes
        if isinstance(item.details, PaymentStateGateDetails)
        and "payment.captured" in item.details.states
    }
    assert captured_gate_ids
    assert any(
        edge.kind == GraphEdgeKind.BRANCHES_TO
        and edge.source_node_id in captured_gate_ids
        and nodes[edge.target_node_id].kind == GraphNodeKind.MERCHANT_STATE_MUTATION
        for edge in graph.edges
    )
    exact_control_edges = tuple(
        edge
        for edge in graph.edges
        if edge.kind == GraphEdgeKind.BRANCHES_TO
        and edge.target_node_id == control.customer_value_node_id
        and edge.branch is not None
        and edge.branch.disposition == BranchDisposition.MATCHED
    )
    assert any("payment.authorized" in edge.branch.states for edge in exact_control_edges)
    assert not any("payment.captured" in edge.branch.states for edge in exact_control_edges)

    sg01 = _scenario(confirmed.artifact, ScenarioId.SG_01)
    instance = next(item for item in sg01.instances if item.normal_control_id == control.control_id)
    assert instance.state == ApplicabilityState.INDETERMINATE
    assert instance.assertions[0].reasons[0].code == (
        ApplicabilityReasonCode.NORMAL_CAPTURE_THRESHOLD_UNPROVEN
    )
    sg02 = _scenario(confirmed.artifact, ScenarioId.SG_02)
    sg02_instance = next(
        item for item in sg02.instances if item.normal_control_id == control.control_id
    )
    assert sg02_instance.state == ApplicabilityState.INDETERMINATE
    assert sg02_instance.assertions[0].reasons[0].code == (
        ApplicabilityReasonCode.CAPTURED_EVENT_TARGET_UNPROVEN
    )


def test_customer_value_execution_edges_require_direct_or_awaited_execution(
    tmp_path: Path,
) -> None:
    repository, config = _source_repository(
        tmp_path,
        domain_source=(
            'async def grant_ticket(payment_id):\n    return {"payment_id": payment_id}\n'
        ),
        main_source="""import razorpay
from domain import grant_ticket
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))

@app.post("/webhook-awaited")
async def awaited_webhook(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        await grant_ticket(payload["payment_id"])
        return {"ok": True}
    return {"ok": False}

@app.post("/webhook-unawaited")
async def unawaited_webhook(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        grant_ticket(payload["payment_id"])
        return {"ok": True}
    return {"ok": False}

@app.post("/webhook-order-unresolved")
async def unresolved_order_webhook(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        if payload.get("issue"):
            await grant_ticket(payload["payment_id"])
    return {"ok": True}
""",
    )
    _resolve_and_confirm(repository, config)
    analyzed = analyze_applicability(repository, config, generated_at=NOW)
    graph = analyzed.snapshot.graph
    nodes = {item.node_id: item for item in graph.nodes}
    ingress_by_path = {
        item.details.registration.effective_path: item
        for item in graph.nodes
        if isinstance(item.details, PaymentIngressDetails)
    }
    route_by_path = {}
    for path, ingress in ingress_by_path.items():
        assert isinstance(ingress.details, PaymentIngressDetails)
        route_by_path[path] = ingress.details.registration.route_registration_id

    def relationship_kinds(path: str) -> set[GraphEdgeKind]:
        route_id = route_by_path[path]
        return {
            edge.kind
            for edge in graph.edges
            if edge.kind in {GraphEdgeKind.BRANCHES_TO, GraphEdgeKind.ACKNOWLEDGES_AFTER}
            and getattr(nodes[edge.source_node_id].details, "route_registration_id", None)
            == route_id
            and nodes[edge.target_node_id].kind == GraphNodeKind.CUSTOMER_VALUE_ACTION
        }

    assert relationship_kinds("/webhook-awaited") == {
        GraphEdgeKind.BRANCHES_TO,
        GraphEdgeKind.ACKNOWLEDGES_AFTER,
    }
    assert relationship_kinds("/webhook-unawaited") == set()
    assert relationship_kinds("/webhook-order-unresolved") == {GraphEdgeKind.BRANCHES_TO}
    assert any(
        diagnostic.route_registration_id == route_by_path["/webhook-unawaited"]
        and diagnostic.impact == GraphDiagnosticImpact.COVERAGE_REDUCED
        for diagnostic in graph.diagnostics
    )

    confirmed = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    )
    sg03 = _scenario(confirmed.artifact, ScenarioId.SG_03)
    states_by_route = {
        instance.route_registration_id: instance.state for instance in sg03.instances
    }
    assert states_by_route[route_by_path["/webhook-awaited"]] == ApplicabilityState.APPLICABLE
    assert states_by_route[route_by_path["/webhook-unawaited"]] == ApplicabilityState.INDETERMINATE
    assert (
        states_by_route[route_by_path["/webhook-order-unresolved"]]
        == ApplicabilityState.INDETERMINATE
    )


def test_cross_route_and_cross_kind_normal_control_substitution_is_rejected(
    tmp_path: Path,
) -> None:
    repository, config = _source_repository(
        tmp_path,
        main_source="""import razorpay
from domain import grant_ticket
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))

@app.post("/webhook-a")
@app.post("/webhook-b")
async def shared_webhook(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        grant_ticket(payload["payment_id"])
        return {"ok": True}
    return {"ok": False}

@app.post("/checkout/callback")
async def checkout_callback(request: Request):
    payload = await request.json()
    client.utility.verify_payment_signature(
        {
            "razorpay_payment_id": payload["razorpay_payment_id"],
            "razorpay_order_id": "server-order",
            "razorpay_signature": payload["razorpay_signature"],
        }
    )
    grant_ticket(payload["razorpay_payment_id"])
    return {"ok": True}
""",
    )
    _resolve_and_confirm(repository, config)
    result = analyze_applicability(repository, config, generated_at=NOW)
    ingress_paths = {
        item.node_id: item.details.registration.effective_path
        for item in result.snapshot.graph.nodes
        if isinstance(item.details, PaymentIngressDetails)
    }
    controls_by_path = {
        ingress_paths[control.ingress_node_id]: control
        for control in result.artifact.normal_controls
    }
    assert set(controls_by_path) == {
        "/webhook-a",
        "/webhook-b",
        "/checkout/callback",
    }
    assert (
        controls_by_path["/webhook-a"].route_registration_id
        != controls_by_path["/webhook-b"].route_registration_id
    )

    def assert_substitution_rejected(
        scenario_id: ScenarioId,
        original_control_id: str,
        replacement_control_id: str,
    ) -> None:
        scenario = _scenario(result.artifact, scenario_id)
        original = next(
            item for item in scenario.instances if item.normal_control_id == original_control_id
        )
        assertions = tuple(
            assertion.model_copy(
                update={
                    "normal_control_id": (
                        replacement_control_id if assertion.normal_control_id is not None else None
                    )
                }
            )
            for assertion in original.assertions
        )
        substituted = ScenarioInstance(
            **original.model_dump(exclude={"normal_control_id", "assertions"}),
            normal_control_id=replacement_control_id,
            assertions=assertions,
        )
        altered = ScenarioApplicability(
            scenario_id=scenario.scenario_id,
            state=scenario.state,
            instances=tuple(
                substituted if item.instance_id == original.instance_id else item
                for item in scenario.instances
            ),
        )
        payload = result.artifact.model_dump(mode="python")
        payload["scenarios"] = tuple(
            altered if item.scenario_id == scenario_id else item
            for item in result.artifact.scenarios
        )
        with pytest.raises(ValueError, match="ingress must match exact normal control"):
            ScenarioApplicabilityArtifact.model_validate(payload)

    webhook_a = controls_by_path["/webhook-a"].control_id
    webhook_b = controls_by_path["/webhook-b"].control_id
    callback = controls_by_path["/checkout/callback"].control_id
    assert_substitution_rejected(ScenarioId.SG_02, webhook_a, webhook_b)
    assert_substitution_rejected(ScenarioId.SG_01, webhook_a, webhook_b)
    assert callback not in {
        item.normal_control_id for item in _scenario(result.artifact, ScenarioId.SG_01).instances
    }


@pytest.mark.parametrize(
    ("fulfilment", "late", "expected_keys", "expected_state"),
    [
        (
            FulfilmentPolicy.CAPTURE_REQUIRED,
            LateAuthorisationPolicy.FULFIL_LATER,
            {SG08_PRECAPTURE_ASSERTION_KEY, SG08_CAPTURE_ASSERTION_KEY},
            ApplicabilityState.APPLICABLE,
        ),
        (
            FulfilmentPolicy.CAPTURE_REQUIRED,
            LateAuthorisationPolicy.DO_NOT_FULFIL,
            {SG08_PRECAPTURE_ASSERTION_KEY},
            ApplicabilityState.APPLICABLE,
        ),
        (
            FulfilmentPolicy.AUTHORIZED_ALLOWED,
            LateAuthorisationPolicy.FULFIL_LATER,
            {SG08_LATE_POLICY_ASSERTION_KEY},
            ApplicabilityState.INDETERMINATE,
        ),
        (
            FulfilmentPolicy.AUTHORIZED_ALLOWED,
            LateAuthorisationPolicy.DO_NOT_FULFIL,
            {SG08_LATE_POLICY_ASSERTION_KEY},
            ApplicabilityState.INDETERMINATE,
        ),
    ],
)
def test_sg08_policy_matrix_selects_exact_assertions(
    tmp_path: Path,
    fulfilment: FulfilmentPolicy,
    late: LateAuthorisationPolicy,
    expected_keys: set[str],
    expected_state: ApplicabilityState,
) -> None:
    repository, config = _repository(tmp_path)
    _resolve_and_confirm(repository, config)
    result = confirm_merchant_policy(
        repository,
        config,
        fulfilment=fulfilment,
        late_authorisation=late,
        generated_at=NOW,
    )
    sg08 = _scenario(result.artifact, ScenarioId.SG_08)
    assert sg08.state == expected_state
    assert all(
        {assertion.key for assertion in instance.assertions} == expected_keys
        for instance in sg08.instances
    )
    assert all(
        assertion.normal_control_id == instance.normal_control_id
        for instance in sg08.instances
        for assertion in instance.assertions
    )


def test_policy_confirmation_is_explicit_atomic_and_does_not_hide_mismatch(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path)
    _resolve_and_confirm(repository, config)
    with pytest.raises(ValueError, match="explicit"):
        confirm_merchant_policy(repository, config, generated_at=NOW)

    result = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    )
    loaded = load_config(config)
    assert loaded.policy is not None and loaded.policy.fulfilment is not None
    assert loaded.policy.fulfilment.value == FulfilmentPolicy.CAPTURE_REQUIRED
    assert "# keep merchant comment" in config.read_text(encoding="utf-8")
    assert load_applicability_artifact(repository) == result.artifact
    artifact_path = repository / ".stateguard" / "applicability.json"
    assert artifact_path.stat().st_mode & 0o777 == 0o600
    payload = artifact_path.read_text(encoding="utf-8")
    assert "VERIFIED PASS" not in payload
    assert "VERIFIED FAIL" not in payload


def test_policy_fingerprint_is_local_and_stale_evidence_keeps_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, config = _repository(tmp_path)
    _resolve_and_confirm(repository, config)
    confirmed = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.AUTHORIZED_ALLOWED,
        generated_at=NOW,
    )
    evidence_fp = confirmed.artifact.policy.fulfilment.evidence_fingerprint
    config.write_text(
        config.read_text(encoding="utf-8")
        + """ai:
  provider: gemini
  model: unrelated-model
  api_key_env: UNRELATED_KEY
""",
        encoding="utf-8",
    )
    unchanged = analyze_applicability(repository, config, generated_at=NOW)
    assert unchanged.artifact.policy.fulfilment.evidence_fingerprint == evidence_fp
    assert unchanged.artifact.policy.fulfilment.evidence_current

    (repository / "notes.py").write_text(
        "def unrelated_helper():\n    return 'unrelated'\n",
        encoding="utf-8",
    )
    unrelated_file = analyze_applicability(repository, config, generated_at=NOW)
    assert unrelated_file.artifact.policy.fulfilment.evidence_fingerprint == evidence_fp

    main_source = repository / "main.py"
    main_source.write_text(
        main_source.read_text(encoding="utf-8")
        + """

@app.get("/health")
async def health():
    return {"ok": True}
""",
        encoding="utf-8",
    )
    unrelated_route = analyze_applicability(repository, config, generated_at=NOW)
    assert unrelated_route.artifact.policy.fulfilment.evidence_fingerprint == evidence_fp
    assert unrelated_route.artifact.policy.late_authorisation.evidence_fingerprint == (
        unchanged.artifact.policy.late_authorisation.evidence_fingerprint
    )

    health_route_id = next(
        item.registration.route_registration_id
        for item in compose_effective_routes(unrelated_route.snapshot.source_index).routes
        if item.registration.effective_path == "/health"
    )

    def graph_with_diagnostic(route_id: str) -> PaymentSafetyGraphArtifact:
        graph = unrelated_route.snapshot.graph
        diagnostics = (
            *graph.diagnostics,
            GraphDiagnosticRecord(
                code=GraphDiagnosticCode.CONTROL_FLOW_UNSUPPORTED,
                impact=GraphDiagnosticImpact.COVERAGE_REDUCED,
                route_registration_id=route_id,
            ),
        )
        completeness = graph_completeness_for(diagnostics)
        fingerprint = graph_fingerprint(
            project_id=graph.project_id,
            source_index_fingerprint=graph.source_index_fingerprint,
            completeness=completeness,
            diagnostics=diagnostics,
            nodes=graph.nodes,
            edges=graph.edges,
        )
        return PaymentSafetyGraphArtifact(
            producer_version=graph.producer_version,
            generated_at=graph.generated_at,
            project_id=graph.project_id,
            source_index_fingerprint=graph.source_index_fingerprint,
            graph_fingerprint=fingerprint,
            completeness=completeness,
            diagnostics=diagnostics,
            nodes=graph.nodes,
            edges=graph.edges,
        )

    def evaluate_with_graph(
        graph: PaymentSafetyGraphArtifact,
    ) -> ScenarioApplicabilityArtifact:
        snapshot = unrelated_route.snapshot
        return evaluate_applicability(
            generated_at=NOW,
            config=load_config(config),
            source_index=snapshot.source_index,
            structural_graph=snapshot.structural_graph,
            projected_graph=graph,
            resolution=snapshot.resolution,
            resolution_fingerprint=snapshot.resolution_fingerprint,
        )

    unrelated_diagnostic = evaluate_with_graph(graph_with_diagnostic(health_route_id))
    assert unrelated_diagnostic.policy.fulfilment.evidence_fingerprint == evidence_fp

    relevant_route_id = unrelated_route.artifact.normal_controls[0].route_registration_id
    relevant_diagnostic = evaluate_with_graph(graph_with_diagnostic(relevant_route_id))
    assert relevant_diagnostic.policy.fulfilment.evidence_fingerprint != evidence_fp
    stale_policy_sg01 = _scenario(relevant_diagnostic, ScenarioId.SG_01)
    assert all(item.state == ApplicabilityState.NEEDS_INPUT for item in stale_policy_sg01.instances)
    assert all(
        assertion.reasons[0].code == ApplicabilityReasonCode.FULFILMENT_POLICY_STALE
        for item in stale_policy_sg01.instances
        for assertion in item.assertions
    )

    original_rule_fingerprint = razorpay_rule_fingerprint
    monkeypatch.setattr(
        "stateguard.applicability.engine.razorpay_rule_fingerprint",
        lambda rule_id: (
            sha256_digest(b"changed-relevant-policy-rule")
            if rule_id == RazorpayProtocolRuleId.CAPTURE_BEFORE_FULFILMENT
            else original_rule_fingerprint(rule_id)
        ),
    )
    revised_rule = analyze_applicability(repository, config, generated_at=NOW)
    assert revised_rule.artifact.policy.fulfilment.evidence_fingerprint != evidence_fp
    monkeypatch.setattr(
        "stateguard.applicability.engine.razorpay_rule_fingerprint",
        original_rule_fingerprint,
    )

    source = repository / "main.py"
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            'payload["event"] == "payment.captured"',
            'payload["event"] == "payment.failed"',
        ),
        encoding="utf-8",
    )
    changed = analyze_applicability(repository, config, generated_at=NOW)
    assert changed.artifact.policy.fulfilment.confirmed_policy == (
        FulfilmentPolicy.AUTHORIZED_ALLOWED
    )
    assert not changed.artifact.policy.fulfilment.evidence_current
    stale_sg01 = _scenario(changed.artifact, ScenarioId.SG_01)
    assert all(item.state == ApplicabilityState.NEEDS_INPUT for item in stale_sg01.instances)


def test_sg03_requires_proven_pre_acknowledgement_customer_value(tmp_path: Path) -> None:
    repository, config = _repository(tmp_path)
    _resolve_and_confirm(repository, config)
    result = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    )
    sg03 = _scenario(result.artifact, ScenarioId.SG_03)
    assert sg03.state == ApplicabilityState.APPLICABLE
    applicable = tuple(
        instance for instance in sg03.instances if instance.state == ApplicabilityState.APPLICABLE
    )
    assert applicable
    assert all(
        assertion.reasons[0].code == ApplicabilityReasonCode.VALUE_BEFORE_ACK_PROVEN
        for instance in applicable
        for assertion in instance.assertions
    )
    assert all(
        any(
            evidence.kind == EvidenceReferenceKind.GRAPH_NODE
            for reason in assertion.reasons
            for evidence in reason.evidence
        )
        for instance in applicable
        for assertion in instance.assertions
    )


def test_sg04_optional_regression_evidence_does_not_leak_across_routes(
    tmp_path: Path,
) -> None:
    repository, config = _repository(tmp_path)
    _resolve_and_confirm(repository, config)
    result = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    )
    sg04 = _scenario(result.artifact, ScenarioId.SG_04)
    optional = [
        assertion
        for instance in sg04.instances
        for assertion in instance.assertions
        if assertion.key == "MERCHANT_STATE_DOES_NOT_REGRESS"
    ]
    assert len(optional) == 2
    assert all(item.state == ApplicabilityState.NOT_APPLICABLE for item in optional)


@pytest.mark.parametrize(
    ("state_field", "optional_state"),
    [
        ("last_event", ApplicabilityState.NOT_APPLICABLE),
        ("status", ApplicabilityState.APPLICABLE),
    ],
)
def test_sg04_transition_literals_only_strengthen_qualified_payment_state(
    tmp_path: Path,
    state_field: str,
    optional_state: ApplicabilityState,
) -> None:
    repository, config = _source_repository(
        tmp_path,
        main_source=f'''import razorpay
from domain import grant_ticket
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))
merchant_state = {{"{state_field}": "pending"}}

@app.post("/webhook")
async def payment_webhook(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        merchant_state["{state_field}"] = "captured"
        grant_ticket(payload["payload"]["payment"]["entity"]["id"])
        return {{"ok": True}}
    if payload["event"] == "payment.authorized":
        merchant_state["{state_field}"] = "authorized"
        return {{"ok": True}}
    return {{"ok": False}}
''',
    )
    _resolve_and_confirm(repository, config)
    result = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        generated_at=NOW,
    )
    instance = next(
        item
        for item in _scenario(result.artifact, ScenarioId.SG_04).instances
        if item.route_registration_id is not None
    )
    assertions = {item.key: item for item in instance.assertions}

    assert assertions[SG04_CUSTOMER_VALUE_ASSERTION_KEY].state == ApplicabilityState.APPLICABLE
    assert assertions[SG04_STATE_REGRESSION_ASSERTION_KEY].state == optional_state


def test_sg08_scopes_controls_to_late_authorisation_capability(tmp_path: Path) -> None:
    repository, config = _source_repository(
        tmp_path,
        main_source="""import razorpay
from domain import grant_ticket
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))

@app.post("/webhook-captured")
async def captured_webhook(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        grant_ticket(payload["payment_id"])
        return {"ok": True}
    return {"ok": False}

@app.post("/webhook-authorized")
async def authorized_webhook(request: Request):
    raw_body = await request.body()
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "secret"
    )
    payload = await request.json()
    if payload["event"] == "payment.authorized":
        grant_ticket(payload["payment_id"])
        return {"ok": True}
    return {"ok": False}

@app.post("/webhook-generic")
async def generic_webhook(request: Request):
    raw_body = await request.body()
    event_id = request.headers["x-razorpay-event-id"]
    client.utility.verify_webhook_signature(
        raw_body, request.headers["x-razorpay-signature"], "secret"
    )
    payload = await request.json()
    grant_ticket(payload["razorpay_payment_id"])
    return {"ok": True, "event_id": event_id}
""",
    )
    _resolve_and_confirm(repository, config)
    result = confirm_merchant_policy(
        repository,
        config,
        fulfilment=FulfilmentPolicy.CAPTURE_REQUIRED,
        late_authorisation=LateAuthorisationPolicy.FULFIL_LATER,
        generated_at=NOW,
    )
    ingress_paths = {
        item.details.registration.route_registration_id: item.details.registration.effective_path
        for item in result.snapshot.graph.nodes
        if isinstance(item.details, PaymentIngressDetails)
    }
    sg08 = _scenario(result.artifact, ScenarioId.SG_08)
    instances_by_path = {
        ingress_paths[instance.route_registration_id]: instance
        for instance in sg08.instances
        if instance.route_registration_id is not None
    }
    assert "/webhook-captured" not in instances_by_path
    assert "/webhook-authorized" in instances_by_path, (
        instances_by_path,
        ingress_paths,
        result.artifact.normal_controls,
    )
    assert instances_by_path["/webhook-authorized"].state == ApplicabilityState.APPLICABLE
    assert instances_by_path["/webhook-generic"].state == ApplicabilityState.INDETERMINATE


def test_assertion_rollup_is_internal_and_core_only() -> None:
    instance = scenario_instance_id("SG-99", "rollup")

    def assertion(
        key: str,
        role: AssertionRole,
        state: ApplicabilityState,
    ) -> AssertionApplicability:
        return AssertionApplicability(
            assertion_id=assertion_id(instance, key),
            key=key,
            role=role,
            state=state,
            reasons=(ApplicabilityReason(code=ApplicabilityReasonCode.INGRESS_ABSENT),),
        )

    assert (
        roll_up_assertions(
            (
                assertion("core", AssertionRole.CORE, ApplicabilityState.INDETERMINATE),
                assertion("optional", AssertionRole.OPTIONAL, ApplicabilityState.APPLICABLE),
            )
        )
        == ApplicabilityState.INDETERMINATE
    )
    assert (
        roll_up_assertions(
            (
                assertion("input", AssertionRole.CORE, ApplicabilityState.NEEDS_INPUT),
                assertion("unknown", AssertionRole.CORE, ApplicabilityState.INDETERMINATE),
            )
        )
        == ApplicabilityState.NEEDS_INPUT
    )


def test_analysis_never_invokes_provider_and_ingress_alone_does_not_roll_up_applicable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, config = _repository(tmp_path)
    monkeypatch.setattr(
        "stateguard.application.semantics.create_model_provider",
        lambda configured: (_ for _ in ()).throw(AssertionError("provider called")),
    )
    result = analyze_applicability(repository, config, generated_at=NOW)
    assert result.artifact.normal_controls == ()
    assert _scenario(result.artifact, ScenarioId.SG_02).state == ApplicabilityState.NEEDS_INPUT
    assert _scenario(result.artifact, ScenarioId.SG_03).state == ApplicabilityState.NEEDS_INPUT
    assert any(
        isinstance(item.details, PaymentIngressDetails) for item in result.snapshot.graph.nodes
    )
