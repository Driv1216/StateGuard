from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from stateguard.contracts.common import ProvenanceKind
from stateguard.contracts.config import StateGuardConfig
from stateguard.contracts.identity import new_project_id
from stateguard.discovery.service import (
    StaleSourceIndexError,
    discover_and_index_project,
)
from stateguard.graph.contracts import (
    AcknowledgementBoundaryDetails,
    AcknowledgementOutcome,
    CheckoutRequestTransport,
    GraphCompleteness,
    GraphDiagnosticCode,
    GraphDiagnosticReason,
    GraphEdgeKind,
    GraphNodeKind,
    MerchantStateMutationDetails,
    OrderIdentityOrigin,
    PaymentIngressDetails,
    TrustGateDetails,
    TrustGateKind,
)
from stateguard.graph.service import construct_payment_safety_graph

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "merchant_repos"
NOW = datetime(2026, 8, 24, tzinfo=UTC)


def _config(*, app_target: str = "main:app") -> StateGuardConfig:
    return StateGuardConfig.model_validate(
        {
            "schema_version": 2,
            "project": {
                "id": new_project_id(),
                "source_root": ".",
                "framework": "fastapi",
                "app_target": app_target,
            },
            "analysis": {"include": ["**/*.py"], "exclude": []},
        }
    )


def _repository(tmp_path: Path, name: str) -> Path:
    destination = tmp_path / name
    shutil.copytree(FIXTURES / name, destination)
    return destination


def _construct(repository: Path, *, config: StateGuardConfig | None = None):
    index = discover_and_index_project(
        repository, config or _config(), generated_at=NOW
    ).source_index
    return index, construct_payment_safety_graph(repository, index, generated_at=NOW)


def _registration_paths(graph) -> dict[str, str]:
    return {
        node.details.registration.route_registration_id: node.details.registration.effective_path
        for node in graph.nodes
        if isinstance(node.details, PaymentIngressDetails)
    }


def test_checkout_request_binding_recognizes_exact_supported_transports(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "checkout_bindings"
    repository.mkdir()
    (repository / "main.py").write_text(
        """from fastapi import Body, Cookie, Depends, FastAPI, Form, Header, Path, Request

app = FastAPI()
client = object()

def verify(payment_id, order_id, signature):
    client.utility.verify_payment_signature({
        "razorpay_payment_id": payment_id,
        "razorpay_order_id": order_id,
        "razorpay_signature": signature,
    })

@app.post("/json")
async def json_callback(request: Request):
    payload = await request.json()
    verify(
        payload["razorpay_payment_id"],
        payload["razorpay_order_id"],
        payload["razorpay_signature"],
    )

@app.post("/form")
async def form_callback(request: Request):
    payload = await request.form()
    verify(
        payload["razorpay_payment_id"],
        payload["razorpay_order_id"],
        payload["razorpay_signature"],
    )

@app.post("/json-optional")
async def json_optional_callback(request: Request):
    payload = await request.json()
    merchant_optional = payload.get("merchant_optional")
    verify(
        payload["razorpay_payment_id"],
        payload["razorpay_order_id"],
        payload["razorpay_signature"],
    )

@app.post("/json-extra-required")
async def json_extra_required_callback(request: Request):
    payload = await request.json()
    merchant_required = payload["merchant_required"]
    verify(
        payload["razorpay_payment_id"],
        payload["razorpay_order_id"],
        payload["razorpay_signature"],
    )

@app.post("/query")
async def query_callback(razorpay_payment_id: str, razorpay_order_id: str, razorpay_signature: str):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)

@app.post("/direct-form")
async def direct_form_callback(
    razorpay_payment_id: str = Form(...),
    razorpay_order_id: str = Form(...),
    razorpay_signature: str = Form(...),
):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)

@app.post("/direct-body")
async def direct_body_callback(
    razorpay_payment_id: str = Body(...),
    razorpay_order_id: str = Body(...),
    razorpay_signature: str = Body(...),
):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)

@app.post("/mixed")
async def mixed_callback(
    razorpay_payment_id: str,
    razorpay_order_id: str = Body(...),
    razorpay_signature: str = Body(...),
):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)

def required_dependency(merchant_token: str = Header(...)):
    return merchant_token

@app.post("/required-header")
async def required_header_callback(
    razorpay_payment_id: str,
    razorpay_order_id: str,
    razorpay_signature: str,
    merchant_token: str = Header(...),
):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)

@app.post("/required-cookie")
async def required_cookie_callback(
    razorpay_payment_id: str,
    razorpay_order_id: str,
    razorpay_signature: str,
    merchant_cookie: str = Cookie(...),
):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)

@app.post("/required-path/{merchant_id}")
async def required_path_callback(
    merchant_id: str = Path(...),
    razorpay_payment_id: str = "",
    razorpay_order_id: str = "",
    razorpay_signature: str = "",
):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)

@app.post("/required-dependency")
async def required_dependency_callback(
    razorpay_payment_id: str,
    razorpay_order_id: str,
    razorpay_signature: str,
    merchant_token: str = Depends(required_dependency),
):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)

@app.post("/optional-unrelated")
async def optional_unrelated_callback(
    razorpay_payment_id: str,
    razorpay_order_id: str,
    razorpay_signature: str,
    merchant_header: str = Header("header-default"),
    merchant_cookie: str = Cookie("cookie-default"),
    merchant_query: str = "query-default",
):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)

@app.post("/dynamic")
async def dynamic_callback(request: Request):
    payload = await request.json()
    dynamic_name = "razorpay_order_id"
    verify(
        payload["razorpay_payment_id"],
        payload[dynamic_name],
        payload["razorpay_signature"],
    )

@app.post("/uncontrolled")
async def uncontrolled_callback(
    razorpay_payment_id: str,
    razorpay_order_id: str,
    razorpay_signature: str,
    merchant_required: str,
):
    verify(razorpay_payment_id, razorpay_order_id, razorpay_signature)
""",
        encoding="utf-8",
    )
    _, graph = _construct(repository)
    bindings = {
        item.details.registration.effective_path: item.details.checkout_request_binding
        for item in graph.nodes
        if isinstance(item.details, PaymentIngressDetails)
    }

    assert bindings["/json"].transport == CheckoutRequestTransport.JSON
    assert bindings["/form"].transport == CheckoutRequestTransport.FORM_URLENCODED
    assert bindings["/json-optional"].transport == CheckoutRequestTransport.JSON
    assert bindings["/json-extra-required"] is None
    assert bindings["/query"].transport == CheckoutRequestTransport.QUERY
    assert bindings["/direct-form"].transport == CheckoutRequestTransport.FORM_URLENCODED
    assert bindings["/direct-body"].transport == CheckoutRequestTransport.JSON
    assert bindings["/mixed"] is None
    assert bindings["/dynamic"] is None
    assert bindings["/uncontrolled"] is None
    assert bindings["/required-header"] is None
    assert bindings["/required-cookie"] is None
    assert bindings["/required-path/{merchant_id}"] is None
    assert bindings["/required-dependency"] is None
    assert bindings["/optional-unrelated"].transport == CheckoutRequestTransport.QUERY
    for path in (
        "/json",
        "/form",
        "/json-optional",
        "/query",
        "/direct-form",
        "/direct-body",
        "/optional-unrelated",
    ):
        assert {item.canonical_name for item in bindings[path].fields} == {
            "razorpay_payment_id",
            "razorpay_order_id",
            "razorpay_signature",
        }


def test_webhook_facts_respect_control_origin_and_false_positive_boundaries(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path, "graph_webhooks")
    _, graph = _construct(repository)
    paths = _registration_paths(graph)
    ingress_paths = set(paths.values())

    assert graph.completeness == GraphCompleteness.COMPLETE
    assert "/webhook-looking-name-only" not in ingress_paths
    assert {
        "/webhooks/correct",
        "/webhooks/late",
        "/webhooks/event-observed",
        "/webhooks/parsed-body",
        "/webhooks/helper",
    }.issubset(ingress_paths)

    trust = [
        node
        for node in graph.nodes
        if isinstance(node.details, TrustGateDetails)
        and node.details.trust_kind == TrustGateKind.WEBHOOK_SIGNATURE_VERIFICATION
    ]
    assert {paths[node.details.route_registration_id] for node in trust} == {
        "/webhooks/correct",
        "/webhooks/late",
        "/webhooks/helper",
    }
    assert any(
        record.reference.startswith("call-site:")
        for node in trust
        if paths[node.details.route_registration_id] == "/webhooks/helper"
        for record in node.provenance
    )

    event_guards = [node for node in graph.nodes if node.kind == GraphNodeKind.EVENT_IDENTITY_GUARD]
    assert len(event_guards) == 1
    assert paths[event_guards[0].details.route_registration_id] == "/webhooks/correct"

    mutations = [
        node for node in graph.nodes if isinstance(node.details, MerchantStateMutationDetails)
    ]
    assert mutations
    assert all("metrics" not in node.label.casefold() for node in mutations)
    reasons = {item.reason for item in graph.diagnostics}
    assert GraphDiagnosticReason.EVENT_ID_OBSERVED_ONLY in reasons
    assert GraphDiagnosticReason.PARSED_BODY_USED in reasons
    assert GraphDiagnosticReason.VALIDATION_AFTER_MUTATION in reasons

    acknowledgements = [
        node.details
        for node in graph.nodes
        if isinstance(node.details, AcknowledgementBoundaryDetails)
    ]
    assert any(item.status_code == 202 for item in acknowledgements)
    assert any(item.status_code == 201 for item in acknowledgements)
    assert any(
        item.status_code == 409 and item.outcome == AcknowledgementOutcome.NON_SUCCESS
        for item in acknowledgements
    )


def test_checkout_signature_and_server_order_binding_are_separate_facts(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path, "graph_checkout")
    _, graph = _construct(repository)
    paths = _registration_paths(graph)
    trust = [node for node in graph.nodes if isinstance(node.details, TrustGateDetails)]

    signatures = {
        paths[node.details.route_registration_id]: node.details.order_identity_origin
        for node in trust
        if node.details.trust_kind == TrustGateKind.CHECKOUT_SIGNATURE_VERIFICATION
    }
    bindings = [
        node
        for node in trust
        if node.details.trust_kind == TrustGateKind.SERVER_ORDER_IDENTITY_BINDING
    ]
    assert graph.completeness == GraphCompleteness.PARTIAL
    assert signatures == {
        "/checkout/confirmed": OrderIdentityOrigin.SERVER_STATE_CONFIRMED,
        "/checkout/client-order": OrderIdentityOrigin.CLIENT_RETURNED,
        "/checkout/client-keyed-order": OrderIdentityOrigin.UNKNOWN,
        "/checkout/unknown-order": OrderIdentityOrigin.UNKNOWN,
    }
    assert len(bindings) == 1
    assert paths[bindings[0].details.route_registration_id] == "/checkout/confirmed"
    confirmed_nodes = [
        node for node in trust if paths[node.details.route_registration_id] == "/checkout/confirmed"
    ]
    assert len({node.node_id for node in confirmed_nodes}) == 2
    assert {item.reason for item in graph.diagnostics} >= {
        GraphDiagnosticReason.CLIENT_ORDER_ID_USED,
        GraphDiagnosticReason.ORDER_IDENTITY_UNKNOWN,
    }
    assert GraphDiagnosticCode.CALL_PATH_UNRESOLVED in {item.code for item in graph.diagnostics}


def test_graph_is_static_confidentiality_safe_and_deterministic(tmp_path: Path) -> None:
    repository = _repository(tmp_path, "graph_webhooks")
    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index
    first = construct_payment_safety_graph(repository, index, generated_at=NOW)
    second = construct_payment_safety_graph(
        repository, index, generated_at=NOW + timedelta(hours=1)
    )

    assert first.graph_fingerprint == second.graph_fingerprint
    assert first.nodes == second.nodes
    assert first.edges == second.edges
    assert not {
        GraphEdgeKind.TRIGGERS,
        GraphEdgeKind.MUTATES,
    } & {item.kind for item in first.edges}
    assert all(node.kind != GraphNodeKind.CUSTOMER_VALUE_ACTION for node in first.nodes)
    assert all(
        record.kind == ProvenanceKind.STATIC
        and record.supporting_fingerprint == index.source_index_fingerprint
        and record.reference.startswith(
            (
                "symbol:",
                "route-registration:",
                "source-reference:",
                "ast-fact:",
                "call-site:",
            )
        )
        for item in (*first.nodes, *first.edges)
        for record in item.provenance
    )
    persisted = first.model_dump_json()
    assert "webhook-secret" not in persisted
    assert "order_server" not in persisted


def test_stale_source_is_fatal_and_partial_index_remains_partial(tmp_path: Path) -> None:
    repository = _repository(tmp_path, "graph_webhooks")
    index = discover_and_index_project(repository, _config(), generated_at=NOW).source_index
    source = repository / "main.py"
    source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(StaleSourceIndexError):
        construct_payment_safety_graph(repository, index, generated_at=NOW)

    partial_repository = _repository(tmp_path, "graph_checkout")
    (partial_repository / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    partial_index = discover_and_index_project(
        partial_repository, _config(), generated_at=NOW
    ).source_index
    graph = construct_payment_safety_graph(partial_repository, partial_index, generated_at=NOW)
    assert graph.completeness == GraphCompleteness.PARTIAL
    assert GraphDiagnosticCode.UPSTREAM_SOURCE_INDEX_PARTIAL in {
        item.code for item in graph.diagnostics
    }
    assert graph.nodes


def test_unselected_app_produces_partial_empty_graph(tmp_path: Path) -> None:
    repository = _repository(tmp_path, "graph_checkout")
    _, graph = _construct(repository, config=_config(app_target="main:missing"))

    assert graph.completeness == GraphCompleteness.PARTIAL
    assert not graph.nodes
    assert not graph.edges
    assert GraphDiagnosticCode.APP_TARGET_UNSELECTED in {item.code for item in graph.diagnostics}
    assert GraphDiagnosticReason.INSUFFICIENT_CONVERGING_EVIDENCE in {
        item.reason for item in graph.diagnostics
    }
