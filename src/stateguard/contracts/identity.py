"""Deterministic identity and fingerprint helpers for immediate pipeline facts."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any

from pydantic import BaseModel

from .common import (
    AssertionId,
    FindingKey,
    FindingOccurrenceId,
    FrameworkInstanceId,
    GraphEdgeId,
    GraphNodeId,
    MerchantStateCarrierId,
    NormalControlId,
    ProjectId,
    RouteRegistrationId,
    RuntimeRequestId,
    RuntimeSessionId,
    ScenarioExecutionId,
    ScenarioInstanceId,
    Sha256Digest,
    SourceFileId,
    SymbolId,
    VerificationCheckId,
    VerificationCheckKey,
    VerificationRunId,
    normalize_relative_path,
)


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_digest(value: bytes | str) -> Sha256Digest:
    payload = value.encode("utf-8") if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def fingerprint_json(value: Any) -> Sha256Digest:
    return sha256_digest(canonical_json(value))


def _stable_id(prefix: str, *components: object) -> str:
    canonical = "\x1f".join(str(component) for component in components)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]
    return f"{prefix}_{digest}"


def new_project_id() -> ProjectId:
    return f"sgproj_{uuid.uuid4().hex}"


def source_file_id(project_id: ProjectId, path: str) -> SourceFileId:
    return _stable_id("sgfile", project_id, normalize_relative_path(path))


def symbol_id(
    file_id: SourceFileId,
    qualified_name: str,
    kind: str,
    definition_ordinal: int = 0,
) -> SymbolId:
    if definition_ordinal < 0:
        raise ValueError("definition ordinal must not be negative")
    if not qualified_name.strip() or not kind.strip():
        raise ValueError("symbol qualified name and kind must not be blank")
    return _stable_id("sgsym", file_id, qualified_name.strip(), kind.strip(), definition_ordinal)


def framework_instance_id(
    file_id: SourceFileId,
    qualified_binding_name: str,
    kind: str,
    definition_ordinal: int = 0,
) -> FrameworkInstanceId:
    if definition_ordinal < 0:
        raise ValueError("framework-instance definition ordinal must not be negative")
    if not qualified_binding_name.strip() or not kind.strip():
        raise ValueError("framework-instance binding name and kind must not be blank")
    return _stable_id(
        "sgfw",
        file_id,
        qualified_binding_name.strip(),
        kind.strip(),
        definition_ordinal,
    )


def graph_node_id(kind: str, backing_identity: str, discriminator: str = "") -> GraphNodeId:
    if not kind.strip() or not backing_identity.strip():
        raise ValueError("graph node kind and backing identity must not be blank")
    return _stable_id("sgnode", kind.strip(), backing_identity.strip(), discriminator.strip())


def include_occurrence_anchor(
    parent_instance_id: FrameworkInstanceId,
    included_router_instance_id: FrameworkInstanceId,
    prefix: str | None,
    same_shape_ordinal: int,
) -> str:
    """Return a transient, line-independent key for one router-include occurrence."""

    if same_shape_ordinal < 0:
        raise ValueError("include same-shape ordinal must not be negative")
    normalized_prefix = "<UNKNOWN>" if prefix is None else prefix.strip()
    return _stable_id(
        "sginclude",
        parent_instance_id,
        included_router_instance_id,
        normalized_prefix,
        same_shape_ordinal,
    )


def route_registration_id(
    *,
    selected_app_instance_id: FrameworkInstanceId,
    include_anchors: Sequence[str],
    registrar_instance_id: FrameworkInstanceId,
    owner_symbol_id: SymbolId,
    method: str,
    route_path: str,
    same_shape_ordinal: int,
) -> RouteRegistrationId:
    """Identify one effective route registration without persisting include IDs."""

    if same_shape_ordinal < 0:
        raise ValueError("route same-shape ordinal must not be negative")
    if not method.strip() or not route_path.strip():
        raise ValueError("route method and path must not be blank")
    return _stable_id(
        "sgroute",
        selected_app_instance_id,
        *include_anchors,
        registrar_instance_id,
        owner_symbol_id,
        method.strip().upper(),
        route_path.strip(),
        same_shape_ordinal,
    )


def structural_anchor(*components: object) -> str:
    """Return a confidentiality-safe identity anchor for a bounded AST fact."""

    if not components:
        raise ValueError("structural anchor requires at least one component")
    return _stable_id("sganchor", *components)


def merchant_state_carrier_id(
    source_file_id: SourceFileId, binding_name: str
) -> MerchantStateCarrierId:
    """Hash a bounded module-state binding without persisting its source spelling."""

    if not binding_name.strip():
        raise ValueError("merchant-state carrier binding must not be blank")
    return _stable_id("sgcarrier", source_file_id, binding_name.strip())


def graph_edge_id(
    kind: str,
    source_node_id: GraphNodeId,
    target_node_id: GraphNodeId,
    duplicate_ordinal: int = 0,
    discriminator: str = "",
) -> GraphEdgeId:
    if duplicate_ordinal < 0:
        raise ValueError("duplicate ordinal must not be negative")
    if not kind.strip():
        raise ValueError("graph edge kind must not be blank")
    return _stable_id(
        "sgedge",
        kind.strip(),
        source_node_id,
        target_node_id,
        duplicate_ordinal,
        discriminator.strip(),
    )


def normal_control_id(*components: object) -> NormalControlId:
    """Identify one exact ingress/path/customer-value positive control."""

    if not components:
        raise ValueError("normal-control identity requires evidence components")
    return _stable_id("sgcontrol", *components)


def scenario_instance_id(scenario_id: str, *components: object) -> ScenarioInstanceId:
    if not scenario_id.strip():
        raise ValueError("scenario identity requires a scenario ID")
    return _stable_id("sgscenario", scenario_id.strip(), *components)


def assertion_id(instance_id: ScenarioInstanceId, assertion_key: str) -> AssertionId:
    if not assertion_key.strip():
        raise ValueError("assertion identity requires an assertion key")
    return _stable_id("sgassert", instance_id, assertion_key.strip())


def new_scenario_execution_id() -> ScenarioExecutionId:
    return f"sgexec_{uuid.uuid4().hex}"


def new_verification_run_id() -> VerificationRunId:
    return f"sgvrun_{uuid.uuid4().hex}"


def verification_check_id(
    run_id: VerificationRunId,
    instance_id: ScenarioInstanceId,
    assertion: AssertionId,
) -> VerificationCheckId:
    return _stable_id("sgcheck", run_id, instance_id, assertion)


def verification_check_key(*components: object) -> VerificationCheckKey:
    """Identify one logical invariant without volatile execution authority."""

    if not components:
        raise ValueError("verification-check identity requires logical components")
    return _stable_id("sgcheckkey", *components)


def finding_key(check_key: VerificationCheckKey) -> FindingKey:
    return _stable_id("sgfindingkey", check_key)


def finding_occurrence_id(
    run_id: VerificationRunId,
    check_id: VerificationCheckId,
) -> FindingOccurrenceId:
    return _stable_id("sgfinding", run_id, check_id)


def new_runtime_session_id() -> RuntimeSessionId:
    return f"sgrun_{uuid.uuid4().hex}"


def runtime_request_id(session_id: RuntimeSessionId, ordinal: int) -> RuntimeRequestId:
    if ordinal < 0:
        raise ValueError("runtime request ordinal must not be negative")
    return _stable_id("sgreq", session_id, ordinal)
