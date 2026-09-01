"""SG-06 local Checkout tamper construction and deterministic reductions."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlencode

from stateguard.contracts.common import ScenarioExecutionId
from stateguard.contracts.identity import canonical_json, fingerprint_json, sha256_digest
from stateguard.graph.contracts import CheckoutRequestBinding, CheckoutRequestTransport
from stateguard.rules.razorpay import RazorpayProtocolRuleId, razorpay_rule_fingerprint

from .contracts import (
    CheckoutRequestInputReference,
    CheckoutSequenceInputReference,
    CustomerTargetObservationSummary,
    EvidenceTier,
    MutationScenarioRequestObservation,
    ScenarioResultReasonCode,
    VerificationResultState,
)
from .sg01 import evaluate_observations as evaluate_normal_control

SG06_DEFINITION_FINGERPRINT = fingerprint_json(
    {
        "scenario": "SG-06",
        "definition_version": 1,
        "sequence": "tampered Checkout callback then valid server-order control",
        "invariant": "tampered callback creates no protected merchant effect",
        "rules": (
            razorpay_rule_fingerprint(
                RazorpayProtocolRuleId.CHECKOUT_SERVER_SIGNATURE_VERIFICATION
            ),
            razorpay_rule_fingerprint(RazorpayProtocolRuleId.CHECKOUT_SERVER_ORDER_ID),
        ),
    }
)


@dataclass(frozen=True, repr=False)
class PreparedCheckoutRequest:
    headers: dict[str, str]
    content: bytes | None
    params: dict[str, str] | None

    def __repr__(self) -> str:
        return "PreparedCheckoutRequest(<redacted request material>)"


@dataclass(frozen=True, repr=False)
class PreparedSG06Requests:
    tampered: PreparedCheckoutRequest
    valid: PreparedCheckoutRequest
    input_reference: CheckoutSequenceInputReference

    def __repr__(self) -> str:
        return "PreparedSG06Requests(<redacted request material>)"


def _signature(order_id: str, payment_id: str, secret: str) -> str:
    message = f"{order_id}|{payment_id}".encode()
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _render(
    binding: CheckoutRequestBinding,
    values: Mapping[str, str],
) -> tuple[PreparedCheckoutRequest, str]:
    aliases: dict[str, str] = {item.canonical_name: item.request_name for item in binding.fields}
    payload = {aliases[name]: value for name, value in values.items()}
    if binding.transport == CheckoutRequestTransport.JSON:
        content = canonical_json(payload).encode("utf-8")
        return (
            PreparedCheckoutRequest(
                headers={"Content-Type": "application/json"},
                content=content,
                params=None,
            ),
            sha256_digest(content),
        )
    if binding.transport == CheckoutRequestTransport.FORM_URLENCODED:
        content = urlencode(payload).encode("ascii")
        return (
            PreparedCheckoutRequest(
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                content=content,
                params=None,
            ),
            sha256_digest(content),
        )
    return (
        PreparedCheckoutRequest(headers={}, content=None, params=payload),
        fingerprint_json(payload),
    )


def prepare_sg06_requests(
    *,
    execution_id: ScenarioExecutionId,
    path: str,
    binding: CheckoutRequestBinding,
    secret: str,
    server_order_id: str,
) -> PreparedSG06Requests:
    suffix = hashlib.sha256(execution_id.encode("ascii")).hexdigest()[:20]
    payment_id = f"pay_{suffix}"
    attacker_order_id = f"order_stateguard_{suffix}"
    if attacker_order_id == server_order_id:
        attacker_order_id = f"order_stateguard_x{suffix}"
    tampered_values = {
        "razorpay_payment_id": payment_id,
        "razorpay_order_id": attacker_order_id,
        "razorpay_signature": _signature(attacker_order_id, payment_id, secret),
    }
    valid_values = {
        "razorpay_payment_id": payment_id,
        "razorpay_order_id": server_order_id,
        "razorpay_signature": _signature(server_order_id, payment_id, secret),
    }
    tampered, tampered_fp = _render(binding, tampered_values)
    valid, valid_fp = _render(binding, valid_values)
    context_fp = fingerprint_json(
        {
            "payment_id": payment_id,
            "server_order_id_fingerprint": sha256_digest(server_order_id.encode("utf-8")),
        }
    )
    reference = CheckoutSequenceInputReference(
        transport=binding.transport.value,
        path=path,
        payment_context_fingerprint=context_fp,
        requests=(
            CheckoutRequestInputReference(
                role="TAMPERED", request_material_fingerprint=tampered_fp
            ),
            CheckoutRequestInputReference(
                role="VALID_CONTROL", request_material_fingerprint=valid_fp
            ),
        ),
    )
    return PreparedSG06Requests(tampered=tampered, valid=valid, input_reference=reference)


def evaluate_customer_sequence(
    tampered: CustomerTargetObservationSummary,
    control: CustomerTargetObservationSummary,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    if len(tampered.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if tampered.entered_count > 0:
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.TAMPERED_CALLBACK_ADDED_CUSTOMER_TARGET_ENTRY,
        )
    if tampered.returned_normally_count or tampered.exception_escaped_count:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.TARGET_TERMINAL_UNPROVEN,
        )
    if len(tampered.response_completed_sequences) != 1 or tampered.request_aborted_sequences:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if evaluate_normal_control(control)[0] != VerificationResultState.VERIFIED_PASS:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.VALID_CHECKOUT_CONTROL_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.TAMPERED_CALLBACK_ADDED_NO_CUSTOMER_TARGET_ENTRY,
    )


def evaluate_mutation_sequence(
    tampered: MutationScenarioRequestObservation,
    control: MutationScenarioRequestObservation,
) -> tuple[VerificationResultState, EvidenceTier | None, ScenarioResultReasonCode]:
    if tuple(item.mutation_node_id for item in tampered.mutation_targets) != tuple(
        item.mutation_node_id for item in control.mutation_targets
    ):
        return VerificationResultState.UNVERIFIED, None, ScenarioResultReasonCode.AUTHORITY_MISMATCH
    if len(tampered.request_received_sequences) != 1:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    if any(item.completed_normally_count for item in tampered.mutation_targets):
        return (
            VerificationResultState.VERIFIED_FAIL,
            EvidenceTier.E3_DYNAMIC_VERIFIED,
            ScenarioResultReasonCode.TAMPERED_CALLBACK_COMPLETED_MUTATION,
        )
    if any(item.reached_count or item.raised_count for item in tampered.mutation_targets):
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.MUTATION_OUTCOME_UNPROVEN,
        )
    if len(tampered.response_completed_sequences) != 1 or tampered.request_aborted_sequences:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.REQUEST_LIFECYCLE_UNPROVEN,
        )
    control_normal = bool(
        len(control.request_received_sequences) == 1
        and len(control.response_completed_sequences) == 1
        and not control.request_aborted_sequences
        and control.http_status_code is not None
        and 200 <= control.http_status_code < 300
        and all(
            item.reached_count >= 1
            and item.completed_normally_count == item.reached_count
            and item.raised_count == 0
            for item in control.mutation_targets
        )
    )
    if not control_normal:
        return (
            VerificationResultState.UNVERIFIED,
            None,
            ScenarioResultReasonCode.VALID_CHECKOUT_CONTROL_UNPROVEN,
        )
    return (
        VerificationResultState.VERIFIED_PASS,
        EvidenceTier.E3_DYNAMIC_VERIFIED,
        ScenarioResultReasonCode.TAMPERED_CALLBACK_ADDED_NO_MUTATION,
    )
