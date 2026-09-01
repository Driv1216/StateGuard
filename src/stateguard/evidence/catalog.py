"""Versioned product definitions for normalized Failure Lab assertions."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from stateguard.applicability.contracts import (
    SG01_ASSERTION_KEY,
    SG02_ASSERTION_KEY,
    SG03_ASSERTION_KEY,
    SG04_CUSTOMER_VALUE_ASSERTION_KEY,
    SG04_STATE_REGRESSION_ASSERTION_KEY,
    SG05_CUSTOMER_VALUE_ASSERTION_KEY,
    SG05_MUTATION_ASSERTION_KEY,
    SG06_CUSTOMER_VALUE_ASSERTION_KEY,
    SG06_MUTATION_ASSERTION_KEY,
    SG07_CUSTOMER_VALUE_ASSERTION_KEY,
    SG08_CAPTURE_ASSERTION_KEY,
    SG08_LATE_POLICY_ASSERTION_KEY,
    SG08_PRECAPTURE_ASSERTION_KEY,
    ScenarioId,
)
from stateguard.contracts.common import PersistedArtifactModel
from stateguard.rules.razorpay import RazorpayProtocolRuleId


class RequestRole(StrEnum):
    NORMAL_CAPTURE = "NORMAL_CAPTURE"
    INITIAL_DELIVERY = "INITIAL_DELIVERY"
    DUPLICATE_DELIVERY = "DUPLICATE_DELIVERY"
    INITIAL_WITH_ACK_FAILURE = "INITIAL_WITH_ACK_FAILURE"
    MODELED_RETRY = "MODELED_RETRY"
    CAPTURED_CONTROL = "CAPTURED_CONTROL"
    STALE_AUTHORIZED = "STALE_AUTHORIZED"
    REJECTED_SIGNATURE = "REJECTED_SIGNATURE"
    VALID_SIGNATURE_CONTROL = "VALID_SIGNATURE_CONTROL"
    TAMPERED_CALLBACK = "TAMPERED_CALLBACK"
    VALID_CALLBACK_CONTROL = "VALID_CALLBACK_CONTROL"
    WEBHOOK_WITH_CALLBACK_OMITTED = "WEBHOOK_WITH_CALLBACK_OMITTED"
    MODELED_LATE_AUTHORIZED = "MODELED_LATE_AUTHORIZED"
    CAPTURED_THRESHOLD_CONTROL = "CAPTURED_THRESHOLD_CONTROL"


class PolicyDimension(StrEnum):
    FULFILMENT = "FULFILMENT"
    LATE_AUTHORISATION = "LATE_AUTHORISATION"


class AssertionDefinition(PersistedArtifactModel):
    scenario_id: ScenarioId
    assertion_key: str = Field(min_length=1, max_length=128)
    invariant_id: str = Field(min_length=1, max_length=128)
    invariant_version: int = Field(ge=1)
    expected_invariant: str = Field(min_length=1, max_length=512)
    request_roles: tuple[RequestRole, ...] = ()
    policy_authority: tuple[PolicyDimension, ...] = ()
    key_policy_dimensions: tuple[PolicyDimension, ...] = ()
    razorpay_rule_ids: tuple[RazorpayProtocolRuleId, ...]

    @model_validator(mode="after")
    def validate_policy_dimensions(self) -> AssertionDefinition:
        if not set(self.key_policy_dimensions) <= set(self.policy_authority):
            raise ValueError("check-key policy dimensions must be used assertion authority")
        if len(set(self.razorpay_rule_ids)) != len(self.razorpay_rule_ids):
            raise ValueError("assertion rule references must be unique")
        return self


_CAPTURE_RULES = (
    RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT,
    RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY,
)


ASSERTION_DEFINITIONS = (
    AssertionDefinition(
        scenario_id=ScenarioId.SG_01,
        assertion_key=SG01_ASSERTION_KEY,
        invariant_id="NORMAL_CAPTURE_VALUE_EXACTLY_ONCE",
        invariant_version=1,
        expected_invariant=(
            "A normal captured payment enters and normally returns from the exact "
            "customer-value target once."
        ),
        request_roles=(RequestRole.NORMAL_CAPTURE,),
        policy_authority=(PolicyDimension.FULFILMENT,),
        key_policy_dimensions=(PolicyDimension.FULFILMENT,),
        razorpay_rule_ids=_CAPTURE_RULES,
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_02,
        assertion_key=SG02_ASSERTION_KEY,
        invariant_id="DUPLICATE_DELIVERY_VALUE_AT_MOST_ONCE",
        invariant_version=1,
        expected_invariant=(
            "A duplicate captured webhook adds no customer-value target entry after a "
            "normal first delivery."
        ),
        request_roles=(RequestRole.INITIAL_DELIVERY, RequestRole.DUPLICATE_DELIVERY),
        policy_authority=(PolicyDimension.FULFILMENT,),
        razorpay_rule_ids=(*_CAPTURE_RULES, RazorpayProtocolRuleId.WEBHOOK_DUPLICATE_DELIVERY),
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_03,
        assertion_key=SG03_ASSERTION_KEY,
        invariant_id="MODELED_RETRY_VALUE_AT_MOST_ONCE",
        invariant_version=1,
        expected_invariant=(
            "A modeled retry after an injected unsuccessful acknowledgement adds no "
            "customer-value target entry."
        ),
        request_roles=(RequestRole.INITIAL_WITH_ACK_FAILURE, RequestRole.MODELED_RETRY),
        policy_authority=(PolicyDimension.FULFILMENT,),
        razorpay_rule_ids=(
            *_CAPTURE_RULES,
            RazorpayProtocolRuleId.WEBHOOK_RETRY_ON_UNSUCCESSFUL_ACK,
        ),
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_04,
        assertion_key=SG04_CUSTOMER_VALUE_ASSERTION_KEY,
        invariant_id="OUT_OF_ORDER_VALUE_AT_MOST_ONCE",
        invariant_version=1,
        expected_invariant=(
            "A stale authorized event after capture adds no customer-value target entry."
        ),
        request_roles=(RequestRole.CAPTURED_CONTROL, RequestRole.STALE_AUTHORIZED),
        policy_authority=(PolicyDimension.FULFILMENT,),
        razorpay_rule_ids=(
            RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT,
            RazorpayProtocolRuleId.WEBHOOK_ORDER_NOT_GUARANTEED,
            RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY,
        ),
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_04,
        assertion_key=SG04_STATE_REGRESSION_ASSERTION_KEY,
        invariant_id="MERCHANT_STATE_DOES_NOT_REGRESS",
        invariant_version=1,
        expected_invariant=(
            "The exact observed merchant assignment does not complete a "
            "captured-to-authorized regression."
        ),
        request_roles=(RequestRole.CAPTURED_CONTROL, RequestRole.STALE_AUTHORIZED),
        razorpay_rule_ids=(
            RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT,
            RazorpayProtocolRuleId.WEBHOOK_ORDER_NOT_GUARANTEED,
            RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY,
        ),
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_05,
        assertion_key=SG05_MUTATION_ASSERTION_KEY,
        invariant_id="FORGED_WEBHOOK_NO_MUTATION_COMPLETION",
        invariant_version=1,
        expected_invariant=(
            "A forged webhook completes no exact Python merchant-assignment instruction."
        ),
        request_roles=(RequestRole.REJECTED_SIGNATURE, RequestRole.VALID_SIGNATURE_CONTROL),
        razorpay_rule_ids=_CAPTURE_RULES,
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_05,
        assertion_key=SG05_CUSTOMER_VALUE_ASSERTION_KEY,
        invariant_id="FORGED_WEBHOOK_NO_CUSTOMER_VALUE",
        invariant_version=1,
        expected_invariant="A forged webhook does not enter the exact customer-value target.",
        request_roles=(RequestRole.REJECTED_SIGNATURE, RequestRole.VALID_SIGNATURE_CONTROL),
        razorpay_rule_ids=_CAPTURE_RULES,
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_06,
        assertion_key=SG06_MUTATION_ASSERTION_KEY,
        invariant_id="TAMPERED_CHECKOUT_NO_MUTATION_COMPLETION",
        invariant_version=1,
        expected_invariant=(
            "A tampered Checkout callback completes no exact protected Python assignment "
            "instruction."
        ),
        request_roles=(RequestRole.TAMPERED_CALLBACK, RequestRole.VALID_CALLBACK_CONTROL),
        razorpay_rule_ids=(
            RazorpayProtocolRuleId.CHECKOUT_SERVER_SIGNATURE_VERIFICATION,
            RazorpayProtocolRuleId.CHECKOUT_SERVER_ORDER_ID,
        ),
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_06,
        assertion_key=SG06_CUSTOMER_VALUE_ASSERTION_KEY,
        invariant_id="TAMPERED_CHECKOUT_NO_CUSTOMER_VALUE",
        invariant_version=1,
        expected_invariant=(
            "A tampered Checkout callback does not enter the exact customer-value target."
        ),
        request_roles=(RequestRole.TAMPERED_CALLBACK, RequestRole.VALID_CALLBACK_CONTROL),
        razorpay_rule_ids=(
            RazorpayProtocolRuleId.CHECKOUT_SERVER_SIGNATURE_VERIFICATION,
            RazorpayProtocolRuleId.CHECKOUT_SERVER_ORDER_ID,
        ),
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_07,
        assertion_key=SG07_CUSTOMER_VALUE_ASSERTION_KEY,
        invariant_id="WEBHOOK_OUTCOME_WITHOUT_CALLBACK",
        invariant_version=1,
        expected_invariant=(
            "The captured webhook reaches the exact customer-value target once without a "
            "browser callback."
        ),
        request_roles=(RequestRole.WEBHOOK_WITH_CALLBACK_OMITTED,),
        policy_authority=(PolicyDimension.FULFILMENT,),
        razorpay_rule_ids=_CAPTURE_RULES,
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_08,
        assertion_key=SG08_PRECAPTURE_ASSERTION_KEY,
        invariant_id="LATE_AUTHORIZATION_NO_PRECAPTURE_VALUE",
        invariant_version=1,
        expected_invariant=(
            "Under capture-required policy, modeled late authorization does not enter the "
            "customer-value target before capture."
        ),
        request_roles=(RequestRole.MODELED_LATE_AUTHORIZED, RequestRole.CAPTURED_THRESHOLD_CONTROL),
        policy_authority=(PolicyDimension.FULFILMENT, PolicyDimension.LATE_AUTHORISATION),
        key_policy_dimensions=(PolicyDimension.FULFILMENT, PolicyDimension.LATE_AUTHORISATION),
        razorpay_rule_ids=(
            RazorpayProtocolRuleId.PAYMENT_AUTHORIZED_WEBHOOK_EVENT,
            RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT,
            RazorpayProtocolRuleId.LATE_AUTHORISATION_BUSINESS_POLICY,
            RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY,
        ),
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_08,
        assertion_key=SG08_CAPTURE_ASSERTION_KEY,
        invariant_id="LATE_PAYMENT_VALUE_ONCE_AFTER_CAPTURE",
        invariant_version=1,
        expected_invariant=(
            "Under fulfil-later capture policy, the capture threshold enters the "
            "customer-value target once."
        ),
        request_roles=(RequestRole.MODELED_LATE_AUTHORIZED, RequestRole.CAPTURED_THRESHOLD_CONTROL),
        policy_authority=(PolicyDimension.FULFILMENT, PolicyDimension.LATE_AUTHORISATION),
        key_policy_dimensions=(PolicyDimension.FULFILMENT, PolicyDimension.LATE_AUTHORISATION),
        razorpay_rule_ids=(
            RazorpayProtocolRuleId.PAYMENT_AUTHORIZED_WEBHOOK_EVENT,
            RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT,
            RazorpayProtocolRuleId.LATE_AUTHORISATION_BUSINESS_POLICY,
            RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY,
        ),
    ),
    AssertionDefinition(
        scenario_id=ScenarioId.SG_08,
        assertion_key=SG08_LATE_POLICY_ASSERTION_KEY,
        invariant_id="LATE_PAYMENT_POLICY_OUTCOME",
        invariant_version=1,
        expected_invariant=(
            "The late-payment outcome is re-verifiable only with current merchant "
            "late-policy context."
        ),
        request_roles=(RequestRole.MODELED_LATE_AUTHORIZED,),
        policy_authority=(PolicyDimension.FULFILMENT, PolicyDimension.LATE_AUTHORISATION),
        key_policy_dimensions=(PolicyDimension.FULFILMENT, PolicyDimension.LATE_AUTHORISATION),
        razorpay_rule_ids=(
            RazorpayProtocolRuleId.PAYMENT_AUTHORIZED_WEBHOOK_EVENT,
            RazorpayProtocolRuleId.PAYMENT_CAPTURED_WEBHOOK_EVENT,
            RazorpayProtocolRuleId.LATE_AUTHORISATION_BUSINESS_POLICY,
            RazorpayProtocolRuleId.WEBHOOK_SIGNATURE_RAW_BODY,
        ),
    ),
)

ASSERTION_DEFINITION_BY_KEY = {
    (item.scenario_id, item.assertion_key): item for item in ASSERTION_DEFINITIONS
}

if len(ASSERTION_DEFINITION_BY_KEY) != len(ASSERTION_DEFINITIONS):
    raise RuntimeError("assertion-definition catalog contains duplicate identities")


def assertion_definition(scenario_id: ScenarioId, assertion_key: str) -> AssertionDefinition:
    try:
        return ASSERTION_DEFINITION_BY_KEY[(scenario_id, assertion_key)]
    except KeyError as exc:
        raise ValueError("unknown Failure Lab assertion definition") from exc


def assertion_order(scenario_id: ScenarioId, assertion_key: str) -> int:
    matching = tuple(item for item in ASSERTION_DEFINITIONS if item.scenario_id == scenario_id)
    return next(index for index, item in enumerate(matching) if item.assertion_key == assertion_key)
