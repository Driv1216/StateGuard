from __future__ import annotations

from stateguard.graph.razorpay_recognizers import (
    RAZORPAY_SDK_RECOGNIZERS,
    RazorpaySdkRecognizerId,
)
from stateguard.rules.razorpay import RAZORPAY_PROTOCOL_FACTS, RazorpayProtocolRuleId


def test_protocol_facts_and_sdk_behavior_are_separate_versioned_catalogs() -> None:
    assert {item.rule_id for item in RAZORPAY_PROTOCOL_FACTS} == set(RazorpayProtocolRuleId)
    assert {item.recognizer_id for item in RAZORPAY_SDK_RECOGNIZERS} == set(RazorpaySdkRecognizerId)
    assert all(
        item.source_url.startswith("https://razorpay.com/docs/") for item in RAZORPAY_PROTOCOL_FACTS
    )
    assert all(item.recognizer_ids for item in RAZORPAY_PROTOCOL_FACTS)
    assert all("razorpay-python" in item.source_url for item in RAZORPAY_SDK_RECOGNIZERS)
