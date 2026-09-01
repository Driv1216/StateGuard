"""Explicitly opted-in, fetch-only smoke against a user-supplied Test Mode Payment."""

from __future__ import annotations

import os

import pytest

from stateguard.contracts.identity import new_verification_run_id
from stateguard.grounding.contracts import (
    RazorpayGroundingStatus,
    RazorpayTestGroundingRequest,
)
from stateguard.grounding.razorpay import acquire_razorpay_test_grounding


@pytest.mark.skipif(
    os.environ.get("STATEGUARD_RAZORPAY_TEST_SMOKE") != "1"
    or not all(
        os.environ.get(name)
        for name in ("RAZORPAY_KEY_ID", "RAZORPAY_KEY_SECRET", "RAZORPAY_PAYMENT_ID")
    ),
    reason="fetch-only Razorpay Test Mode smoke was not explicitly configured",
)
def test_fetch_only_captured_payment_and_linked_order_smoke() -> None:
    result = acquire_razorpay_test_grounding(
        RazorpayTestGroundingRequest(payment_id_env="RAZORPAY_PAYMENT_ID"),
        new_verification_run_id(),
    )
    assert result.snapshot.status == RazorpayGroundingStatus.GROUNDED
    assert result.profile is not None
