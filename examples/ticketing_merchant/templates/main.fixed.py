"""Corrected ticketing merchant for sequential duplicate and modeled retry proof."""

from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import FastAPI, HTTPException, Request

from .domain import bind_attendee_roster_row, mint_admission_pass
from .storage import claim_webhook_event

app = FastAPI(title="StateGuard Ticketing Merchant")

processed_event_ids: set[str] = set()
merchant_payment_state = {"status": "created"}
merchant_orders = {
    "demo-booking": {
        "razorpay_order_id": os.environ["MERCHANT_SERVER_ORDER_ID"],
        "payment_status": "created",
    }
}


@app.post("/webhooks/razorpay")
async def razorpay_webhook(request: Request) -> dict[str, bool | str]:
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    if not hmac.compare_digest(
        hmac.new(
            os.environ["MERCHANT_WEBHOOK_SECRET"].encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest(),
        signature,
    ):
        raise HTTPException(status_code=400, detail="invalid webhook signature")

    payload = await request.json()
    event = payload["event"]
    payment_id = payload["payload"]["payment"]["entity"]["id"]
    if event_id in processed_event_ids:
        return {"accepted": True, "duplicate": True}
    if not claim_webhook_event(event_id):
        processed_event_ids.add(event_id)
        return {"accepted": True, "duplicate": True}
    processed_event_ids.add(event_id)

    if event == "payment.captured":
        merchant_payment_state["status"] = "captured"
        bind_attendee_roster_row(payment_id)
        mint_admission_pass(payment_id)
        return {"accepted": True, "state": "captured"}
    return {"accepted": True, "state": "ignored"}


@app.post("/checkout/complete")
async def checkout_complete(request: Request) -> dict[str, bool | str]:
    payload = await request.json()
    payment_id = payload["razorpay_payment_id"]
    browser_order_id = payload["razorpay_order_id"]
    signature = payload["razorpay_signature"]
    server_order_id = merchant_orders["demo-booking"]["razorpay_order_id"]
    if browser_order_id != server_order_id:
        raise HTTPException(status_code=400, detail="unexpected order identity")
    if not hmac.compare_digest(
        hmac.new(
            os.environ["MERCHANT_CHECKOUT_SECRET"].encode("utf-8"),
            f"{server_order_id}|{payment_id}".encode(),
            hashlib.sha256,
        ).hexdigest(),
        signature,
    ):
        raise HTTPException(status_code=400, detail="invalid Checkout signature")

    merchant_orders["demo-booking"]["payment_status"] = "captured"
    mint_admission_pass(payment_id)
    return {"accepted": True, "state": "captured"}
