import os

import razorpay
from domain import grant_ticket
from domain import grant_ticket as grant_ticket_for_authorized
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
client = razorpay.Client(auth=("test-key", os.environ["MERCHANT_CHECKOUT_SECRET"]))
merchant_state = {"status": "pending"}
sg03_captured_deliveries = 0


@app.post("/webhooks/payment")
async def payment_webhook(request: Request):
    global sg03_captured_deliveries

    if (
        request.headers.get("x-stateguard-acknowledgement-failure") is not None
        or request.headers.get("x-stateguard-request-id") is not None
    ):
        return JSONResponse({"accepted": False}, status_code=418)
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    client.utility.verify_webhook_signature(
        raw_body,
        signature,
        os.environ["MERCHANT_WEBHOOK_SECRET"],
    )
    payload = await request.json()
    payment_id = payload["payload"]["payment"]["entity"]["id"]
    if payload["event"] == "payment.captured":
        merchant_state["status"] = "captured"
        sg03_behavior = os.environ.get("SG03_BEHAVIOR")
        if sg03_behavior is not None:
            sg03_captured_deliveries += 1
            if sg03_behavior == "pass":
                repeat = 1 if sg03_captured_deliveries == 1 else 0
            elif sg03_behavior == "initial_multiple":
                repeat = 2 if sg03_captured_deliveries == 1 else 0
            elif sg03_behavior == "retry_entry":
                repeat = 1
            else:
                repeat = 0
        else:
            behavior = os.environ.get("WEBHOOK_CAPTURE_BEHAVIOR", "once")
            repeat = 2 if behavior == "multiple" else 1
            repeat = 0 if behavior == "zero" else repeat
        for _ in range(repeat):
            await grant_ticket(payment_id)
        return {"accepted": True}
    if payload["event"] == "payment.authorized":
        if os.environ.get("SG04_STATE_BEHAVIOR", "safe") == "regress":
            merchant_state["status"] = "authorized"
        if os.environ.get("SG04_CUSTOMER_BEHAVIOR", "safe") == "duplicate":
            await grant_ticket_for_authorized(payment_id)
        sg08_behavior = os.environ.get("SG08_AUTHORIZED_BEHAVIOR", "zero")
        sg08_repeat = 2 if sg08_behavior == "multiple" else 1
        sg08_repeat = 0 if sg08_behavior == "zero" else sg08_repeat
        for _ in range(sg08_repeat):
            await grant_ticket_for_authorized(payment_id)
        return {"accepted": True}
    return JSONResponse({"accepted": False}, status_code=400)


@app.post("/checkout/callback")
async def checkout_callback(request: Request):
    payload = await request.json()
    payment_id = payload["razorpay_payment_id"]
    browser_order_id = payload["razorpay_order_id"]
    server_order_id = os.environ["MERCHANT_SERVER_ORDER_ID"]
    order_for_verification = server_order_id
    if os.environ.get("SG06_BEHAVIOR", "safe") == "vulnerable":
        order_for_verification = browser_order_id
    try:
        client.utility.verify_payment_signature(
            {
                "razorpay_payment_id": payment_id,
                "razorpay_order_id": order_for_verification,
                "razorpay_signature": payload["razorpay_signature"],
            }
        )
    except ValueError:
        return JSONResponse({"accepted": False}, status_code=400)
    merchant_state["status"] = "captured"
    await grant_ticket(payment_id)
    return {"accepted": True}
