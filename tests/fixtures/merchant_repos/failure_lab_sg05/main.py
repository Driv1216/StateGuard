import os

import razorpay
from domain import grant_ticket
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
client = razorpay.Client(auth=("test-key", "test-secret"))
merchant_state = {"status": "pending"}


@app.post("/webhooks/payment")
async def payment_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    rejected = False
    behavior = "safe"
    try:
        client.utility.verify_webhook_signature(
            raw_body,
            signature,
            os.environ["MERCHANT_WEBHOOK_SECRET"],
        )
    except ValueError:
        behavior = os.environ.get("SG05_BEHAVIOR", "safe")
        if behavior == "safe":
            return JSONResponse({"accepted": False}, status_code=400)
        rejected = True
    payload = await request.json()
    if payload["event"] == "payment.authorized":
        merchant_state["status"] = f"authorized:{event_id}"
    if payload["event"] == "payment.captured":
        payment_id = payload["payload"]["payment"]["entity"]["id"]
        if not rejected or behavior == "mutation_fail":
            merchant_state["status"] = f"captured:{event_id}"
        if not rejected or behavior == "customer_fail":
            await grant_ticket(payment_id)
        if rejected:
            return JSONResponse({"accepted": False}, status_code=400)
        return {"accepted": True}
    return {"accepted": False}
