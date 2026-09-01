import os

import razorpay
from domain import grant_ticket
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
client = razorpay.Client(auth=("test-key", "test-secret"))
delivery_counts = {}


@app.post("/webhooks/payment")
async def payment_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    client.utility.verify_webhook_signature(
        raw_body,
        signature,
        os.environ["MERCHANT_WEBHOOK_SECRET"],
    )
    payload = await request.json()
    if payload["event"] == "payment.captured":
        sg02_behavior = os.environ.get("SG02_BEHAVIOR")
        if sg02_behavior:
            event_id = request.headers["x-razorpay-event-id"]
            delivery = delivery_counts.get(event_id, 0) + 1
            delivery_counts[event_id] = delivery
            if sg02_behavior == "zero":
                repeat = 0
            elif sg02_behavior == "fail":
                repeat = 1
            elif sg02_behavior == "first_multiple":
                repeat = 2 if delivery == 1 else 0
            else:
                repeat = 1 if delivery == 1 else 0
        else:
            behavior = os.environ.get("SG01_BEHAVIOR", "pass")
            repeat = 2 if behavior == "multiple" else 1
            should_enter = behavior != "zero" or bool(payload.get("merchant_ready"))
            repeat = repeat if should_enter else 0
        for _ in range(repeat):
            await grant_ticket(payload["payload"]["payment"]["entity"]["id"])
        if sg02_behavior == "second_500" and delivery == 2:
            return JSONResponse({"accepted": False}, status_code=500)
        return {"accepted": True}
    return {"accepted": False}
