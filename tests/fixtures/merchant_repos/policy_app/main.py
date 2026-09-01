import razorpay
from domain import grant_ticket
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))
orders = {"merchant-order": {"status": "pending"}}


@app.post("/webhooks/captured")
async def captured_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    payload = await request.json()
    if payload["event"] == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
        grant_ticket(payload["payload"]["payment"]["entity"]["id"])
        return {"event_id": event_id, "processed": True}
    return {"event_id": event_id}


@app.post("/webhooks/authorized")
async def authorized_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razpay-event-id"]
    client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    payload = await request.json()
    if payload["event"] == "payment.authorized":
        orders["merchant-order"]["status"] = "authorized"
        grant_ticket(payload["payload"]["payment"]["entity"]["id"])
        return {"event_id": event_id, "processed": True}
    return {"event_id": event_id}


@app.post("/checkout/callback")
async def checkout_callback(request: Request):
    payload = await request.json()
    payment_id = payload["razorpay_payment_id"]
    server_order_id = "merchant-order"
    client.utility.verify_payment_signature(
        {
            "razorpay_payment_id": payment_id,
            "razorpay_order_id": server_order_id,
            "razorpay_signature": payload["razorpay_signature"],
        }
    )
    grant_ticket(payment_id)
    return {"ok": True}
