import razorpay
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("test-key", "test-secret"))
orders = {"merchant-order": {"status": "pending"}}
audit = {"last_event": None}


@app.post("/webhooks/payment")
async def payment_webhook(request: Request):
    correlation_visible = "x-stateguard-request-id" in request.headers
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    client.utility.verify_webhook_signature(raw_body, signature, "test-webhook-secret")
    payload = await request.json()
    if payload["event"] == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
        audit["last_event"] = "payment.captured"
        return {"processed": True, "correlation_visible": correlation_visible}
    return {"processed": False, "correlation_visible": correlation_visible}
