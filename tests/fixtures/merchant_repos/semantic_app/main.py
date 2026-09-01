import razorpay
from domain import grant_ticket, unused_imported_helper
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))
IMPORTED_BUT_UNREACHED = unused_imported_helper


@app.post("/webhook")
async def payment_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    payload = await request.json()
    if payload["event"] == "payment.captured":
        grant_ticket(payload["payload"]["payment"]["entity"]["id"])
    return {"ok": True}
