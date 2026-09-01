import razorpay
from fastapi import FastAPI, Request

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))
orders = {}


@app.post("/webhook")
async def payment_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    payload = await request.json()
    if payload["event"] == "payment.captured":
        orders[payload["id"]] = "fulfilled"
    return {"ok": True}
