import razorpay
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from helpers import apply_verified_event

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))
processed_event_ids = set()
orders = {"merchant-order": {"status": "pending"}}
metrics = {"requests": 0}


@app.post("/webhooks/correct")
async def correct_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    payload = await request.json()
    event = payload["event"]
    if event_id in processed_event_ids:
        return JSONResponse({"duplicate": True}, status_code=200)
    processed_event_ids.add(event_id)
    if event == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
    elif event == "payment.failed":
        orders["merchant-order"]["status"] = "failed"
    return JSONResponse({"ok": True}, status_code=202)


@app.post("/webhooks/late", status_code=201)
async def late_signature_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    payload = await request.json()
    event = payload["event"]
    if event == "payment.authorized":
        orders["merchant-order"]["status"] = "authorized"
    client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    return {"ok": True}


@app.post("/webhooks/event-observed")
async def event_observed_webhook(request: Request):
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    event = payload["event"]
    if event == "order.paid":
        metrics["requests"] += 1
    return {"event_id": event_id}


@app.post("/webhooks/parsed-body")
async def parsed_body_webhook(request: Request):
    payload = await request.json()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    try:
        client.utility.verify_webhook_signature(payload, signature, "webhook-secret")
    except Exception:
        pass
    if payload["event"] == "payment.captured":
        raise HTTPException(status_code=409)
    return {"event_id": event_id}


@app.post("/webhooks/helper")
async def helper_webhook(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    apply_verified_event(raw_body, signature, payload["event"])
    return {"event_id": event_id}


@app.post("/webhook-looking-name-only")
async def false_positive_webhook(request: Request):
    metrics["requests"] += 1
    return {"payment": "looks relevant"}
