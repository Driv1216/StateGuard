import razorpay
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from helpers import verify_forwarded_webhook

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))
rebound_client = razorpay.Client(auth=("key", "secret"))
if __name__ == "__main__":
    rebound_client = object()

orders = {"merchant-order": {"status": "pending"}}
metrics = {"requests": 0}


@app.post("/exceptions/swallowed")
async def swallowed_exception(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    try:
        client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    except Exception:
        pass
    if payload["event"] == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
    return {"event_id": event_id}


@app.post("/exceptions/terminating")
async def terminating_exception(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    try:
        client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    except Exception:
        return JSONResponse({"ok": False}, status_code=400)
    if payload["event"] == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
    return JSONResponse({"event_id": event_id}, status_code=202)


@app.post("/exceptions/finally-return")
async def finally_return(request: Request):
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    try:
        if payload["event"] == "payment.captured":
            orders["merchant-order"]["status"] = "captured"
    finally:
        return JSONResponse({"event_id": event_id}, status_code=200)  # noqa: B012


@app.post("/exceptions/finally-mutation")
async def finally_mutation(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    try:
        client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    finally:
        if payload["event"] == "payment.captured":
            orders["merchant-order"]["status"] = "captured"
    return {"event_id": event_id}


@app.post("/exceptions/multiple-exits")
async def multiple_exception_exits(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    if payload["event"] == "payment.captured":
        metrics["requests"] += 1
    try:
        client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    except Exception:
        return JSONResponse({"ok": False}, status_code=400)
    else:
        return JSONResponse({"event_id": event_id}, status_code=202)
    finally:
        metrics["requests"] += 1


@app.post("/sdk/rebound")
async def rebound_sdk_client(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    rebound_client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    if payload["event"] == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
    return {"event_id": event_id}


@app.post("/helpers/propagated")
async def propagated_helper(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    verify_forwarded_webhook(raw_body, signature)
    if payload["event"] == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
    return {"event_id": event_id}


@app.post("/helpers/swallowed")
async def swallowed_helper(request: Request):
    raw_body = await request.body()
    signature = request.headers["x-razorpay-signature"]
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    try:
        verify_forwarded_webhook(raw_body, signature)
    except Exception:
        pass
    if payload["event"] == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
    return {"event_id": event_id}
