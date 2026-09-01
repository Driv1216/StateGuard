from fastapi import APIRouter
from fastapi import FastAPI as API

PREFIX = "/payments"
app: API = API()
router = APIRouter(prefix=PREFIX)


@app.get("/health")
def health():
    return {"ok": True}


@app.api_route("/callback", methods=["POST", "PUT"])
async def callback(razorpay_payment_id: str):
    return razorpay_payment_id


@router.post("/webhook")
async def webhook():
    event = "payment.captured"
    header = "x-razorpay-event-id"
    unrelated = "sk_live_private_secret"
    return event, header, unrelated


app.include_router(router)
