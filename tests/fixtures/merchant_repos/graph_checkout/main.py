import razorpay
from fastapi import FastAPI

app = FastAPI()
client = razorpay.Client(auth=("key", "secret"))
server_orders = {"merchant-order": {"razorpay_order_id": "order_server", "status": "created"}}


@app.post("/checkout/confirmed")
def confirmed_checkout(razorpay_payment_id, razorpay_order_id, razorpay_signature):
    server_order_id = server_orders["merchant-order"]["razorpay_order_id"]
    client.utility.verify_payment_signature(
        {
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_order_id": server_order_id,
            "razorpay_signature": razorpay_signature,
        }
    )
    server_orders["merchant-order"]["status"] = "captured"
    return {"ok": True}


@app.post("/checkout/client-order")
def client_order_checkout(razorpay_payment_id, razorpay_order_id, razorpay_signature):
    client.utility.verify_payment_signature(
        {
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_order_id": razorpay_order_id,
            "razorpay_signature": razorpay_signature,
        }
    )
    return {"ok": True}


@app.post("/checkout/client-keyed-order")
def client_keyed_order_checkout(razorpay_payment_id, razorpay_order_id, razorpay_signature):
    merchant_order = server_orders[razorpay_order_id]
    server_order_id = merchant_order["razorpay_order_id"]
    client.utility.verify_payment_signature(
        {
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_order_id": server_order_id,
            "razorpay_signature": razorpay_signature,
        }
    )
    return {"ok": True}


class Repository:
    def order_id(self):
        return "unknown"


repository = Repository()


@app.post("/checkout/unknown-order")
def unknown_order_checkout(razorpay_payment_id, razorpay_order_id, razorpay_signature):
    stored_order_id = repository.order_id()
    client.utility.verify_payment_signature(
        {
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_order_id": stored_order_id,
            "razorpay_signature": razorpay_signature,
        }
    )
    return {"ok": True}
