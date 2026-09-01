import razorpay

client = razorpay.Client(auth=("key", "secret"))
orders = {"merchant-order": {"status": "pending"}}


def apply_verified_event(raw_body, signature, event):
    client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
    if event == "payment.captured":
        orders["merchant-order"]["status"] = "captured"
