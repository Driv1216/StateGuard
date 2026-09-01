import razorpay

client = razorpay.Client(auth=("key", "secret"))


def verify_forwarded_webhook(raw_body, signature):
    client.utility.verify_webhook_signature(raw_body, signature, "webhook-secret")
