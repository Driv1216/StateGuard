import hashlib
import hmac


class Utility:
    def __init__(self, secret):
        self.secret = secret

    def verify_webhook_signature(self, body, signature, secret):
        expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("invalid webhook signature")

    def verify_payment_signature(self, values):
        message = f"{values['razorpay_order_id']}|{values['razorpay_payment_id']}"
        expected = hmac.new(
            self.secret.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, values["razorpay_signature"]):
            raise ValueError("invalid Checkout signature")


class Client:
    def __init__(self, auth):
        self.utility = Utility(auth[1])
