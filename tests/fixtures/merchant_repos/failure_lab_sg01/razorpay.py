import hashlib
import hmac


class Utility:
    def verify_webhook_signature(self, body, signature, secret):
        expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("invalid webhook signature")


class Client:
    def __init__(self, auth):
        self.utility = Utility()
