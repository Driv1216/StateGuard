class Utility:
    def verify_webhook_signature(self, body, signature, secret):
        return None


class Client:
    def __init__(self, auth):
        self.utility = Utility()
