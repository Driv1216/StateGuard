from . import state


def grant_subscription_access(payment: dict) -> str:
    key = f"subscription:{payment['customer_id']}"
    state.subscriptions[key] = {"plan_id": payment["product_id"], "access_state": "enabled"}
    return key


def persist_payment_record(payment: dict) -> str:
    key = f"payment:{payment['id']}"
    state.payment_records[key] = dict(payment)
    return key


def persist_customer_profile(payment: dict) -> str:
    key = f"customer:{payment['customer_id']}"
    state.customer_profiles[key] = {"last_plan": payment["product_id"]}
    return key


def send_receipt_notification(payment: dict) -> str:
    key = f"message:{payment['event_id']}"
    state.notifications[key] = {"customer_id": payment["customer_id"]}
    return key


def record_payment_analytics(payment: dict) -> str:
    key = f"metric:{payment['event_id']}"
    state.analytics_rows[key] = {"amount": payment["amount"]}
    return key


def persist_plan_catalog(payment: dict) -> str:
    key = f"plan:{payment['product_id']}"
    state.plan_snapshots[key] = {"order_id": payment["order_id"]}
    return key


def validate_webhook_signature(payment: dict) -> str:
    key = f"signature:{payment['event_id']}"
    state.signature_checks[key] = {"checked": True}
    return key

