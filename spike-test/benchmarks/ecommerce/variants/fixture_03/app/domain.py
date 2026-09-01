from . import state


def ship_order(payment: dict) -> str:
    key = f"shipment:{payment['order_id']}"
    state.shipments[key] = {"order_id": payment["order_id"], "destination": payment["address"], "dispatch_state": "queued"}
    return key


def persist_payment_record(payment: dict) -> str:
    key = f"payment:{payment['id']}"
    state.payment_records[key] = dict(payment)
    return key


def persist_customer_profile(payment: dict) -> str:
    key = f"customer:{payment['customer_id']}"
    state.customer_profiles[key] = {"last_order": payment["order_id"]}
    return key


def send_receipt_notification(payment: dict) -> str:
    key = f"message:{payment['event_id']}"
    state.notifications[key] = {"customer_id": payment["customer_id"]}
    return key


def record_payment_analytics(payment: dict) -> str:
    key = f"metric:{payment['event_id']}"
    state.analytics_rows[key] = {"amount": payment["amount"]}
    return key


def reserve_inventory_item(payment: dict) -> str:
    key = f"stock:{payment['product_id']}"
    state.stock_holds[key] = {"order_id": payment["order_id"]}
    return key


def validate_webhook_signature(payment: dict) -> str:
    key = f"signature:{payment['event_id']}"
    state.signature_checks[key] = {"checked": True}
    return key

