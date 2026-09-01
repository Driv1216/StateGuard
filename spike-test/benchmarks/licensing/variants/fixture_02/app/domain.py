from . import state


def allocate_license_seat(payment: dict) -> str:
    key = f"seat:{payment['order_id']}"
    state.license_seats[key] = {"user_id": payment["customer_id"], "product_id": payment["product_id"], "seat_state": "assigned"}
    return key


def bind_contract_term(payment: dict) -> str:
    key = f"term:{payment['order_id']}"
    state.contract_terms[key] = {"user_id": payment["customer_id"], "term_code": payment["term_code"], "term_state": "bound"}
    return key


def stamp_catalog_edition(payment: dict) -> str:
    key = f"edition:{payment['order_id']}"
    state.catalog_editions[key] = {"user_id": payment["customer_id"], "edition": payment["product_id"], "edition_state": "stamped"}
    return key


def attach_reseller_attribution(payment: dict) -> str:
    key = f"reseller:{payment['order_id']}"
    state.reseller_attributions[key] = {"user_id": payment["customer_id"], "reseller_id": payment["reseller_id"], "attribution_state": "attached"}
    return key


def persist_payment_record(payment: dict) -> str:
    key = f"payment:{payment['id']}"
    state.payment_records[key] = dict(payment)
    return key


def persist_customer_profile(payment: dict) -> str:
    key = f"customer:{payment['customer_id']}"
    state.customer_profiles[key] = {"last_product": payment["product_id"]}
    return key


def send_receipt_notification(payment: dict) -> str:
    key = f"message:{payment['event_id']}"
    state.notifications[key] = {"customer_id": payment["customer_id"]}
    return key


def record_payment_analytics(payment: dict) -> str:
    key = f"metric:{payment['event_id']}"
    state.analytics_rows[key] = {"amount": payment["amount"]}
    return key


def validate_webhook_signature(payment: dict) -> str:
    key = f"signature:{payment['event_id']}"
    state.signature_checks[key] = {"checked": True}
    return key

