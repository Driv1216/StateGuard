from . import state


def bind_attendee_roster_row(payment: dict) -> str:
    key = f"roster:{payment['order_id']}"
    state.attendee_roster_rows[key] = {"event_id": payment["product_id"], "attendee_id": payment["customer_id"], "roster_state": "listed"}
    return key


def mint_admission_pass(payment: dict) -> str:
    key = f"pass:{payment['order_id']}"
    state.admission_passes[key] = {"event_id": payment["product_id"], "holder_id": payment["customer_id"], "scan_state": "ready"}
    return key


def stamp_venue_reconciliation_entry(payment: dict) -> str:
    key = f"venue:{payment['order_id']}"
    state.venue_reconciliation_entries[key] = {"event_id": payment["product_id"], "gross_amount": payment["amount"], "entry_state": "posted"}
    return key


def attach_event_tax_basis(payment: dict) -> str:
    key = f"tax:{payment['order_id']}"
    state.event_tax_bases[key] = {"event_id": payment["product_id"], "gross_amount": payment["amount"], "basis_state": "classified"}
    return key


def persist_payment_record(payment: dict) -> str:
    key = f"payment:{payment['id']}"
    state.payment_records[key] = dict(payment)
    return key


def persist_customer_profile(payment: dict) -> str:
    key = f"customer:{payment['customer_id']}"
    state.customer_profiles[key] = {"last_event": payment["product_id"]}
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

