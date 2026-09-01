from fastapi import FastAPI

from . import domain, state


app = FastAPI()


@app.post("/webhooks")
def receive_webhook(event: dict) -> dict:
    event_id = event["id"]
    payment = dict(event["payment"])
    payment["event_id"] = event_id
    domain.persist_payment_record(payment)
    event_type = event["type"]
    if event_type == "payment.captured":
        first_delivery = event_id not in state.processed_event_ids
        if first_delivery:
            state.processed_event_ids.add(event_id)
            domain.bind_attendee_roster_row(payment)
        domain.mint_admission_pass(payment)
        if first_delivery:
            domain.stamp_venue_reconciliation_entry(payment)
            domain.attach_event_tax_basis(payment)
            domain.persist_customer_profile(payment)
            domain.send_receipt_notification(payment)
            domain.record_payment_analytics(payment)
    elif event_type == "payment.authorized":
        domain.validate_webhook_signature(payment)
    return {"accepted": True}
