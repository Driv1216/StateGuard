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
            domain.persist_learner_profile(payment)
            domain.send_receipt_notification(payment)
            domain.record_payment_analytics(payment)
            domain.persist_cohort_row(payment)
        domain.unlock_course(payment)
    elif event_type == "payment.authorized":
        domain.validate_webhook_signature(payment)
    return {"accepted": True}
