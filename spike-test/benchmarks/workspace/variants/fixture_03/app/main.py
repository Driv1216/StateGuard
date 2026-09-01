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
            domain.bind_region_affinity(payment)
            domain.snapshot_tenant_quota_basis(payment)
            domain.attach_workspace_cost_center(payment)
            domain.persist_customer_profile(payment)
            domain.send_receipt_notification(payment)
            domain.record_payment_analytics(payment)
        if event_id not in state.fulfilled_event_ids:
            state.fulfilled_event_ids.add(event_id)
            domain.materialize_workspace_entitlement(payment)
    elif event_type == "payment.authorized":
        domain.materialize_workspace_entitlement(payment)
        domain.validate_webhook_signature(payment)
    return {"accepted": True}
