from . import state


def bind_region_affinity(payment: dict) -> str:
    key = f"region:{payment['order_id']}"
    state.region_affinities[key] = {"tenant_id": payment["customer_id"], "region": payment["region"], "affinity_state": "bound"}
    return key


def snapshot_tenant_quota_basis(payment: dict) -> str:
    key = f"quota:{payment['order_id']}"
    state.tenant_quota_bases[key] = {"tenant_id": payment["customer_id"], "plan_id": payment["product_id"], "basis_state": "measured"}
    return key


def attach_workspace_cost_center(payment: dict) -> str:
    key = f"cost:{payment['order_id']}"
    state.workspace_cost_centers[key] = {"tenant_id": payment["customer_id"], "cost_center": payment["cost_center"], "attribution_state": "attached"}
    return key


def materialize_workspace_entitlement(payment: dict) -> str:
    key = f"entitlement:{payment['order_id']}"
    state.workspace_entitlements[key] = {"tenant_id": payment["customer_id"], "workspace_id": payment["product_id"], "entitlement_state": "ready"}
    return key


def persist_payment_record(payment: dict) -> str:
    key = f"payment:{payment['id']}"
    state.payment_records[key] = dict(payment)
    return key


def persist_customer_profile(payment: dict) -> str:
    key = f"customer:{payment['customer_id']}"
    state.customer_profiles[key] = {"last_workspace": payment["product_id"]}
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

