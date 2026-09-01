processed_event_ids: set[str] = set()
fulfilled_event_ids: set[str] = set()
workspace_entitlements: dict[str, dict] = {}
region_affinities: dict[str, dict] = {}
tenant_quota_bases: dict[str, dict] = {}
workspace_cost_centers: dict[str, dict] = {}
payment_records: dict[str, dict] = {}
customer_profiles: dict[str, dict] = {}
notifications: dict[str, dict] = {}
analytics_rows: dict[str, dict] = {}
signature_checks: dict[str, dict] = {}


def reset_state() -> None:
    processed_event_ids.clear()
    fulfilled_event_ids.clear()
    workspace_entitlements.clear()
    region_affinities.clear()
    tenant_quota_bases.clear()
    workspace_cost_centers.clear()
    payment_records.clear()
    customer_profiles.clear()
    notifications.clear()
    analytics_rows.clear()
    signature_checks.clear()

