processed_event_ids: set[str] = set()
fulfilled_event_ids: set[str] = set()
subscriptions: dict[str, dict] = {}
payment_records: dict[str, dict] = {}
customer_profiles: dict[str, dict] = {}
notifications: dict[str, dict] = {}
analytics_rows: dict[str, dict] = {}
plan_snapshots: dict[str, dict] = {}
signature_checks: dict[str, dict] = {}


def reset_state() -> None:
    processed_event_ids.clear()
    fulfilled_event_ids.clear()
    subscriptions.clear()
    payment_records.clear()
    customer_profiles.clear()
    notifications.clear()
    analytics_rows.clear()
    plan_snapshots.clear()
    signature_checks.clear()

