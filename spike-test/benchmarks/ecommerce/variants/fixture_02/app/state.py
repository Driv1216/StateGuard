processed_event_ids: set[str] = set()
fulfilled_event_ids: set[str] = set()
shipments: dict[str, dict] = {}
payment_records: dict[str, dict] = {}
customer_profiles: dict[str, dict] = {}
notifications: dict[str, dict] = {}
analytics_rows: dict[str, dict] = {}
stock_holds: dict[str, dict] = {}
signature_checks: dict[str, dict] = {}


def reset_state() -> None:
    processed_event_ids.clear()
    fulfilled_event_ids.clear()
    shipments.clear()
    payment_records.clear()
    customer_profiles.clear()
    notifications.clear()
    analytics_rows.clear()
    stock_holds.clear()
    signature_checks.clear()

