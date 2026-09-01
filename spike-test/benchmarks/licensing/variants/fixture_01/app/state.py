processed_event_ids: set[str] = set()
fulfilled_event_ids: set[str] = set()
license_seats: dict[str, dict] = {}
contract_terms: dict[str, dict] = {}
catalog_editions: dict[str, dict] = {}
reseller_attributions: dict[str, dict] = {}
payment_records: dict[str, dict] = {}
customer_profiles: dict[str, dict] = {}
notifications: dict[str, dict] = {}
analytics_rows: dict[str, dict] = {}
signature_checks: dict[str, dict] = {}


def reset_state() -> None:
    processed_event_ids.clear()
    fulfilled_event_ids.clear()
    license_seats.clear()
    contract_terms.clear()
    catalog_editions.clear()
    reseller_attributions.clear()
    payment_records.clear()
    customer_profiles.clear()
    notifications.clear()
    analytics_rows.clear()
    signature_checks.clear()

