processed_event_ids: set[str] = set()
fulfilled_event_ids: set[str] = set()
admission_passes: dict[str, dict] = {}
attendee_roster_rows: dict[str, dict] = {}
venue_reconciliation_entries: dict[str, dict] = {}
event_tax_bases: dict[str, dict] = {}
payment_records: dict[str, dict] = {}
customer_profiles: dict[str, dict] = {}
notifications: dict[str, dict] = {}
analytics_rows: dict[str, dict] = {}
signature_checks: dict[str, dict] = {}


def reset_state() -> None:
    processed_event_ids.clear()
    fulfilled_event_ids.clear()
    admission_passes.clear()
    attendee_roster_rows.clear()
    venue_reconciliation_entries.clear()
    event_tax_bases.clear()
    payment_records.clear()
    customer_profiles.clear()
    notifications.clear()
    analytics_rows.clear()
    signature_checks.clear()

