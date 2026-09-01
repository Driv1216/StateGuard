processed_event_ids: set[str] = set()
fulfilled_event_ids: set[str] = set()
course_access: dict[str, dict] = {}
payment_records: dict[str, dict] = {}
learner_profiles: dict[str, dict] = {}
notifications: dict[str, dict] = {}
analytics_rows: dict[str, dict] = {}
cohort_rows: dict[str, dict] = {}
signature_checks: dict[str, dict] = {}


def reset_state() -> None:
    processed_event_ids.clear()
    fulfilled_event_ids.clear()
    course_access.clear()
    payment_records.clear()
    learner_profiles.clear()
    notifications.clear()
    analytics_rows.clear()
    cohort_rows.clear()
    signature_checks.clear()

