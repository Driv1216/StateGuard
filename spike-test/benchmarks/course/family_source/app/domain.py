from . import state


def unlock_course(payment: dict) -> str:
    key = f"course:{payment['customer_id']}:{payment['product_id']}"
    state.course_access[key] = {"learner_id": payment["customer_id"], "course_id": payment["product_id"], "access_state": "open"}
    return key


def persist_payment_record(payment: dict) -> str:
    key = f"payment:{payment['id']}"
    state.payment_records[key] = dict(payment)
    return key


def persist_learner_profile(payment: dict) -> str:
    key = f"learner:{payment['customer_id']}"
    state.learner_profiles[key] = {"last_course": payment["product_id"]}
    return key


def send_receipt_notification(payment: dict) -> str:
    key = f"message:{payment['event_id']}"
    state.notifications[key] = {"learner_id": payment["customer_id"]}
    return key


def record_payment_analytics(payment: dict) -> str:
    key = f"metric:{payment['event_id']}"
    state.analytics_rows[key] = {"amount": payment["amount"]}
    return key


def persist_cohort_row(payment: dict) -> str:
    key = f"cohort:{payment['order_id']}"
    state.cohort_rows[key] = {"course_id": payment["product_id"]}
    return key


def validate_webhook_signature(payment: dict) -> str:
    key = f"signature:{payment['event_id']}"
    state.signature_checks[key] = {"checked": True}
    return key

