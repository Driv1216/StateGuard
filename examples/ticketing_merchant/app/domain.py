"""Ticketing-domain actions with deliberately plausible semantic names."""

from __future__ import annotations

from .storage import record_admission_pass, record_roster_binding


def bind_attendee_roster_row(payment_id: str) -> dict[str, str | int]:
    """Bind paid attendee metadata into the event roster."""

    row_id = record_roster_binding(payment_id)
    return {"payment_id": payment_id, "roster_row_id": row_id}


def mint_admission_pass(payment_id: str) -> dict[str, str | int]:
    """Create the scan-ready admission entitlement purchased by the attendee."""

    pass_id = record_admission_pass(payment_id)
    return {"payment_id": payment_id, "admission_pass_id": pass_id}
