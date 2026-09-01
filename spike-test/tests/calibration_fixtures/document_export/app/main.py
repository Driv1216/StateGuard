from fastapi import APIRouter

from . import actions


router = APIRouter()


def finish_export(payload: dict) -> str:
    return actions.deliver_export_bundle(payload)


@router.api_route("/export-events", methods=["POST"])
def ingest_export_event(event: dict) -> dict:
    if event["type"] == "payment.captured":
        finish_export(event["payment"])
    actions.notify_export_operator(event["payment"])
    return {"stored": True}

