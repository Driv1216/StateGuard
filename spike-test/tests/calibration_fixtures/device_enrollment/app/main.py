from fastapi import FastAPI

from .operations import activate_device_profile as bring_online
from .operations import issue_refund_record


app = FastAPI()


@app.post("/device-events")
async def accept_device_event(event: dict) -> dict:
    if event["type"] == "payment.captured":
        bring_online(event["payment"])
    elif event["type"] == "payment.authorized":
        issue_refund_record(event["payment"])
    return {"accepted": True}

