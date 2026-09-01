import os


async def grant_ticket(payment_id):
    if (
        os.environ.get("SG01_BEHAVIOR") == "exception"
        or os.environ.get("SG02_BEHAVIOR") == "exception"
    ):
        raise RuntimeError("synthetic customer target failure")
    return {"payment_id": payment_id}
