from fastapi import APIRouter

from ..domain import ship_order as fulfil

router = APIRouter(prefix="/payments")


@router.post("/webhook")
async def webhook(order_id):
    return fulfil(order_id)
