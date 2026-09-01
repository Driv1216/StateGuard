from fastapi import APIRouter, FastAPI, Request

app = FastAPI()
outer = APIRouter(prefix="/outer")
inner = APIRouter(prefix="/inner")


@inner.post("/hook/")
async def nested_hook(request: Request):
    event_id = request.headers["x-razorpay-event-id"]
    payload = await request.json()
    if payload["event"] == "payment.captured":
        return {"event_id": event_id}
    return {"ok": True}


outer.include_router(inner, prefix="/nested")
inner.include_router(outer, prefix="/cycle")
app.include_router(outer, prefix="/one")
app.include_router(outer, prefix="/two")
app.include_router(outer, prefix="/same")
app.include_router(outer, prefix="/same")
