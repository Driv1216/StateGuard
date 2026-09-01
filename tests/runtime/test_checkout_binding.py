from __future__ import annotations

from fastapi import Body, Cookie, Depends, FastAPI, Header, Path, Request

from stateguard.graph.contracts import (
    CheckoutFieldBinding,
    CheckoutRequestBinding,
    CheckoutRequestTransport,
)
from stateguard.runtime.contracts import IngressRuntimeBinding
from stateguard.runtime.routes import _checkout_binding_matches


def _binding(path: str, transport: CheckoutRequestTransport) -> IngressRuntimeBinding:
    return IngressRuntimeBinding(
        ingress_node_id=f"sgnode_{'1' * 32}",
        route_registration_id=f"sgroute_{'2' * 32}",
        app_instance_id=f"sgfw_{'3' * 32}",
        ingress_symbol_id=f"sgsym_{'4' * 32}",
        method="POST",
        effective_path=path,
        checkout_request_binding=CheckoutRequestBinding(
            transport=transport,
            fields=tuple(
                CheckoutFieldBinding(canonical_name=name, request_name=name)
                for name in (
                    "razorpay_payment_id",
                    "razorpay_order_id",
                    "razorpay_signature",
                )
            ),
        ),
    )


def _route(app: FastAPI, path: str):
    return next(item for item in app.routes if getattr(item, "path", None) == path)


def test_live_checkout_binding_rejects_unsupplied_required_inputs() -> None:
    app = FastAPI()

    def merchant_dependency() -> str:
        return "merchant-token"

    @app.post("/header")
    async def header_callback(
        razorpay_payment_id: str,
        razorpay_order_id: str,
        razorpay_signature: str,
        merchant_token: str = Header(...),
    ) -> None:
        return None

    @app.post("/cookie")
    async def cookie_callback(
        razorpay_payment_id: str,
        razorpay_order_id: str,
        razorpay_signature: str,
        merchant_cookie: str = Cookie(...),
    ) -> None:
        return None

    @app.post("/path/{merchant_id}")
    async def path_callback(
        merchant_id: str = Path(...),
        razorpay_payment_id: str = "",
        razorpay_order_id: str = "",
        razorpay_signature: str = "",
    ) -> None:
        return None

    @app.post("/dependency")
    async def dependency_callback(
        razorpay_payment_id: str,
        razorpay_order_id: str,
        razorpay_signature: str,
        merchant_token: str = Depends(merchant_dependency),
    ) -> None:
        return None

    @app.post("/body-extra")
    async def body_extra_callback(
        razorpay_payment_id: str = Body(...),
        razorpay_order_id: str = Body(...),
        razorpay_signature: str = Body(...),
        merchant_required: str = Body(...),
    ) -> None:
        return None

    cases = (
        ("/header", CheckoutRequestTransport.QUERY),
        ("/cookie", CheckoutRequestTransport.QUERY),
        ("/path/{merchant_id}", CheckoutRequestTransport.QUERY),
        ("/dependency", CheckoutRequestTransport.QUERY),
        ("/body-extra", CheckoutRequestTransport.JSON),
    )
    for path, transport in cases:
        assert not _checkout_binding_matches(_route(app, path), _binding(path, transport))


def test_live_checkout_binding_accepts_framework_and_optional_inputs() -> None:
    app = FastAPI()

    @app.post("/manual-json")
    async def manual_json_callback(request: Request) -> None:
        await request.json()

    @app.post("/optional")
    async def optional_callback(
        razorpay_payment_id: str,
        razorpay_order_id: str,
        razorpay_signature: str,
        merchant_query: str = "query-default",
        merchant_header: str = Header("header-default"),
        merchant_cookie: str = Cookie("cookie-default"),
    ) -> None:
        return None

    assert _checkout_binding_matches(
        _route(app, "/manual-json"),
        _binding("/manual-json", CheckoutRequestTransport.JSON),
    )
    assert _checkout_binding_matches(
        _route(app, "/optional"),
        _binding("/optional", CheckoutRequestTransport.QUERY),
    )
