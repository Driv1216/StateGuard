from __future__ import annotations

import functools
import importlib
from contextlib import contextmanager
from typing import Any, Iterator

from ..schemas import CallRecord


@contextmanager
def instrument_symbol(symbol: str, calls: list[CallRecord]) -> Iterator[None]:
    module_name, attribute = symbol.rsplit(".", 1)
    module = importlib.import_module(module_name)
    original = getattr(module, attribute)
    if not callable(original):
        raise TypeError(f"instrumentation target is not callable: {symbol}")

    @functools.wraps(original)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        payment = args[0] if args and isinstance(args[0], dict) else kwargs.get("payment", {})
        calls.append(CallRecord(
            sequence=len(calls) + 1,
            symbol=symbol,
            event_id=str(payment.get("event_id", "")),
            payment_id=str(payment.get("id", "")),
        ))
        return original(*args, **kwargs)

    setattr(module, attribute, wrapper)
    try:
        yield
    finally:
        setattr(module, attribute, original)

