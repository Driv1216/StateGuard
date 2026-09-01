"""HTTP-only request and liveness contracts for the local control API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from stateguard.contracts.common import SymbolId
from stateguard.contracts.config import FulfilmentPolicy, LateAuthorisationPolicy


class HTTPContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HealthV1(HTTPContract):
    schema_version: Literal[1] = 1
    api_version: Literal["v1"] = "v1"
    status: Literal["OK"] = "OK"
    producer_version: str


class EmptyActionRequest(HTTPContract):
    """An exact empty JSON object; the URL versions this request contract."""


class SemanticConfirmRequest(HTTPContract):
    symbol_id: SymbolId


class PolicyConfirmRequest(HTTPContract):
    fulfilment: FulfilmentPolicy | None = None
    late_authorisation: LateAuthorisationPolicy | None = None

    @model_validator(mode="after")
    def require_one_value(self) -> PolicyConfirmRequest:
        if self.fulfilment is None and self.late_authorisation is None:
            raise ValueError("at least one policy value is required")
        return self
