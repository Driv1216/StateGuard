"""Safe contracts for bounded Razorpay Test Mode resource grounding."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from stateguard.contracts.common import (
    PersistedArtifactModel,
    Sha256Digest,
    VerificationRunId,
)
from stateguard.contracts.identity import fingerprint_json


class RazorpayGroundingStatus(StrEnum):
    GROUNDED = "GROUNDED"
    UNAVAILABLE = "UNAVAILABLE"


class RazorpayGroundingReason(StrEnum):
    MISSING_ENVIRONMENT = "MISSING_ENVIRONMENT"
    LIVE_CREDENTIAL_REJECTED = "LIVE_CREDENTIAL_REJECTED"
    INVALID_TEST_CREDENTIAL = "INVALID_TEST_CREDENTIAL"
    INVALID_PAYMENT_REFERENCE = "INVALID_PAYMENT_REFERENCE"
    REQUEST_REJECTED = "REQUEST_REJECTED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_FAILED = "PROVIDER_FAILED"
    NETWORK_FAILED = "NETWORK_FAILED"
    TIMEOUT = "TIMEOUT"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    RESOURCE_INELIGIBLE = "RESOURCE_INELIGIBLE"


class RazorpaySourceEndpointKind(StrEnum):
    FETCH_PAYMENT = "FETCH_PAYMENT"
    FETCH_LINKED_ORDER = "FETCH_LINKED_ORDER"


class RazorpayTestGroundingRequest(BaseModel):
    """Ephemeral names of environment variables; values are never retained here."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    payment_id_env: str
    key_id_env: str = "RAZORPAY_KEY_ID"
    key_secret_env: str = "RAZORPAY_KEY_SECRET"

    @field_validator("payment_id_env", "key_id_env", "key_secret_env")
    @classmethod
    def validate_environment_name(cls, value: str) -> str:
        if not value or len(value) > 128:
            raise ValueError("environment variable name is invalid")
        if not (value[0].isalpha() or value[0] == "_"):
            raise ValueError("environment variable name is invalid")
        if any(not (character.isalnum() or character == "_") for character in value):
            raise ValueError("environment variable name is invalid")
        return value


class CapturedPaymentProfile(PersistedArtifactModel):
    """Allowlisted resource values used only to shape the synthetic SG-01 input."""

    amount: int = Field(gt=0)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    status: Literal["captured"] = "captured"
    captured: Literal[True] = True


class RazorpayGroundingSnapshot(PersistedArtifactModel):
    schema_version: Literal[1] = 1
    mode: Literal["TEST"] = "TEST"
    status: RazorpayGroundingStatus
    unavailable_reason: RazorpayGroundingReason | None = None
    run_id: VerificationRunId
    acquired_at: datetime
    source_endpoint_kinds: tuple[RazorpaySourceEndpointKind, ...] = ()
    key_id_fingerprint: Sha256Digest | None = None
    payment_id_fingerprint: Sha256Digest | None = None
    order_id_fingerprint: Sha256Digest | None = None
    resource_snapshot_fingerprint: Sha256Digest | None = None
    sanitized_projection_fingerprint: Sha256Digest | None = None
    payment_captured: bool = False
    order_paid: bool = False
    linkage_consistent: bool = False
    amount_consistent: bool = False
    currency_consistent: bool = False
    no_current_refund: bool = False
    grounding_fingerprint: Sha256Digest

    @field_validator("acquired_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("grounding acquisition timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_snapshot(self) -> RazorpayGroundingSnapshot:
        if self.source_endpoint_kinds != tuple(dict.fromkeys(self.source_endpoint_kinds)):
            raise ValueError("grounding endpoint kinds must be unique and ordered")
        fingerprints = (
            self.key_id_fingerprint,
            self.payment_id_fingerprint,
            self.order_id_fingerprint,
            self.resource_snapshot_fingerprint,
            self.sanitized_projection_fingerprint,
        )
        consistency = (
            self.payment_captured,
            self.order_paid,
            self.linkage_consistent,
            self.amount_consistent,
            self.currency_consistent,
            self.no_current_refund,
        )
        if self.status == RazorpayGroundingStatus.GROUNDED:
            if (
                self.unavailable_reason is not None
                or self.source_endpoint_kinds
                != (
                    RazorpaySourceEndpointKind.FETCH_PAYMENT,
                    RazorpaySourceEndpointKind.FETCH_LINKED_ORDER,
                )
                or any(item is None for item in fingerprints)
                or not all(consistency)
            ):
                raise ValueError("grounded evidence requires the complete eligible resource pair")
        elif (
            self.unavailable_reason is None
            or any(item is not None for item in fingerprints)
            or any(consistency)
        ):
            raise ValueError("unavailable grounding may retain only bounded attempt diagnostics")
        if self.grounding_fingerprint != fingerprint_json(
            self.model_dump(mode="json", exclude={"grounding_fingerprint"})
        ):
            raise ValueError("grounding fingerprint must match the safe snapshot")
        return self


class CheckGroundingEvidence(PersistedArtifactModel):
    schema_version: Literal[1] = 1
    label: Literal["TEST MODE RESOURCE PROFILE GROUNDED"] = "TEST MODE RESOURCE PROFILE GROUNDED"
    grounding_fingerprint: Sha256Digest
    sanitized_projection_fingerprint: Sha256Digest
