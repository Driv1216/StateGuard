"""Comment-preserving, authoritative edits of human semantic configuration."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from stateguard.contracts.config import (
    AIConfig,
    ConfirmedCustomerValueConfig,
    MerchantPolicyConfig,
    RuntimeConfig,
)
from stateguard.contracts.identity import sha256_digest

from .config import ConfigLoadError, load_config


class ConcurrentConfigEditError(ConfigLoadError):
    """The user-authored configuration changed during a guarded edit."""


def write_customer_value_confirmation(
    path: Path,
    confirmation: ConfirmedCustomerValueConfig,
) -> None:
    """Replace only semantics.customer_value after authoritative temporary validation."""

    if path.is_symlink():
        raise ConfigLoadError("refusing to edit a symlinked configuration")
    authoritative = load_config(path)
    if authoritative.schema_version != 2:  # pragma: no cover - Literal contract defense
        raise ConfigLoadError("semantic confirmation requires schema_version 2")
    original = path.read_bytes()
    original_fingerprint = sha256_digest(original)
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    try:
        document = yaml.load(original.decode("utf-8"))
    except (UnicodeError, OSError, ValueError) as exc:
        raise ConfigLoadError("configuration cannot be round-trip edited") from exc
    if not isinstance(document, CommentedMap):
        raise ConfigLoadError("configuration root must be a YAML mapping")
    semantics = document.get("semantics")
    if semantics is None:
        semantics = CommentedMap()
        document["semantics"] = semantics
    if not isinstance(semantics, CommentedMap):
        raise ConfigLoadError("semantics must be a YAML mapping")
    semantics["customer_value"] = CommentedMap(
        {
            "symbol_id": confirmation.symbol_id,
            "semantic_context_fingerprint": confirmation.semantic_context_fingerprint,
            "basis": confirmation.basis.value,
        }
    )

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            yaml.dump(document, handle)
            handle.flush()
            os.fsync(handle.fileno())
        load_config(temporary)
        if sha256_digest(path.read_bytes()) != original_fingerprint:
            raise ConcurrentConfigEditError("configuration changed during semantic update")
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
        load_config(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_merchant_policy_confirmation(
    path: Path,
    update: MerchantPolicyConfig,
) -> None:
    """Merge explicitly confirmed policy fields with a guarded comment-preserving edit."""

    if update.fulfilment is None and update.late_authorisation is None:
        raise ValueError("merchant policy update requires at least one explicit value")
    if path.is_symlink():
        raise ConfigLoadError("refusing to edit a symlinked configuration")
    authoritative = load_config(path)
    if authoritative.schema_version != 2:  # pragma: no cover
        raise ConfigLoadError("policy confirmation requires schema_version 2")
    original = path.read_bytes()
    original_fingerprint = sha256_digest(original)
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    try:
        document = yaml.load(original.decode("utf-8"))
    except (UnicodeError, OSError, ValueError) as exc:
        raise ConfigLoadError("configuration cannot be round-trip edited") from exc
    if not isinstance(document, CommentedMap):
        raise ConfigLoadError("configuration root must be a YAML mapping")
    policy = document.get("policy")
    if policy is None:
        policy = CommentedMap()
        document["policy"] = policy
    if not isinstance(policy, CommentedMap):
        raise ConfigLoadError("policy must be a YAML mapping")
    for key, confirmation in (
        ("fulfilment", update.fulfilment),
        ("late_authorisation", update.late_authorisation),
    ):
        if confirmation is not None:
            policy[key] = CommentedMap(
                {
                    "value": confirmation.value.value,
                    "evidence_fingerprint": confirmation.evidence_fingerprint,
                }
            )

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            yaml.dump(document, handle)
            handle.flush()
            os.fsync(handle.fileno())
        load_config(temporary)
        if sha256_digest(path.read_bytes()) != original_fingerprint:
            raise ConcurrentConfigEditError("configuration changed during policy update")
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
        load_config(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_owned_configuration_section(
    path: Path,
    *,
    section: str,
    payload: dict[str, object],
) -> None:
    """Guarded whole-section replacement for the two typed setup-owned sections."""

    if section not in {"ai", "runtime"}:  # pragma: no cover - private caller defense
        raise ValueError("unsupported owned configuration section")
    if path.is_symlink():
        raise ConfigLoadError("refusing to edit a symlinked configuration")
    authoritative = load_config(path)
    if authoritative.schema_version != 2:  # pragma: no cover
        raise ConfigLoadError("setup configuration requires schema_version 2")
    original = path.read_bytes()
    original_fingerprint = sha256_digest(original)
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    try:
        document = yaml.load(original.decode("utf-8"))
    except (UnicodeError, OSError, ValueError) as exc:
        raise ConfigLoadError("configuration cannot be round-trip edited") from exc
    if not isinstance(document, CommentedMap):
        raise ConfigLoadError("configuration root must be a YAML mapping")
    document[section] = CommentedMap(payload)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            yaml.dump(document, handle)
            handle.flush()
            os.fsync(handle.fileno())
        load_config(temporary)
        if sha256_digest(path.read_bytes()) != original_fingerprint:
            raise ConcurrentConfigEditError(f"configuration changed during {section} update")
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
        load_config(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_ai_configuration(path: Path, config: AIConfig) -> None:
    """Replace only the validated provider-agnostic AI configuration section."""

    _write_owned_configuration_section(
        path,
        section="ai",
        payload=config.model_dump(mode="json", exclude_none=True),
    )


def write_runtime_configuration(path: Path, config: RuntimeConfig) -> None:
    """Replace only the validated bounded runtime configuration section."""

    _write_owned_configuration_section(
        path,
        section="runtime",
        payload=config.model_dump(mode="json", exclude_none=True),
    )
