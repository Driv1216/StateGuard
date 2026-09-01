"""Safe YAML loading for the StateGuard project configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError
from yaml.nodes import MappingNode  # type: ignore[import-untyped]

from stateguard.contracts.config import StateGuardConfig


class ConfigLoadError(ValueError):
    """A safe, user-facing configuration load failure."""


class _UniqueKeySafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader, node: MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping keys must be scalar/hashable values",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key: {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def load_config(path: Path) -> StateGuardConfig:
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeySafeLoader)
    except OSError as exc:
        raise ConfigLoadError(f"cannot read configuration: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigLoadError(f"invalid YAML configuration: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigLoadError("configuration root must be a YAML mapping")
    try:
        return StateGuardConfig.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_url=False, include_context=False, include_input=False)
        )
        raise ConfigLoadError(f"invalid StateGuard configuration: {details}") from exc
