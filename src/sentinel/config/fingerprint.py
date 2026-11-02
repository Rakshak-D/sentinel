"""Deterministic serialization and fingerprinting for exact Sentinel config DTOs."""

from __future__ import annotations

import hashlib
import json
from typing import cast

from pydantic import BaseModel, ValidationError

from sentinel.config.schema import (
    ConfigValidationError,
    DataConfig,
    ExternalWriteConfig,
    ExternalWritesConfig,
    ModelEgressConfig,
    ModelsConfig,
    ProfileConfig,
    SecurityConfig,
    SentinelConfig,
    SourcesConfig,
)

_NESTED_MODEL_FIELDS: dict[type[BaseModel], dict[str, type[BaseModel]]] = {
    SentinelConfig: {
        "profile": ProfileConfig,
        "data": DataConfig,
        "sources": SourcesConfig,
        "models": ModelsConfig,
        "security": SecurityConfig,
    },
    ModelsConfig: {"egress": ModelEgressConfig},
    SecurityConfig: {"external_writes": ExternalWritesConfig},
    ExternalWritesConfig: {
        "gmail_draft": ExternalWriteConfig,
        "gmail_send": ExternalWriteConfig,
        "github_comment": ExternalWriteConfig,
        "github_label": ExternalWriteConfig,
    },
}


def _model_to_input(value: object, expected_type: type[BaseModel]) -> dict[str, object]:
    """Extract only known fields from an exact model instance, recursively."""

    if type(value) is not expected_type:
        raise ConfigValidationError("Configuration is invalid.")

    try:
        instance_fields = object.__getattribute__(value, "__dict__")
        field_names = tuple(expected_type.model_fields)
        if type(instance_fields) is not dict or len(instance_fields) != len(field_names):
            raise ConfigValidationError("Configuration is invalid.")
        if any(type(key) is not str for key in instance_fields):
            raise ConfigValidationError("Configuration is invalid.")
        if any(name not in instance_fields for name in field_names):
            raise ConfigValidationError("Configuration is invalid.")
        if object.__getattribute__(value, "__pydantic_extra__") is not None:
            raise ConfigValidationError("Configuration is invalid.")

        nested_fields = _NESTED_MODEL_FIELDS.get(expected_type, {})
        values: dict[str, object] = {}
        for name in field_names:
            field_value = instance_fields[name]
            nested_type = nested_fields.get(name)
            if nested_type is not None:
                values[name] = _value_to_input(field_value, nested_type)
            else:
                values[name] = field_value
        return values
    except ConfigValidationError:
        raise
    except Exception:
        raise ConfigValidationError("Configuration is invalid.") from None


def _value_to_input(value: object, expected_type: type[BaseModel]) -> dict[str, object]:
    if type(value) is expected_type:
        return _model_to_input(value, expected_type)
    if type(value) is not dict:
        raise ConfigValidationError("Configuration is invalid.")

    raw_mapping = cast(dict[object, object], value)
    if any(type(key) is not str for key in raw_mapping):
        raise ConfigValidationError("Configuration is invalid.")

    normalized: dict[str, object] = {}
    nested_fields = _NESTED_MODEL_FIELDS.get(expected_type, {})
    for key, item in raw_mapping.items():
        field_name = cast(str, key)
        nested_type = nested_fields.get(field_name)
        if nested_type is not None:
            normalized[field_name] = _value_to_input(item, nested_type)
        else:
            normalized[field_name] = item
    return normalized


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigValidationError("Configuration is invalid.")
        result[key] = value
    return result


def validate_bundled_config(value: object) -> SentinelConfig:
    """Strictly validate a config DTO, exact Python mapping, or JSON document.

    Validation errors deliberately omit input values so a rejected credential-like
    value is not echoed in exception text. This function validates configuration
    data only; it does not activate settings or establish owner authority.
    """

    try:
        if type(value) is str or type(value) is bytes:
            json.loads(value, object_pairs_hook=_reject_duplicate_keys)
            return SentinelConfig.model_validate_json(value, strict=True)
        normalized = _value_to_input(value, SentinelConfig)
        return SentinelConfig.model_validate(normalized, strict=True)
    except ConfigValidationError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ConfigValidationError("Configuration is invalid.") from None
    except ValidationError:
        raise ConfigValidationError("Configuration is invalid.") from None


def canonical_config_bytes(value: object) -> bytes:
    """Serialize one validated config as sorted, compact UTF-8 JSON bytes."""

    validated = validate_bundled_config(value)
    payload = validated.model_dump(mode="json")
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def config_sha256(value: object) -> str:
    """Return a lowercase SHA-256 hex fingerprint of the canonical config bytes."""

    return hashlib.sha256(canonical_config_bytes(value)).hexdigest()
