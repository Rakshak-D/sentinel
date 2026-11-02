from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any

import pytest

from sentinel.config import (
    CONFIG_SCHEMA_VERSION,
    ConfigValidationError,
    SentinelConfig,
    canonical_config_bytes,
    config_sha256,
    load_bundled_defaults,
    validate_bundled_config,
)


def _as_document(config: SentinelConfig) -> dict[str, Any]:
    return deepcopy(config.model_dump(mode="python"))


def _reverse_mapping(value: object) -> object:
    if isinstance(value, dict):
        return {key: _reverse_mapping(item) for key, item in reversed(tuple(value.items()))}
    if isinstance(value, tuple):
        return tuple(_reverse_mapping(item) for item in value)
    return value


def test_canonical_bytes_parse_unambiguously_and_include_schema_version() -> None:
    config = load_bundled_defaults()
    encoded = canonical_config_bytes(config)
    parsed = json.loads(encoded)

    assert isinstance(parsed, dict)
    assert parsed["schema_version"] == CONFIG_SCHEMA_VERSION
    assert b'"schema_version":"sentinel.config.v1"' in encoded
    assert validate_bundled_config(encoded) == config


def test_duplicate_json_keys_are_rejected_instead_of_using_last_value() -> None:
    encoded = canonical_config_bytes(load_bundled_defaults())
    duplicated = encoded.replace(
        b'"timezone":"UTC"',
        b'"timezone":"UTC","timezone":"UTC"',
    )

    with pytest.raises(ConfigValidationError):
        validate_bundled_config(duplicated)


def test_equivalent_validated_configurations_have_identical_canonical_bytes() -> None:
    config = load_bundled_defaults()
    equivalent = validate_bundled_config(_as_document(config))

    assert canonical_config_bytes(config) == canonical_config_bytes(equivalent)


def test_input_key_order_does_not_change_canonical_bytes_or_fingerprint() -> None:
    config = load_bundled_defaults()
    reordered = validate_bundled_config(_reverse_mapping(_as_document(config)))

    assert canonical_config_bytes(config) == canonical_config_bytes(reordered)
    assert config_sha256(config) == config_sha256(reordered)


def test_sha256_is_deterministic_and_covers_the_canonical_bytes() -> None:
    config = load_bundled_defaults()
    encoded = canonical_config_bytes(config)

    assert config_sha256(config) == hashlib.sha256(encoded).hexdigest()
    assert config_sha256(config) == config_sha256(load_bundled_defaults())
    assert len(config_sha256(config)) == 64


@pytest.mark.parametrize(
    "mutated",
    [
        lambda config: config.model_copy(update={"schema_version": "sentinel.config.v99"}),
        lambda config: config.model_copy(
            update={"profile": config.profile.model_copy(update={"name": "cloud-max"})}
        ),
        lambda config: config.model_copy(
            update={
                "security": config.security.model_copy(
                    update={"external_writes": config.security.external_writes.model_copy(
                        update={"gmail_send": {"enabled": True}}
                    )}
                )
            }
        ),
    ],
)
def test_unvalidated_pydantic_copies_cannot_bypass_fingerprint_validation(mutated) -> None:
    unsafe_copy = mutated(load_bundled_defaults())

    with pytest.raises(ConfigValidationError):
        canonical_config_bytes(unsafe_copy)
    with pytest.raises(ConfigValidationError):
        config_sha256(unsafe_copy)


def test_untrusted_object_is_not_stringified_during_validation_or_fingerprinting() -> None:
    class HostileValue:
        def __str__(self) -> str:
            raise AssertionError("__str__ must not be called")

        def __repr__(self) -> str:
            raise AssertionError("__repr__ must not be called")

    config = load_bundled_defaults()
    unsafe_profile = config.profile.model_copy(update={"timezone": HostileValue()})
    unsafe_copy = config.model_copy(update={"profile": unsafe_profile})

    with pytest.raises(ConfigValidationError):
        canonical_config_bytes(unsafe_copy)


def test_unchecked_constructed_model_is_revalidated_before_fingerprinting() -> None:
    config = load_bundled_defaults()
    raw = _as_document(config)
    raw["schema_version"] = "sentinel.config.v99"
    unchecked = SentinelConfig.model_construct(**raw)

    with pytest.raises(ConfigValidationError):
        canonical_config_bytes(unchecked)


def test_canonical_api_rejects_arbitrary_python_objects_and_mappings() -> None:
    with pytest.raises(ConfigValidationError):
        canonical_config_bytes({"schema_version": CONFIG_SCHEMA_VERSION})  # type: ignore[arg-type]

    with pytest.raises(ConfigValidationError):
        canonical_config_bytes(object())  # type: ignore[arg-type]
