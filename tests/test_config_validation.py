from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from sentinel.config import (
    ConfigValidationError,
    SentinelConfig,
    config_sha256,
    load_bundled_defaults,
    validate_bundled_config,
)
from sentinel.policy import builtin_registry_sha256, policy_sha256

_AB_T1_BASELINE_CONFIG_SHA256 = "9ba0e71e6026ecc93149cfe2052d75082528732a82c2556ce10de893e97c4256"
_AB_T1_BASELINE_POLICY_SHA256 = "743d6f9c314d63b449bfa58952494204edaa6c24eecca78c4f6ef1a1c93ef1df"
_AB_T1_BASELINE_REGISTRY_SHA256 = "15477ccd03a75ad05a05fe5e346e58f1c2946c892d721b187d4f8e71062eab27"


def _document() -> dict[str, Any]:
    return deepcopy(load_bundled_defaults().model_dump(mode="python"))


def _set_path(document: dict[str, Any], *path: str, value: object) -> None:
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value


def test_valid_bundled_document_revalidates_to_the_config_type() -> None:
    result = validate_bundled_config(_document())

    assert isinstance(result, SentinelConfig)
    assert result == load_bundled_defaults()


def test_ab15_valid_bundled_config_preserves_pinned_security_fingerprints() -> None:
    defaults = load_bundled_defaults()
    result = validate_bundled_config(_document())

    assert result == defaults
    assert config_sha256(result) == _AB_T1_BASELINE_CONFIG_SHA256
    assert policy_sha256() == _AB_T1_BASELINE_POLICY_SHA256
    assert builtin_registry_sha256() == _AB_T1_BASELINE_REGISTRY_SHA256


@pytest.mark.parametrize("location", ["top_level_policy", "nested_security"])
@pytest.mark.parametrize("rule_id", ["P00", "P01", "P02"])
def test_ab15_unsupported_hard_rule_overrides_fail_closed_without_mutation(
    location: str,
    rule_id: str,
) -> None:
    document = _document()
    original_defaults = load_bundled_defaults()

    if location == "top_level_policy":
        document["policy"] = {"unsafe_overrides": {rule_id: True}}
    else:
        document["security"]["unsafe_overrides"] = {rule_id: True}
    submitted_document = deepcopy(document)

    with pytest.raises(ConfigValidationError) as exc_info:
        validate_bundled_config(document)

    assert str(exc_info.value) == "Configuration is invalid."
    assert rule_id not in str(exc_info.value)
    assert document == submitted_document
    assert load_bundled_defaults() == original_defaults
    assert config_sha256(load_bundled_defaults()) == _AB_T1_BASELINE_CONFIG_SHA256
    assert policy_sha256() == _AB_T1_BASELINE_POLICY_SHA256
    assert builtin_registry_sha256() == _AB_T1_BASELINE_REGISTRY_SHA256


@pytest.mark.parametrize(
    "field,value",
    [
        ("approved", True),
        ("owner_verified", True),
        ("policy_disabled", True),
        ("allow_private_cloud", True),
        ("external_writes_enabled", True),
        ("approval_grants", ("synthetic-grant",)),
        ("credentials", {"api_key": "SYNTHETIC-CREDENTIAL-CANARY"}),
        ("plugins", {"registry": ("unreviewed.synthetic",)}),
        ("policy", {"unsafe_overrides": ("P03",)}),
        ("sensitivity", "PUBLIC"),
    ],
)
def test_unknown_top_level_privilege_or_authority_fields_are_rejected(
    field: str, value: object
) -> None:
    document = _document()
    document[field] = value

    with pytest.raises(ConfigValidationError):
        validate_bundled_config(document)


@pytest.mark.parametrize(
    "path,value",
    [
        (("profile", "approved"), True),
        (("data", "retention"), "forever"),
        (("sources", "sensitivity"), "PUBLIC"),
        (("models", "profiles"), {"cloud-max": {"per_task": {"briefing": "openai/x"}}}),
        (("models", "egress", "allow_private_cloud"), True),
        (("security", "credentials"), {"refresh_token": "SYNTHETIC-CANARY"}),
        (("security", "approval_grants"), ("synthetic-grant",)),
        (("security", "external_writes", "gmail_send", "approved"), True),
        (("security", "external_writes", "unknown_capability"), {"enabled": True}),
        (("security", "unsafe_overrides"), {"P03": True}),
    ],
)
def test_unknown_nested_configuration_is_rejected(
    path: tuple[str, ...], value: object
) -> None:
    document = _document()
    _set_path(document, *path[:-1], value={path[-1]: value})

    with pytest.raises(ConfigValidationError):
        validate_bundled_config(document)


@pytest.mark.parametrize(
    "path,value",
    [
        (("schema_version",), 1),
        (("profile", "name"), 5),
        (("profile", "timezone"), 123),
        (("profile", "timezone"), "Asia/Kolkata"),
        (("data", "storage_path"), "C:/SENTINEL.sqlite3"),
        (("sources", "enabled"), ["gmail_read"]),
        (("models", "egress", "internal_cloud_consent"), "false"),
        (("security", "allowed_email_recipients"), ["owner@example.test"]),
        (("security", "github_allowlisted_repos"), 1),
    ],
)
def test_incorrect_types_are_rejected_without_coercion(
    path: tuple[str, ...], value: object
) -> None:
    document = _document()
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(ConfigValidationError):
        validate_bundled_config(document)


@pytest.mark.parametrize(
    "path,value",
    [
        (("profile", "name"), "cloud-max"),
        (("models", "egress", "internal_cloud_consent"), True),
        (("security", "external_writes", "gmail_draft", "enabled"), True),
        (("security", "external_writes", "gmail_send", "enabled"), True),
        (("security", "external_writes", "github_comment", "enabled"), True),
        (("security", "external_writes", "github_label", "enabled"), True),
        (("sources", "enabled"), ("gmail_read",)),
        (("security", "allowed_email_recipients"), ("owner@example.test",)),
        (("security", "github_allowlisted_repos"), ("owner/private-repo",)),
    ],
)
def test_privileged_or_external_defaults_cannot_be_enabled(
    path: tuple[str, ...], value: object
) -> None:
    document = _document()
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(ConfigValidationError):
        validate_bundled_config(document)


@pytest.mark.parametrize(
    "path",
    [
        ("schema_version",),
        ("profile",),
        ("profile", "name"),
        ("profile", "timezone"),
        ("data",),
        ("sources",),
        ("models",),
        ("models", "egress"),
        ("security",),
        ("security", "external_writes"),
    ],
)
def test_missing_required_fields_are_rejected(path: tuple[str, ...]) -> None:
    document = _document()
    target = document
    for part in path[:-1]:
        target = target[part]
    del target[path[-1]]

    with pytest.raises(ConfigValidationError):
        validate_bundled_config(document)


def test_invalid_input_error_does_not_echo_credentials() -> None:
    document = _document()
    canary = "SYNTHETIC-API-CREDENTIAL-CANARY"
    document["credentials"] = {"token": canary}

    with pytest.raises(ConfigValidationError) as exc_info:
        validate_bundled_config(document)

    assert str(exc_info.value) == "Configuration is invalid."
    assert canary not in str(exc_info.value)
