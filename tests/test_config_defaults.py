from __future__ import annotations

import socket
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.config import (
    CONFIG_SCHEMA_VERSION,
    DataConfig,
    ExternalWriteConfig,
    ExternalWritesConfig,
    ModelEgressConfig,
    ModelsConfig,
    ProfileConfig,
    SecurityConfig,
    SentinelConfig,
    SourcesConfig,
    load_bundled_defaults,
)


def test_bundled_defaults_are_typed_and_credential_free() -> None:
    config = load_bundled_defaults()

    assert isinstance(config, SentinelConfig)
    assert config.schema_version == CONFIG_SCHEMA_VERSION
    assert config.profile.name == "local-only"
    assert config.profile.timezone == "UTC"
    assert config.data.storage_path is None
    assert config.sources.enabled == ()
    assert config.sources.host_allowlist == ()
    assert config.models.egress.internal_cloud_consent is False
    assert config.security.allowed_email_recipients == ()
    assert config.security.github_allowlisted_repos == ()
    assert not hasattr(config, "credentials")


def test_every_nested_default_uses_its_immutable_schema_type() -> None:
    config = load_bundled_defaults()

    assert isinstance(config.profile, ProfileConfig)
    assert isinstance(config.data, DataConfig)
    assert isinstance(config.sources, SourcesConfig)
    assert isinstance(config.models, ModelsConfig)
    assert isinstance(config.models.egress, ModelEgressConfig)
    assert isinstance(config.security, SecurityConfig)
    assert isinstance(config.security.external_writes, ExternalWritesConfig)
    for capability in (
        config.security.external_writes.gmail_draft,
        config.security.external_writes.gmail_send,
        config.security.external_writes.github_comment,
        config.security.external_writes.github_label,
    ):
        assert isinstance(capability, ExternalWriteConfig)
        assert capability.enabled is False


def test_all_privileged_capabilities_are_explicitly_disabled() -> None:
    config = load_bundled_defaults()
    write_gates = config.security.external_writes

    assert (
        write_gates.gmail_draft.enabled,
        write_gates.gmail_send.enabled,
        write_gates.github_comment.enabled,
        write_gates.github_label.enabled,
    ) == (False, False, False, False)
    assert config.models.egress.internal_cloud_consent is False
    assert config.sources.enabled == ()
    assert config.security.allowed_email_recipients == ()
    assert config.security.github_allowlisted_repos == ()


def test_repeated_default_loads_are_equivalent_but_separate_objects() -> None:
    first = load_bundled_defaults()
    second = load_bundled_defaults()

    assert first == second
    assert first is not second
    assert first.profile is not second.profile


def test_default_models_and_nested_models_are_immutable() -> None:
    config = load_bundled_defaults()

    with pytest.raises(ValidationError):
        config.profile.name = "cloud-max"
    with pytest.raises(ValidationError):
        config.security.external_writes.gmail_send.enabled = True


def test_loading_defaults_needs_no_network_or_filesystem_creation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)

    def unexpected_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("bundled defaults must not access the network")

    def unexpected_mkdir(*args: object, **kwargs: object) -> None:
        raise AssertionError("bundled defaults must not create directories")

    monkeypatch.setattr(socket, "create_connection", unexpected_network)
    monkeypatch.setattr(Path, "mkdir", unexpected_mkdir)

    config = load_bundled_defaults()

    assert config.profile.name == "local-only"
    assert list(tmp_path.iterdir()) == []
