"""Strict immutable schema for Sentinel's bundled CR0 configuration."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictStr, field_validator

CONFIG_SCHEMA_VERSION: Literal["sentinel.config.v1"] = "sentinel.config.v1"


class ConfigValidationError(ValueError):
    """Non-sensitive validation failure that never echoes config input values."""


class _FrozenConfig(BaseModel):
    """Strict nested configuration model with no mutable collection fields."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
    )


class ProfileConfig(_FrozenConfig):
    """Local profile selection and the only timezone supported in this slice."""

    name: Literal["local-only"]
    timezone: Literal["UTC"]


class DataConfig(_FrozenConfig):
    """Storage remains unselected; this slice never chooses or creates a path."""

    storage_path: None


class SourcesConfig(_FrozenConfig):
    """Source and host allowlists are empty and cannot be activated in CR0-F."""

    enabled: tuple[StrictStr, ...]
    host_allowlist: tuple[StrictStr, ...]

    @field_validator("enabled", "host_allowlist")
    @classmethod
    def keep_external_sources_disabled(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value:
            raise ValueError("bundled configuration cannot enable external sources")
        return value


class ModelEgressConfig(_FrozenConfig):
    """Cloud consent is a hard false in the bundled configuration schema."""

    internal_cloud_consent: Literal[False]


class ModelsConfig(_FrozenConfig):
    """No provider profiles or model aliases are configured in this slice."""

    egress: ModelEgressConfig


class ExternalWriteConfig(_FrozenConfig):
    """One external-write switch; activation is not representable in CR0-F."""

    enabled: Literal[False]


class ExternalWritesConfig(_FrozenConfig):
    """Fixed, known external effect switches; all must remain disabled."""

    gmail_draft: ExternalWriteConfig
    gmail_send: ExternalWriteConfig
    github_comment: ExternalWriteConfig
    github_label: ExternalWriteConfig


class SecurityConfig(_FrozenConfig):
    """External recipient/repository allowlists stay empty without owner review."""

    external_writes: ExternalWritesConfig
    allowed_email_recipients: tuple[StrictStr, ...]
    github_allowlisted_repos: tuple[StrictStr, ...]

    @field_validator("allowed_email_recipients", "github_allowlisted_repos")
    @classmethod
    def keep_external_allowlists_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value:
            raise ValueError("bundled configuration cannot allow external targets")
        return value


class SentinelConfig(_FrozenConfig):
    """Only the safe bundled defaults and their strict schema are represented."""

    schema_version: Literal["sentinel.config.v1"]
    profile: ProfileConfig
    data: DataConfig
    sources: SourcesConfig
    models: ModelsConfig
    security: SecurityConfig
