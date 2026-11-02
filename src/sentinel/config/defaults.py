"""In-memory bundled defaults; loading them does not inspect or create files."""

from sentinel.config.schema import (
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
)


def load_bundled_defaults() -> SentinelConfig:
    """Return a fresh immutable, local-only configuration with privileged paths off."""

    return SentinelConfig(
        schema_version=CONFIG_SCHEMA_VERSION,
        profile=ProfileConfig(name="local-only", timezone="UTC"),
        data=DataConfig(storage_path=None),
        sources=SourcesConfig(enabled=(), host_allowlist=()),
        models=ModelsConfig(egress=ModelEgressConfig(internal_cloud_consent=False)),
        security=SecurityConfig(
            external_writes=ExternalWritesConfig(
                gmail_draft=ExternalWriteConfig(enabled=False),
                gmail_send=ExternalWriteConfig(enabled=False),
                github_comment=ExternalWriteConfig(enabled=False),
                github_label=ExternalWriteConfig(enabled=False),
            ),
            allowed_email_recipients=(),
            github_allowlisted_repos=(),
        ),
    )
