"""Deterministic, credential-free CR0-J demonstration flow."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from importlib.resources import files
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    model_validator,
)

from sentinel.config import (
    config_sha256,
    load_bundled_defaults,
    validate_bundled_config,
)
from sentinel.contracts import (
    BoundaryKind,
    SensitivityLabel,
    SourceEnvelope,
    TrustLabel,
)
from sentinel.gateways import (
    DemoPayload,
    ExecutionMode,
    GatewayFailureCode,
    GatewayRegistry,
    ModelAdapterOutput,
    ModelAdapterRegistration,
    ModelCallResult,
    ModelGateway,
    ModelInvocation,
    ModelLocality,
    ModelProfile,
    ModelRequest,
    ModelTaskClass,
    ToolAdapterOutput,
    ToolAdapterRegistration,
    ToolCallResult,
    ToolCapability,
    ToolGateway,
    ToolInvocation,
    ToolRequest,
)

DEMO_OUTPUT_SCHEMA_VERSION: Literal["sentinel.demo.v1"] = "sentinel.demo.v1"
FIXTURE_VERSION: Literal["sentinel.demo-fixture.v1"] = "sentinel.demo-fixture.v1"
FIXTURE_SHA256 = "365c9f02f1375c3e784138b7cdb3c2fd3ed1a0f4cf64cfec6fdef2fe5d9ecbb8"
_MAX_FIXTURE_BYTES = 8_192
_SOURCE_ID = UUID("1ef3f942-3da2-49a2-9e6c-9dd0ad6d1a8e")
_PRIVATE_SOURCE_ID = UUID("3c760524-e120-4fcf-a00c-19d49685922c")
_SECRET_SOURCE_ID = UUID("715912eb-d1ac-4ad2-a11c-06ec05f77d38")
_MODEL_CALL_ID = UUID("0ffbd21d-8540-4e66-9db4-6fa52ba9c717")
_TOOL_CALL_ID = UUID("3ad0f421-4692-49ed-80c6-3a4778e2f155")
_RUN_ID = UUID("7f251fa1-3791-4e4c-89aa-b4e9dbdf12db")
_MODEL_ADAPTER_ID = "demo.synthetic_model"
_MODEL_PROVIDER_ID = "synthetic.memory"
_MODEL_ID = "synthetic/demo-v1"
_TOOL_ID = "demo.lookup"
_PROMPT_BYTES = b"Sentinel synthetic demonstration prompt v1"
_PROMPT_SHA256 = hashlib.sha256(_PROMPT_BYTES).hexdigest()
_CONFIG_SCHEMA_ID = "sentinel.text.v1"
_DEADLINE = datetime(2099, 1, 1, tzinfo=UTC)


class DemoExecutionError(RuntimeError):
    """A bounded, non-sensitive error raised when the complete demo cannot verify."""


class DemoFixtureValidationError(ValueError):
    """A fixture could not be decoded as the fixed versioned schema."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
    )


class _FixtureSource(_FrozenModel):
    source_id: UUID
    observed_at: AwareDatetime
    sensitivity: Literal["PUBLIC"]
    content: Annotated[StrictStr, Field(min_length=1, max_length=2_048)]


class _FixtureModel(_FrozenModel):
    response_prefix: Annotated[StrictStr, Field(min_length=1, max_length=96)]
    expected_output: Annotated[StrictStr, Field(min_length=1, max_length=2_304)]


class _FixtureTool(_FrozenModel):
    lookup_key: Annotated[StrictStr, Field(min_length=1, max_length=96)]
    lookup_value: Annotated[StrictStr, Field(min_length=1, max_length=512)]


class DemoFixture(_FrozenModel):
    """Strict schema for the single trusted, packaged synthetic fixture."""

    fixture_version: Literal["sentinel.demo-fixture.v1"]
    source: _FixtureSource
    model: _FixtureModel
    tool: _FixtureTool

    @model_validator(mode="after")
    def validate_fixture_model_output(self) -> DemoFixture:
        expected = f"{self.model.response_prefix}: {self.source.content}"
        if self.model.expected_output != expected:
            raise ValueError("fixture model output must match its synthetic input")
        return self


class _BoundaryHashes(_FrozenModel):
    status: Literal["SUCCESS"]
    request_sha256: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    response_sha256: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]


class _NegativeProbes(_FrozenModel):
    unknown_model: Literal["DENIED"]
    secret_model: Literal["DENIED"]
    private_model: Literal["DENIED"]
    unknown_tool: Literal["DENIED"]
    external_write_tool: Literal["DENIED"]
    approval_tool: Literal["DENIED"]


class DemoReport(_FrozenModel):
    """Minimal stable output DTO; it contains no fixture body or execution IDs."""

    schema_version: Literal["sentinel.demo.v1"]
    fixture_version: Literal["sentinel.demo-fixture.v1"]
    fixture_sha256: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    execution_mode: Literal["DEMO"]
    profile: Literal["local-only"]
    config_sha256: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    model: _BoundaryHashes
    tool: _BoundaryHashes
    negative_probes: _NegativeProbes
    credentials_used: Literal[False]
    external_effects: Literal[False]
    production_readiness: Literal[False]

    def to_json_bytes(self) -> bytes:
        """Return the exact sorted, compact UTF-8 JSON report representation."""

        validated = DemoReport.model_validate(self.model_dump(mode="python"), strict=True)
        return json.dumps(
            validated.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class _FixtureModelAdapter:
    """Trusted in-memory adapter whose output is a deterministic fixture transform."""

    demo_only = True

    def __init__(self, fixture: DemoFixture) -> None:
        self._fixture = fixture
        self.invocations: list[ModelInvocation] = []

    def generate(self, invocation: ModelInvocation) -> ModelAdapterOutput:
        if not isinstance(invocation, ModelInvocation):
            raise TypeError("Expected a validated model invocation.")
        expected = self._fixture.source.content.encode("utf-8")
        if invocation.payload_bytes != expected:
            raise ValueError("The demo fixture input did not match.")
        self.invocations.append(invocation)
        output = f"{self._fixture.model.response_prefix}: {self._fixture.source.content}"
        return ModelAdapterOutput(output_bytes=output.encode("utf-8"))


class _FixtureToolAdapter:
    """Trusted in-memory, read-only lookup for the one packaged fixture key."""

    demo_only = True

    def __init__(self, fixture: DemoFixture) -> None:
        self._fixture = fixture
        self.invocations: list[ToolInvocation] = []

    def call(self, invocation: ToolInvocation) -> ToolAdapterOutput:
        if not isinstance(invocation, ToolInvocation):
            raise TypeError("Expected a validated tool invocation.")
        if invocation.capability is not ToolCapability.READ_ONLY:
            raise ValueError("Only a read-only demo lookup is supported.")
        if invocation.request.arguments != (("key", self._fixture.tool.lookup_key),):
            raise ValueError("The demo fixture lookup key did not match.")
        self.invocations.append(invocation)
        return ToolAdapterOutput(output_bytes=self._fixture.tool.lookup_value.encode("utf-8"))


def _read_fixture_resource() -> bytes:
    """Read the one fixed package resource; callers cannot choose a path."""

    return files("sentinel.demo").joinpath("fixtures", "demo-v1.json").read_bytes()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise DemoFixtureValidationError("The synthetic demo fixture is invalid.")
        document[key] = value
    return document


def parse_fixture_document(document: bytes) -> DemoFixture:
    """Validate UTF-8 JSON, duplicate keys, exact fields and the fixed schema version."""

    if type(document) is not bytes or len(document) > _MAX_FIXTURE_BYTES:
        raise DemoFixtureValidationError("The synthetic demo fixture is invalid.")
    try:
        decoded = document.decode("utf-8", errors="strict")
        json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
        return DemoFixture.model_validate_json(document, strict=True)
    except DemoFixtureValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError):
        raise DemoFixtureValidationError("The synthetic demo fixture is invalid.") from None


def load_packaged_fixture() -> DemoFixture:
    """Read and hash-check the pinned packaged fixture without using a user path."""

    try:
        raw = _read_fixture_resource()
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != FIXTURE_SHA256:
            raise DemoExecutionError("The synthetic demo fixture could not be verified.")
        return parse_fixture_document(raw)
    except DemoExecutionError:
        raise
    except Exception:
        raise DemoExecutionError("The synthetic demo fixture could not be verified.") from None


def _source_envelope(
    source_id: UUID,
    content: bytes,
    sensitivity: SensitivityLabel,
    observed_at: datetime,
) -> SourceEnvelope:
    return SourceEnvelope(
        source_id=source_id,
        provider_id="synthetic.demo",
        content_sha256=hashlib.sha256(content).hexdigest(),
        observed_at=observed_at,
        trust=TrustLabel.T3_DERIVED,
        sensitivity=sensitivity,
        parent_ids=(),
        byte_spans=(),
    )


def _model_request(
    source: SourceEnvelope,
    payload: bytes,
    sensitivity: SensitivityLabel,
    config_digest: str,
    *,
    model_id: str = _MODEL_ID,
) -> ModelRequest:
    return ModelRequest(
        call_id=_MODEL_CALL_ID,
        run_id=_RUN_ID,
        adapter_id=_MODEL_ADAPTER_ID,
        model_id=model_id,
        task_class=ModelTaskClass.SUMMARIZATION,
        prompt_id="demo.summary",
        prompt_version="1.0.0",
        prompt_sha256=_PROMPT_SHA256,
        input_schema_id=_CONFIG_SCHEMA_ID,
        output_schema_id=_CONFIG_SCHEMA_ID,
        source_ids=(source.source_id,),
        sensitivity=sensitivity,
        payload_ref=f"sha256:{hashlib.sha256(payload).hexdigest()}",
        redaction_manifest_ref=None,
        config_sha256=config_digest,
        temperature=0.0,
        max_output_tokens=128,
        deadline=_DEADLINE,
        requested_profile=ModelProfile.LOCAL_ONLY,
        replay_mode=False,
    )


def _tool_request(source: SourceEnvelope, key: str, *, tool_id: str = _TOOL_ID) -> ToolRequest:
    return ToolRequest(
        call_id=_TOOL_CALL_ID,
        run_id=_RUN_ID,
        tool_id=tool_id,
        arguments=(("key", key),),
        source_ids=(source.source_id,),
        sensitivity=SensitivityLabel.PUBLIC,
    )


def _require_model_success(
    result: ModelCallResult,
    adapter: _FixtureModelAdapter,
    expected_output: bytes,
) -> _BoundaryHashes:
    if (
        not isinstance(result, ModelCallResult)
        or result.failure is not None
        or result.response is None
        or result.boundary is None
        or result.external_effect is not False
        or result.boundary.kind is not BoundaryKind.MODEL
        or result.boundary.error_code is not None
        or len(adapter.invocations) != 1
    ):
        raise DemoExecutionError("The synthetic model gateway check failed.")

    invocation = adapter.invocations[0]
    response_bytes = result.response.output.encode("utf-8", errors="strict")
    request_digest = hashlib.sha256(invocation.request_bytes).hexdigest()
    response_digest = hashlib.sha256(response_bytes).hexdigest()
    if (
        result.response.provider_model_id != _MODEL_ID
        or result.response.provider_id != _MODEL_PROVIDER_ID
        or invocation.model_id != _MODEL_ID
        or response_bytes != expected_output
        or result.boundary.request_sha256 != request_digest
        or result.boundary.response_sha256 != response_digest
        or result.boundary.request_ref != f"sha256:{request_digest}"
        or result.boundary.response_ref != f"sha256:{response_digest}"
        or result.response.request_sha256 != request_digest
        or result.response.raw_output_ref != f"sha256:{response_digest}"
        or result.response.parsed_ref != f"sha256:{response_digest}"
    ):
        raise DemoExecutionError("The synthetic model boundary check failed.")

    return _BoundaryHashes(
        status="SUCCESS",
        request_sha256=request_digest,
        response_sha256=response_digest,
    )


def _require_tool_success(
    result: ToolCallResult,
    adapter: _FixtureToolAdapter,
    expected_output: bytes,
) -> _BoundaryHashes:
    if (
        not isinstance(result, ToolCallResult)
        or result.failure is not None
        or result.response is None
        or result.boundary is None
        or result.external_effect is not False
        or result.boundary.kind is not BoundaryKind.TOOL
        or result.boundary.error_code is not None
        or len(adapter.invocations) != 1
    ):
        raise DemoExecutionError("The synthetic tool gateway check failed.")

    invocation = adapter.invocations[0]
    response_bytes = result.response.output.encode("utf-8", errors="strict")
    request_digest = hashlib.sha256(invocation.request_bytes).hexdigest()
    response_digest = hashlib.sha256(response_bytes).hexdigest()
    if (
        response_bytes != expected_output
        or result.boundary.request_sha256 != request_digest
        or result.boundary.response_sha256 != response_digest
        or result.boundary.request_ref != f"sha256:{request_digest}"
        or result.boundary.response_ref != f"sha256:{response_digest}"
        or result.response.result_ref != f"sha256:{response_digest}"
    ):
        raise DemoExecutionError("The synthetic tool boundary check failed.")

    return _BoundaryHashes(
        status="SUCCESS",
        request_sha256=request_digest,
        response_sha256=response_digest,
    )


def _require_denied_model(result: ModelCallResult, expected: GatewayFailureCode) -> None:
    if (
        not isinstance(result, ModelCallResult)
        or result.failure is None
        or result.failure.code is not expected
        or result.response is not None
        or result.external_effect is not False
    ):
        raise DemoExecutionError("A synthetic model boundary probe was not denied.")


def _require_denied_tool(result: ToolCallResult, expected: GatewayFailureCode) -> None:
    if (
        not isinstance(result, ToolCallResult)
        or result.failure is None
        or result.failure.code is not expected
        or result.response is not None
        or result.external_effect is not False
    ):
        raise DemoExecutionError("A synthetic tool boundary probe was not denied.")


def _validate_demo_config() -> tuple[Literal["local-only"], str]:
    config = validate_bundled_config(load_bundled_defaults())
    if (
        config.profile.name != "local-only"
        or config.profile.timezone != "UTC"
        or config.data.storage_path is not None
        or config.sources.enabled
        or config.models.egress.internal_cloud_consent is not False
        or any(
            capability.enabled
            for capability in (
                config.security.external_writes.gmail_draft,
                config.security.external_writes.gmail_send,
                config.security.external_writes.github_comment,
                config.security.external_writes.github_label,
            )
        )
        or config.security.allowed_email_recipients
        or config.security.github_allowlisted_repos
    ):
        raise DemoExecutionError("Bundled demo configuration is not safely disabled.")
    return config.profile.name, config_sha256(config)


def _run_verified_flow() -> DemoReport:
    fixture = load_packaged_fixture()
    profile, config_digest = _validate_demo_config()
    source_bytes = fixture.source.content.encode("utf-8")
    source = _source_envelope(
        fixture.source.source_id,
        source_bytes,
        SensitivityLabel.PUBLIC,
        fixture.source.observed_at,
    )
    payload_ref = f"sha256:{hashlib.sha256(source_bytes).hexdigest()}"

    secret_bytes = b"SYNTHETIC_SECRET_INPUT_CANARY"
    private_bytes = b"SYNTHETIC_PRIVATE_INPUT_CANARY"
    secret_source = _source_envelope(
        _SECRET_SOURCE_ID,
        secret_bytes,
        SensitivityLabel.SECRET,
        fixture.source.observed_at,
    )
    private_source = _source_envelope(
        _PRIVATE_SOURCE_ID,
        private_bytes,
        SensitivityLabel.PRIVATE,
        fixture.source.observed_at,
    )
    model_adapter = _FixtureModelAdapter(fixture)
    tool_adapter = _FixtureToolAdapter(fixture)
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(source, secret_source, private_source),
        demo_payloads=(
            DemoPayload(payload_ref=payload_ref, payload_bytes=source_bytes),
        ),
        model_adapters=(
            ModelAdapterRegistration(
                adapter_id=_MODEL_ADAPTER_ID,
                provider_id=_MODEL_PROVIDER_ID,
                model_id=_MODEL_ID,
                locality=ModelLocality.LOOPBACK,
                demo_only=True,
                adapter=model_adapter,
            ),
        ),
        tool_adapters=(
            ToolAdapterRegistration(
                tool_id=_TOOL_ID,
                capability=ToolCapability.READ_ONLY,
                argument_names=("key",),
                demo_only=True,
                adapter=tool_adapter,
            ),
        ),
    )
    model_gateway = ModelGateway(registry)
    tool_gateway = ToolGateway(registry)

    model_result = model_gateway.generate(
        _model_request(source, source_bytes, SensitivityLabel.PUBLIC, config_digest)
    )
    expected_model_bytes = fixture.model.expected_output.encode("utf-8")
    model_hashes = _require_model_success(model_result, model_adapter, expected_model_bytes)

    tool_result = tool_gateway.call(_tool_request(source, fixture.tool.lookup_key))
    expected_tool_bytes = fixture.tool.lookup_value.encode("utf-8")
    tool_hashes = _require_tool_success(tool_result, tool_adapter, expected_tool_bytes)

    unknown_model_result = model_gateway.generate(
        _model_request(
            source,
            source_bytes,
            SensitivityLabel.PUBLIC,
            config_digest,
            model_id="synthetic/unregistered-demo-v1",
        )
    )
    _require_denied_model(unknown_model_result, GatewayFailureCode.UNKNOWN_MODEL)
    secret_result = model_gateway.generate(
        _model_request(secret_source, secret_bytes, SensitivityLabel.SECRET, config_digest)
    )
    _require_denied_model(secret_result, GatewayFailureCode.SENSITIVITY_DENIED)
    private_result = model_gateway.generate(
        _model_request(private_source, private_bytes, SensitivityLabel.PRIVATE, config_digest)
    )
    _require_denied_model(private_result, GatewayFailureCode.SENSITIVITY_DENIED)

    unknown_tool_result = tool_gateway.call(
        _tool_request(source, fixture.tool.lookup_key, tool_id="demo.unregistered")
    )
    _require_denied_tool(unknown_tool_result, GatewayFailureCode.UNKNOWN_TOOL)
    denied_capabilities: dict[ToolCapability, GatewayFailureCode] = {
        ToolCapability.WRITE_EXTERNAL: GatewayFailureCode.CAPABILITY_DENIED,
        ToolCapability.APPROVAL: GatewayFailureCode.CAPABILITY_DENIED,
    }
    for index, (capability, expected_code) in enumerate(denied_capabilities.items()):
        denied_adapter = _FixtureToolAdapter(fixture)
        denied_registry = GatewayRegistry(
            execution_mode=ExecutionMode.DEMO,
            sources=(source,),
            tool_adapters=(
                ToolAdapterRegistration(
                    tool_id=f"demo.denied_{index}",
                    capability=capability,
                    argument_names=("key",),
                    demo_only=True,
                    adapter=denied_adapter,
                ),
            ),
        )
        denied_result = ToolGateway(denied_registry).call(
            _tool_request(source, fixture.tool.lookup_key, tool_id=f"demo.denied_{index}")
        )
        _require_denied_tool(denied_result, expected_code)
        if denied_adapter.invocations:
            raise DemoExecutionError("A denied synthetic tool was invoked.")

    if len(model_adapter.invocations) != 1 or len(tool_adapter.invocations) != 1:
        raise DemoExecutionError("Synthetic gateway probe execution was not bounded.")

    return DemoReport(
        schema_version=DEMO_OUTPUT_SCHEMA_VERSION,
        fixture_version=fixture.fixture_version,
        fixture_sha256=FIXTURE_SHA256,
        execution_mode="DEMO",
        profile=profile,
        config_sha256=config_digest,
        model=model_hashes,
        tool=tool_hashes,
        negative_probes=_NegativeProbes(
            unknown_model="DENIED",
            secret_model="DENIED",
            private_model="DENIED",
            unknown_tool="DENIED",
            external_write_tool="DENIED",
            approval_tool="DENIED",
        ),
        credentials_used=False,
        external_effects=False,
        production_readiness=False,
    )


def run_demo() -> DemoReport:
    """Run the complete fixture flow, map any defect to a bounded safe failure."""

    try:
        return _run_verified_flow()
    except DemoExecutionError:
        raise
    except Exception:
        raise DemoExecutionError("The synthetic demo could not be verified.") from None
