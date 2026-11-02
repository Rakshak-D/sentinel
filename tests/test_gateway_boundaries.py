"""Boundary-envelope evidence tests for model and tool gateway calls."""

from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID

from sentinel.contracts import (
    BoundaryEnvelope,
    BoundaryKind,
    SensitivityLabel,
    SourceEnvelope,
    TrustLabel,
)
from sentinel.gateways.model import ModelGateway
from sentinel.gateways.registry import (
    GatewayRegistry,
    ModelAdapterRegistration,
    ToolAdapterRegistration,
)
from sentinel.gateways.tool import ToolGateway
from sentinel.gateways.types import (
    DemoPayload,
    ExecutionMode,
    ModelAdapterOutput,
    ModelInvocation,
    ModelLocality,
    ModelProfile,
    ModelRequest,
    ModelTaskClass,
    ToolAdapterOutput,
    ToolCapability,
    ToolInvocation,
    ToolRequest,
)

NOW = datetime(2026, 11, 2, 12, tzinfo=UTC)
MODEL_TEXT = "synthetic boundary input containing no secrets"
TOOL_TEXT = "synthetic source used for a local read"
SOURCE_ID = UUID("b3acfa6c-f6af-4a44-9b0b-2d8e11dc5f30")


def _source(text: str) -> SourceEnvelope:
    return SourceEnvelope(
        source_id=SOURCE_ID,
        provider_id="synthetic.fixture",
        content_sha256=sha256(text.encode("utf-8")).hexdigest(),
        observed_at=NOW,
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=SensitivityLabel.PUBLIC,
        parent_ids=(),
        byte_spans=(),
    )


class BoundaryModelAdapter:
    demo_only = True

    def __init__(self) -> None:
        self.invocation: ModelInvocation | None = None
        self.output_bytes = b"deterministic synthetic model output"

    def generate(self, invocation: ModelInvocation) -> ModelAdapterOutput:
        self.invocation = invocation
        return ModelAdapterOutput(output_bytes=self.output_bytes)


class BoundaryToolAdapter:
    demo_only = True

    def __init__(self) -> None:
        self.invocation: ToolInvocation | None = None
        self.output_bytes = b"synthetic read result"

    def call(self, invocation: ToolInvocation) -> ToolAdapterOutput:
        self.invocation = invocation
        return ToolAdapterOutput(output_bytes=self.output_bytes)


def _model_request() -> ModelRequest:
    digest = sha256(MODEL_TEXT.encode("utf-8")).hexdigest()
    return ModelRequest(
        call_id=UUID("362c043a-33b7-49bd-9339-801a88f6b6bf"),
        run_id=UUID("1c99b2b1-0c2e-436e-bfcf-932d7909e0ad"),
        adapter_id="demo.text",
        model_id="synthetic.text.v1",
        task_class=ModelTaskClass.SUMMARIZATION,
        prompt_id="demo.summary",
        prompt_version="1.0.0",
        prompt_sha256="3" * 64,
        input_schema_id="sentinel.text.v1",
        output_schema_id="sentinel.text.v1",
        source_ids=(SOURCE_ID,),
        sensitivity=SensitivityLabel.PUBLIC,
        payload_ref=f"sha256:{digest}",
        redaction_manifest_ref=None,
        config_sha256="4" * 64,
        temperature=0.0,
        max_output_tokens=64,
        deadline=datetime(2099, 1, 1, tzinfo=UTC),
        requested_profile=ModelProfile.LOCAL_ONLY,
        replay_mode=False,
    )


def _demo_payload() -> DemoPayload:
    return DemoPayload(
        payload_ref=f"sha256:{sha256(MODEL_TEXT.encode('utf-8')).hexdigest()}",
        payload_bytes=MODEL_TEXT.encode("utf-8"),
    )


def _tool_request() -> ToolRequest:
    return ToolRequest(
        call_id=UUID("f3ce0745-ec7e-4cd3-a58b-9f70a608cc2c"),
        run_id=UUID("c7957604-dd29-4857-a171-a8b80a70002e"),
        tool_id="demo.lookup",
        arguments=(("key", "beta"),),
        source_ids=(SOURCE_ID,),
        sensitivity=SensitivityLabel.PUBLIC,
    )


def test_model_boundary_hashes_exact_request_and_response_bytes() -> None:
    adapter = BoundaryModelAdapter()
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(MODEL_TEXT),),
        demo_payloads=(_demo_payload(),),
        model_adapters=(
            ModelAdapterRegistration(
                adapter_id="demo.text",
                provider_id="synthetic.memory",
                model_id="synthetic.text.v1",
                locality=ModelLocality.LOOPBACK,
                demo_only=True,
                adapter=adapter,
            ),
        ),
    )

    result = ModelGateway(registry).generate(_model_request())

    boundary = result.boundary
    assert isinstance(boundary, BoundaryEnvelope)
    assert boundary.kind is BoundaryKind.MODEL
    assert adapter.invocation is not None
    assert boundary.request_sha256 == sha256(adapter.invocation.request_bytes).hexdigest()
    assert adapter.invocation.payload_bytes == MODEL_TEXT.encode("utf-8")
    assert MODEL_TEXT.encode("utf-8") in adapter.invocation.request_bytes
    assert MODEL_TEXT not in adapter.invocation.request.model_dump_json()
    assert boundary.response_sha256 == sha256(adapter.output_bytes).hexdigest()
    assert boundary.request_ref == f"sha256:{boundary.request_sha256}"
    assert boundary.response_ref == f"sha256:{boundary.response_sha256}"
    assert boundary.source_ids == (SOURCE_ID,)


def test_tool_boundary_hashes_exact_request_and_response_bytes() -> None:
    adapter = BoundaryToolAdapter()
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(TOOL_TEXT),),
        tool_adapters=(
            ToolAdapterRegistration(
                tool_id="demo.lookup",
                capability=ToolCapability.READ_ONLY,
                argument_names=("key",),
                demo_only=True,
                adapter=adapter,
            ),
        ),
    )

    result = ToolGateway(registry).call(_tool_request())

    boundary = result.boundary
    assert isinstance(boundary, BoundaryEnvelope)
    assert boundary.kind is BoundaryKind.TOOL
    assert adapter.invocation is not None
    assert boundary.request_sha256 == sha256(adapter.invocation.request_bytes).hexdigest()
    assert boundary.response_sha256 == sha256(adapter.output_bytes).hexdigest()
    assert boundary.source_ids == (SOURCE_ID,)


def test_boundary_envelopes_contain_references_not_payloads_or_credentials() -> None:
    adapter = BoundaryModelAdapter()
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(MODEL_TEXT),),
        demo_payloads=(_demo_payload(),),
        model_adapters=(
            ModelAdapterRegistration(
                adapter_id="demo.text",
                provider_id="synthetic.memory",
                model_id="synthetic.text.v1",
                locality=ModelLocality.LOOPBACK,
                demo_only=True,
                adapter=adapter,
            ),
        ),
    )

    result = ModelGateway(registry).generate(_model_request())
    serialized = result.boundary.model_dump_json()

    assert MODEL_TEXT not in serialized
    assert "credential" not in serialized.lower()
    assert "payload" not in serialized.lower()
    assert result.boundary.request_ref.startswith("sha256:")
    assert result.boundary.response_ref is not None


def test_failure_boundary_has_no_response_digest_or_external_effect() -> None:
    class FailingModelAdapter(BoundaryModelAdapter):
        def generate(self, invocation: ModelInvocation) -> ModelAdapterOutput:
            self.invocation = invocation
            raise RuntimeError("private failure detail")

    adapter = FailingModelAdapter()
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(MODEL_TEXT),),
        demo_payloads=(_demo_payload(),),
        model_adapters=(
            ModelAdapterRegistration(
                adapter_id="demo.text",
                provider_id="synthetic.memory",
                model_id="synthetic.text.v1",
                locality=ModelLocality.LOOPBACK,
                demo_only=True,
                adapter=adapter,
            ),
        ),
    )

    result = ModelGateway(registry).generate(_model_request())

    assert result.failure is not None
    assert result.boundary is not None
    assert result.boundary.error_code == result.failure.code.value
    assert result.boundary.response_ref is None
    assert result.boundary.response_sha256 is None
    assert result.external_effect is False
    assert "private failure detail" not in result.failure.message


def test_synthetic_outputs_are_deterministic_for_the_same_fixture() -> None:
    first_adapter = BoundaryModelAdapter()
    second_adapter = BoundaryModelAdapter()
    first_registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(MODEL_TEXT),),
        demo_payloads=(_demo_payload(),),
        model_adapters=(
            ModelAdapterRegistration(
                adapter_id="demo.text",
                provider_id="synthetic.memory",
                model_id="synthetic.text.v1",
                locality=ModelLocality.LOOPBACK,
                demo_only=True,
                adapter=first_adapter,
            ),
        ),
    )
    second_registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(MODEL_TEXT),),
        demo_payloads=(_demo_payload(),),
        model_adapters=(
            ModelAdapterRegistration(
                adapter_id="demo.text",
                provider_id="synthetic.memory",
                model_id="synthetic.text.v1",
                locality=ModelLocality.LOOPBACK,
                demo_only=True,
                adapter=second_adapter,
            ),
        ),
    )

    first = ModelGateway(first_registry).generate(_model_request())
    second = ModelGateway(second_registry).generate(_model_request())

    assert first.response is not None and second.response is not None
    assert first.response.output == second.response.output
    assert first.boundary.request_sha256 == second.boundary.request_sha256
    assert first.boundary.response_sha256 == second.boundary.response_sha256
