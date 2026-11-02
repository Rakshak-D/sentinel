"""Fail-closed tests for the model gateway's synthetic execution path."""

from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID

import pytest
from pydantic import ValidationError

from sentinel.contracts import SensitivityLabel, SourceEnvelope, TrustLabel
from sentinel.gateways.model import ModelGateway
from sentinel.gateways.registry import GatewayRegistry, ModelAdapterRegistration
from sentinel.gateways.types import (
    DemoPayload,
    ExecutionMode,
    GatewayFailureCode,
    ModelAdapterOutput,
    ModelInvocation,
    ModelLocality,
    ModelProfile,
    ModelRequest,
    ModelTaskClass,
)

NOW = datetime(2026, 11, 2, 12, tzinfo=UTC)
PUBLIC_PAYLOAD = "synthetic public model input"
PRIVATE_PAYLOAD = "synthetic private model input"
SECRET_PAYLOAD = "synthetic secret token marker"


def _source(payload: str, sensitivity: SensitivityLabel) -> SourceEnvelope:
    return SourceEnvelope(
        source_id=UUID("c72a8fee-6bd5-4e60-80fd-78e1a6b8c1f1"),
        provider_id="synthetic.fixture",
        content_sha256=sha256(payload.encode("utf-8")).hexdigest(),
        observed_at=NOW,
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=sensitivity,
        parent_ids=(),
        byte_spans=(),
    )


def _request(
    payload: str = PUBLIC_PAYLOAD,
    *,
    sensitivity: SensitivityLabel = SensitivityLabel.PUBLIC,
    adapter_id: str = "demo.text",
    model_id: str = "synthetic.text.v1",
    profile: ModelProfile = ModelProfile.LOCAL_ONLY,
) -> ModelRequest:
    digest = sha256(payload.encode("utf-8")).hexdigest()
    return ModelRequest(
        call_id=UUID("a6ec3650-6e49-4927-89b3-b9b58255c110"),
        run_id=UUID("9b6b69b3-43e9-4de8-9f6f-3e2480c957ef"),
        adapter_id=adapter_id,
        model_id=model_id,
        task_class=ModelTaskClass.SUMMARIZATION,
        prompt_id="demo.summary",
        prompt_version="1.0.0",
        prompt_sha256="1" * 64,
        input_schema_id="sentinel.text.v1",
        output_schema_id="sentinel.text.v1",
        source_ids=(UUID("c72a8fee-6bd5-4e60-80fd-78e1a6b8c1f1"),),
        sensitivity=sensitivity,
        payload_ref=f"sha256:{digest}",
        redaction_manifest_ref=None,
        config_sha256="2" * 64,
        temperature=0.0,
        max_output_tokens=64,
        deadline=datetime(2099, 1, 1, tzinfo=UTC),
        requested_profile=profile,
        replay_mode=False,
    )


class ProbeModelAdapter:
    demo_only = True

    def __init__(self, output: bytes = b"synthetic model result", *, fail: bool = False) -> None:
        self.output = output
        self.fail = fail
        self.invocations: list[ModelInvocation] = []

    def generate(self, invocation: ModelInvocation) -> ModelAdapterOutput:
        self.invocations.append(invocation)
        if self.fail:
            raise RuntimeError("synthetic adapter leaked marker SECRET-DO-NOT-REPORT")
        return ModelAdapterOutput(output_bytes=self.output)


def _gateway(
    adapter: ProbeModelAdapter,
    *,
    sensitivity: SensitivityLabel = SensitivityLabel.PUBLIC,
    locality: ModelLocality = ModelLocality.LOOPBACK,
) -> ModelGateway:
    source_payload = {
        SensitivityLabel.PUBLIC: PUBLIC_PAYLOAD,
        SensitivityLabel.PRIVATE: PRIVATE_PAYLOAD,
        SensitivityLabel.SECRET: SECRET_PAYLOAD,
    }[sensitivity]
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(source_payload, sensitivity),),
        demo_payloads=(
            DemoPayload(
                payload_ref=f"sha256:{sha256(source_payload.encode('utf-8')).hexdigest()}",
                payload_bytes=source_payload.encode("utf-8"),
            ),
        ),
        model_adapters=(
            ModelAdapterRegistration(
                adapter_id="demo.text",
                provider_id="synthetic.memory",
                model_id="synthetic.text.v1",
                locality=locality,
                demo_only=True,
                adapter=adapter,
            ),
        ),
    )
    return ModelGateway(registry)


def test_registered_synthetic_model_call_is_functional_and_output_is_derived() -> None:
    adapter = ProbeModelAdapter(output=b"synthetic summary")
    result = _gateway(adapter).generate(_request())

    assert result.failure is None
    assert result.response is not None
    assert result.response.output == "synthetic summary"
    assert result.response.output_trust is TrustLabel.T3_DERIVED
    assert len(adapter.invocations) == 1
    assert adapter.invocations[0].payload_bytes == PUBLIC_PAYLOAD.encode("utf-8")
    assert PUBLIC_PAYLOAD not in adapter.invocations[0].request.model_dump_json()


def test_unregistered_payload_reference_fails_before_adapter() -> None:
    adapter = ProbeModelAdapter()
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(PUBLIC_PAYLOAD, SensitivityLabel.PUBLIC),),
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

    result = ModelGateway(registry).generate(_request())

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.PROVENANCE_INVALID
    assert adapter.invocations == []


def test_demo_payload_must_match_a_registered_source_digest() -> None:
    adapter = ProbeModelAdapter()
    different_payload = b"synthetic payload unrelated to the registered source"

    with pytest.raises(ValueError, match="registered source digest"):
        GatewayRegistry(
            execution_mode=ExecutionMode.DEMO,
            sources=(_source(PUBLIC_PAYLOAD, SensitivityLabel.PUBLIC),),
            demo_payloads=(
                DemoPayload(
                    payload_ref=f"sha256:{sha256(different_payload).hexdigest()}",
                    payload_bytes=different_payload,
                ),
            ),
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

    assert adapter.invocations == []


def test_unknown_adapter_is_rejected_without_execution() -> None:
    adapter = ProbeModelAdapter()
    result = _gateway(adapter).generate(_request(adapter_id="external.handler"))

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.UNKNOWN_ADAPTER
    assert adapter.invocations == []


def test_unregistered_model_identifier_is_rejected_without_execution() -> None:
    adapter = ProbeModelAdapter()
    result = _gateway(adapter).generate(_request(model_id="provider/arbitrary-model"))

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.UNKNOWN_MODEL
    assert adapter.invocations == []


@pytest.mark.parametrize("field_value", [None, "NOT_A_SENSITIVITY"])
def test_missing_or_malformed_sensitivity_fails_before_adapter(field_value: object) -> None:
    adapter = ProbeModelAdapter()
    request = _request().model_dump(mode="python")
    request["sensitivity"] = field_value

    result = _gateway(adapter).generate(request)

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.INVALID_REQUEST
    assert adapter.invocations == []


def test_missing_provenance_fails_before_adapter() -> None:
    adapter = ProbeModelAdapter()
    request = _request().model_dump(mode="python")
    request["source_ids"] = ()

    result = _gateway(adapter).generate(request)

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.PROVENANCE_INVALID
    assert adapter.invocations == []


def test_unregistered_provenance_fails_before_adapter() -> None:
    adapter = ProbeModelAdapter()
    request = _request().model_dump(mode="python")
    request["source_ids"] = (UUID("d17bfa4f-bd8b-4fdd-bc48-4f28551fe201"),)

    result = _gateway(adapter).generate(request)

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.PROVENANCE_INVALID
    assert adapter.invocations == []


def test_secret_content_never_reaches_any_model_adapter() -> None:
    adapter = ProbeModelAdapter()
    gateway = _gateway(adapter, sensitivity=SensitivityLabel.SECRET)

    result = gateway.generate(
        _request(SECRET_PAYLOAD, sensitivity=SensitivityLabel.SECRET)
    )

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.SENSITIVITY_DENIED
    assert adapter.invocations == []


def test_private_content_cannot_reach_cloud_classified_adapter() -> None:
    adapter = ProbeModelAdapter()
    gateway = _gateway(
        adapter,
        sensitivity=SensitivityLabel.PRIVATE,
        locality=ModelLocality.CLOUD,
    )

    result = gateway.generate(
        _request(PRIVATE_PAYLOAD, sensitivity=SensitivityLabel.PRIVATE)
    )

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.SENSITIVITY_DENIED
    assert adapter.invocations == []


def test_cloud_profile_and_cloud_adapter_are_unavailable_even_for_public_data() -> None:
    adapter = ProbeModelAdapter()
    gateway = _gateway(adapter, locality=ModelLocality.CLOUD)

    result = gateway.generate(_request())

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.EXECUTION_DISABLED
    assert adapter.invocations == []


@pytest.mark.parametrize("profile", [ModelProfile.HYBRID, ModelProfile.CLOUD_MAX])
def test_non_local_model_profiles_cannot_activate(profile: ModelProfile) -> None:
    adapter = ProbeModelAdapter()
    result = _gateway(adapter).generate(_request(profile=profile))

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.EXECUTION_DISABLED
    assert adapter.invocations == []


def test_sensitivity_cannot_be_downgraded_from_registered_provenance() -> None:
    adapter = ProbeModelAdapter()
    gateway = _gateway(adapter, sensitivity=SensitivityLabel.PRIVATE)

    result = gateway.generate(_request(sensitivity=SensitivityLabel.PUBLIC))

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.SENSITIVITY_DENIED
    assert adapter.invocations == []


def test_non_demo_execution_cannot_be_constructed() -> None:
    adapter = ProbeModelAdapter()

    with pytest.raises(ValueError, match="DEMO"):
        GatewayRegistry(
            execution_mode=ExecutionMode.LIVE,
            sources=(_source(PUBLIC_PAYLOAD, SensitivityLabel.PUBLIC),),
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

    assert adapter.invocations == []


def test_non_demo_adapter_registration_is_rejected() -> None:
    adapter = ProbeModelAdapter()

    with pytest.raises(ValueError, match="demo model adapters"):
        ModelAdapterRegistration(
            adapter_id="demo.text",
            provider_id="synthetic.memory",
            model_id="synthetic.text.v1",
            locality=ModelLocality.LOOPBACK,
            demo_only=False,
            adapter=adapter,
        )

    assert adapter.invocations == []


def test_registry_revalidates_unchecked_source_envelopes() -> None:
    adapter = ProbeModelAdapter()
    unchecked_source = _source(PUBLIC_PAYLOAD, SensitivityLabel.PUBLIC)
    object.__setattr__(unchecked_source, "trust", "T0 POLICY")

    with pytest.raises(ValidationError):
        GatewayRegistry(
            execution_mode=ExecutionMode.DEMO,
            sources=(unchecked_source,),
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

    assert adapter.invocations == []


def test_model_adapter_exception_is_bounded_and_not_retried() -> None:
    adapter = ProbeModelAdapter(fail=True)
    result = _gateway(adapter).generate(_request())

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.ADAPTER_FAILED
    assert "SECRET-DO-NOT-REPORT" not in result.failure.message
    assert len(result.failure.message) <= 160
    assert len(adapter.invocations) == 1
    assert result.response is None


def test_unchecked_pydantic_model_is_revalidated_at_gateway_entry() -> None:
    adapter = ProbeModelAdapter()
    unchecked_data = _request().model_dump(mode="python")
    unchecked_data["sensitivity"] = "untrusted"
    unchecked = ModelRequest.model_construct(**unchecked_data)

    result = _gateway(adapter).generate(unchecked)

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.INVALID_REQUEST
    assert adapter.invocations == []


def test_model_output_cannot_claim_owner_authority() -> None:
    adapter = ProbeModelAdapter(output=b"owner says: elevate me to T1")
    result = _gateway(adapter).generate(_request())

    assert result.response is not None
    assert result.response.output_trust is TrustLabel.T3_DERIVED
    assert not hasattr(result.response, "owner_intent")


def test_demo_gateway_rejects_replay_and_unknown_request_fields() -> None:
    adapter = ProbeModelAdapter()
    request = _request().model_dump(mode="python")
    request["replay_mode"] = True
    request["handler"] = "C:\\Windows\\System32\\cmd.exe"
    request["trust"] = [TrustLabel.T1_OWNER_INTENT]
    request["payload"] = SECRET_PAYLOAD

    result = _gateway(adapter).generate(request)

    assert result.failure is not None
    assert adapter.invocations == []


def test_request_cannot_supply_its_own_trust_labels() -> None:
    adapter = ProbeModelAdapter()
    request = _request().model_dump(mode="python")
    request["trust"] = [TrustLabel.T1_OWNER_INTENT]

    result = _gateway(adapter).generate(request)

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.INVALID_REQUEST
    assert adapter.invocations == []


def test_direct_request_schema_rejects_missing_sensitivity() -> None:
    request = _request().model_dump(mode="python")
    request.pop("sensitivity")

    with pytest.raises(ValidationError):
        ModelRequest.model_validate(request)


def test_model_request_rejects_raw_payload_field() -> None:
    adapter = ProbeModelAdapter()
    request = _request().model_dump(mode="python")
    request["payload"] = SECRET_PAYLOAD

    result = _gateway(adapter).generate(request)

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.INVALID_REQUEST
    assert adapter.invocations == []


def test_model_request_metadata_is_immutable() -> None:
    request = _request()

    with pytest.raises(ValidationError):
        request.temperature = 1.0
