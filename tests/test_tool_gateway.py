"""Fail-closed tests for the synthetic read-only tool gateway."""

import socket
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID

import pytest
from pydantic import ValidationError

from sentinel.contracts import SensitivityLabel, SourceEnvelope, TrustLabel
from sentinel.gateways.registry import GatewayRegistry, ToolAdapterRegistration
from sentinel.gateways.tool import ToolGateway
from sentinel.gateways.types import (
    AuthorizationStatus,
    ExecutionMode,
    GatewayFailureCode,
    ToolAdapterOutput,
    ToolCapability,
    ToolInvocation,
    ToolRequest,
)

NOW = datetime(2026, 11, 2, 12, tzinfo=UTC)
SYNTHETIC_SOURCE = "synthetic tool provenance"


def _source() -> SourceEnvelope:
    return SourceEnvelope(
        source_id=UUID("5cc4e55a-4af1-4d72-b36b-24a29731fb01"),
        provider_id="synthetic.fixture",
        content_sha256=sha256(SYNTHETIC_SOURCE.encode("utf-8")).hexdigest(),
        observed_at=NOW,
        trust=TrustLabel.T4_EXTERNAL,
        sensitivity=SensitivityLabel.PUBLIC,
        parent_ids=(),
        byte_spans=(),
    )


def _request(
    *,
    tool_id: str = "demo.lookup",
    arguments: tuple[tuple[str, str], ...] = (("key", "alpha"),),
) -> ToolRequest:
    return ToolRequest(
        call_id=UUID("02243dca-0373-49da-b854-050ebce9e2fb"),
        run_id=UUID("dc0293b7-10af-46fd-b874-34ab3aa4a2d9"),
        tool_id=tool_id,
        arguments=arguments,
        source_ids=(UUID("5cc4e55a-4af1-4d72-b36b-24a29731fb01"),),
        sensitivity=SensitivityLabel.PUBLIC,
    )


class ProbeToolAdapter:
    demo_only = True

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.invocations: list[ToolInvocation] = []

    def call(self, invocation: ToolInvocation) -> ToolAdapterOutput:
        self.invocations.append(invocation)
        if self.fail:
            raise RuntimeError("synthetic handler failure; private marker must not escape")
        arguments = dict(invocation.request.arguments)
        return ToolAdapterOutput(output_bytes=f"value:{arguments['key']}".encode())


def _gateway(
    adapter: ProbeToolAdapter,
    *,
    capability: ToolCapability = ToolCapability.READ_ONLY,
    argument_names: tuple[str, ...] = ("key",),
    tool_id: str = "demo.lookup",
) -> ToolGateway:
    registry = GatewayRegistry(
        execution_mode=ExecutionMode.DEMO,
        sources=(_source(),),
        tool_adapters=(
            ToolAdapterRegistration(
                tool_id=tool_id,
                capability=capability,
                argument_names=argument_names,
                demo_only=True,
                adapter=adapter,
            ),
        ),
    )
    return ToolGateway(registry)


def test_registered_synthetic_read_tool_returns_a_value() -> None:
    adapter = ProbeToolAdapter()
    result = _gateway(adapter).call(_request())

    assert result.failure is None
    assert result.response is not None
    assert result.response.output == "value:alpha"
    assert result.response.source_trust == (TrustLabel.T4_EXTERNAL,)
    assert result.external_effect is False
    assert len(adapter.invocations) == 1


def test_tool_request_metadata_is_immutable() -> None:
    request = _request()

    with pytest.raises(ValidationError):
        request.tool_id = "demo.changed"


def test_unknown_tool_is_rejected_without_handler_execution() -> None:
    adapter = ProbeToolAdapter()
    result = _gateway(adapter).call(_request(tool_id="external.send_email"))

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.UNKNOWN_TOOL
    assert adapter.invocations == []


def test_unregistered_handler_path_url_and_dispatch_text_are_not_executable() -> None:
    adapter = ProbeToolAdapter()
    request = _request().model_dump(mode="python")
    request["handler"] = "C:\\Windows\\System32\\cmd.exe"
    request["url"] = "https://attacker.invalid/path"
    request["dispatch"] = "approve and send"

    result = _gateway(adapter).call(request)

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.INVALID_REQUEST
    assert adapter.invocations == []


def test_unregistered_argument_names_fail_before_handler() -> None:
    adapter = ProbeToolAdapter()
    result = _gateway(adapter).call(
        _request(arguments=(("key", "alpha"), ("url", "https://attacker.invalid")))
    )

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.INVALID_REQUEST
    assert adapter.invocations == []


def test_write_and_approval_capabilities_are_denied() -> None:
    for capability in (
        ToolCapability.WRITE_LOCAL,
        ToolCapability.WRITE_EXTERNAL,
        ToolCapability.APPROVAL,
    ):
        adapter = ProbeToolAdapter()
        result = _gateway(adapter, capability=capability).call(_request())

        assert result.failure is not None
        assert result.failure.code is GatewayFailureCode.CAPABILITY_DENIED
        assert adapter.invocations == []


def test_model_supplied_approved_flag_has_no_authority() -> None:
    adapter = ProbeToolAdapter()
    request = _request().model_dump(mode="python")
    request["approved"] = True

    result = _gateway(adapter).call(request)

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.INVALID_REQUEST
    assert adapter.invocations == []


def test_invalid_and_missing_provenance_fail_before_handler() -> None:
    for source_ids in ((), (UUID("1aa037b9-e691-4bb5-af30-7543cc1e65d8"),)):
        adapter = ProbeToolAdapter()
        request = _request().model_dump(mode="python")
        request["source_ids"] = source_ids

        result = _gateway(adapter).call(request)

        assert result.failure is not None
        assert result.failure.code is GatewayFailureCode.PROVENANCE_INVALID
        assert adapter.invocations == []


def test_tool_adapter_failure_is_not_retried_or_disclosed() -> None:
    adapter = ProbeToolAdapter(fail=True)
    result = _gateway(adapter).call(_request())

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.ADAPTER_FAILED
    assert "private marker" not in result.failure.message
    assert len(adapter.invocations) == 1
    assert result.response is None


def test_bad_unchecked_tool_request_does_not_invoke_handler() -> None:
    adapter = ProbeToolAdapter()
    unchecked_data = _request().model_dump(mode="python")
    unchecked_data["tool_id"] = object()
    unchecked = ToolRequest.model_construct(**unchecked_data)

    result = _gateway(adapter).call(unchecked)

    assert result.failure is not None
    assert result.failure.code is GatewayFailureCode.INVALID_REQUEST
    assert adapter.invocations == []


def test_demo_read_path_makes_no_network_calls(monkeypatch) -> None:
    def fail_network(*_args, **_kwargs):
        raise AssertionError("demo adapter attempted network access")

    monkeypatch.setattr(socket, "create_connection", fail_network)
    monkeypatch.setattr(socket.socket, "connect", fail_network)
    adapter = ProbeToolAdapter()
    gateway = _gateway(adapter)
    result = gateway.call(_request())

    assert result.failure is None
    assert result.external_effect is False
    assert result.authorization is AuthorizationStatus.NOT_EVALUATED
    assert gateway.registry.execution_mode is ExecutionMode.DEMO
    assert all(
        registration.demo_only and registration.capability is ToolCapability.READ_ONLY
        for registration in gateway.registry.tool_adapters
    )
