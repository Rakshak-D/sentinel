"""Behavioral tests for the credential-free packaged synthetic demo."""

import hashlib
import json
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

import sentinel.demo.runner as demo_runner
from sentinel.config import config_sha256, load_bundled_defaults
from sentinel.contracts import BoundaryKind
from sentinel.credentials import CredentialBroker
from sentinel.demo.runner import (
    DEMO_OUTPUT_SCHEMA_VERSION,
    FIXTURE_SHA256,
    FIXTURE_VERSION,
    DemoExecutionError,
    DemoFixture,
    DemoReport,
    load_packaged_fixture,
    parse_fixture_document,
    run_demo,
)
from sentinel.gateways.model import ModelGateway
from sentinel.gateways.tool import ToolGateway
from sentinel.gateways.types import GatewayFailureCode

EXPECTED_FIXTURE_SHA256 = "365c9f02f1375c3e784138b7cdb3c2fd3ed1a0f4cf64cfec6fdef2fe5d9ecbb8"


def _fixture_json() -> dict[str, Any]:
    fixture = load_packaged_fixture()
    assert isinstance(fixture, DemoFixture)
    return fixture.model_dump(mode="json")


def test_packaged_fixture_is_pinned_typed_and_public() -> None:
    fixture = load_packaged_fixture()

    assert isinstance(fixture, DemoFixture)
    assert fixture.fixture_version == FIXTURE_VERSION
    assert fixture.fixture_version == "sentinel.demo-fixture.v1"
    assert FIXTURE_SHA256 == EXPECTED_FIXTURE_SHA256
    assert fixture.source.sensitivity == "PUBLIC"
    assert len(fixture.source.content.encode("utf-8")) <= 2048
    assert fixture.model.expected_output == (
        f"{fixture.model.response_prefix}: {fixture.source.content}"
    )


def test_fixture_parser_rejects_unknown_fields_invalid_version_and_bad_structure() -> None:
    baseline = _fixture_json()
    unknown = json.loads(json.dumps(baseline))
    unknown["handler"] = "C:\\Windows\\System32\\cmd.exe"
    wrong_version = json.loads(json.dumps(baseline))
    wrong_version["fixture_version"] = "sentinel.demo-fixture.v999"
    malformed = {"fixture_version": FIXTURE_VERSION, "source": [], "model": {}, "tool": {}}
    mismatched_output = json.loads(json.dumps(baseline))
    mismatched_output["model"]["expected_output"] = "unrelated synthetic output"

    for candidate in (unknown, wrong_version, malformed, mismatched_output):
        with pytest.raises(ValueError):
            parse_fixture_document(
                json.dumps(candidate, ensure_ascii=False, sort_keys=True).encode("utf-8")
            )


def test_fixture_parser_rejects_duplicate_keys_and_invalid_utf8() -> None:
    with pytest.raises(ValueError):
        parse_fixture_document(
            b'{"fixture_version":"sentinel.demo-fixture.v1",'
            b'"fixture_version":"sentinel.demo-fixture.v1"}'
        )
    with pytest.raises(ValueError):
        parse_fixture_document(b"\xff")


def test_fixture_resource_loads_independently_of_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    fixture = load_packaged_fixture()

    assert isinstance(fixture, DemoFixture)
    assert fixture.fixture_version == FIXTURE_VERSION


def test_missing_or_modified_packaged_fixture_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(demo_runner, "_read_fixture_resource", lambda: b"{}")
    with pytest.raises(DemoExecutionError):
        run_demo()


def test_missing_packaged_fixture_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_resource() -> bytes:
        raise FileNotFoundError("synthetic missing fixture")

    monkeypatch.setattr(demo_runner, "_read_fixture_resource", missing_resource)
    with pytest.raises(DemoExecutionError):
        run_demo()


def test_demo_executes_both_gateways_and_reports_real_boundary_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_invocations: list[object] = []
    tool_invocations: list[object] = []
    model_gateway_calls: list[tuple[object, object]] = []
    tool_gateway_calls: list[tuple[object, object]] = []

    model_adapter = demo_runner._FixtureModelAdapter.generate
    tool_adapter = demo_runner._FixtureToolAdapter.call
    model_gateway = ModelGateway.generate
    tool_gateway = ToolGateway.call

    def model_adapter_spy(adapter: object, invocation: object) -> object:
        model_invocations.append(invocation)
        return model_adapter(adapter, invocation)

    def tool_adapter_spy(adapter: object, invocation: object) -> object:
        tool_invocations.append(invocation)
        return tool_adapter(adapter, invocation)

    def model_gateway_spy(gateway: object, request: object) -> object:
        result = model_gateway(gateway, request)
        model_gateway_calls.append((request, result))
        return result

    def tool_gateway_spy(gateway: object, request: object) -> object:
        result = tool_gateway(gateway, request)
        tool_gateway_calls.append((request, result))
        return result

    monkeypatch.setattr(demo_runner._FixtureModelAdapter, "generate", model_adapter_spy)
    monkeypatch.setattr(demo_runner._FixtureToolAdapter, "call", tool_adapter_spy)
    monkeypatch.setattr(ModelGateway, "generate", model_gateway_spy)
    monkeypatch.setattr(ToolGateway, "call", tool_gateway_spy)

    report = run_demo()
    output = json.loads(report.to_json_bytes())
    fixture = load_packaged_fixture()
    assert isinstance(fixture, DemoFixture)

    assert isinstance(report, DemoReport)
    assert len(model_gateway_calls) == 4
    assert len(tool_gateway_calls) == 4
    assert model_gateway_calls[1][1].failure.code is GatewayFailureCode.UNKNOWN_MODEL
    assert model_gateway_calls[2][1].failure.code is GatewayFailureCode.SENSITIVITY_DENIED
    assert model_gateway_calls[3][1].failure.code is GatewayFailureCode.SENSITIVITY_DENIED
    assert tool_gateway_calls[1][1].failure.code is GatewayFailureCode.UNKNOWN_TOOL
    assert tool_gateway_calls[2][1].failure.code is GatewayFailureCode.CAPABILITY_DENIED
    assert tool_gateway_calls[3][1].failure.code is GatewayFailureCode.CAPABILITY_DENIED
    assert len(model_invocations) == 1
    assert len(tool_invocations) == 1
    model_invocation = model_invocations[0]
    tool_invocation = tool_invocations[0]
    assert model_invocation.sources[0].sensitivity.value == "PUBLIC"
    assert model_invocation.model_id == "synthetic/demo-v1"
    assert model_invocation.sources[0].source_id == fixture.source.source_id
    assert model_gateway_calls[0][1].response.provider_model_id == "synthetic/demo-v1"
    assert model_invocation.payload_bytes == fixture.source.content.encode("utf-8")
    assert model_invocation.sources[0].content_sha256 == hashlib.sha256(
        fixture.source.content.encode("utf-8")
    ).hexdigest()
    expected_model_bytes = fixture.model.expected_output.encode("utf-8")
    expected_tool_bytes = fixture.tool.lookup_value.encode("utf-8")
    assert model_gateway_calls[0][1].response.output.encode("utf-8") == expected_model_bytes
    assert tool_gateway_calls[0][1].response.output.encode("utf-8") == expected_tool_bytes
    assert model_gateway_calls[0][1].external_effect is False
    assert tool_gateway_calls[0][1].external_effect is False
    assert output["model"]["request_sha256"] == hashlib.sha256(
        model_invocation.request_bytes
    ).hexdigest()
    assert output["model"]["response_sha256"] == hashlib.sha256(expected_model_bytes).hexdigest()
    assert output["tool"]["request_sha256"] == hashlib.sha256(
        tool_invocation.request_bytes
    ).hexdigest()
    assert output["tool"]["response_sha256"] == hashlib.sha256(expected_tool_bytes).hexdigest()
    assert model_gateway_calls[0][1].boundary.kind is BoundaryKind.MODEL
    assert tool_gateway_calls[0][1].boundary.kind is BoundaryKind.TOOL
    assert output["config_sha256"] == config_sha256(load_bundled_defaults())
    assert output["schema_version"] == DEMO_OUTPUT_SCHEMA_VERSION
    assert output["fixture_version"] == FIXTURE_VERSION
    assert output["fixture_sha256"] == EXPECTED_FIXTURE_SHA256
    assert output["execution_mode"] == "DEMO"
    assert output["profile"] == "local-only"
    assert output["credentials_used"] is False
    assert output["external_effects"] is False
    assert output["production_readiness"] is False
    assert set(output["negative_probes"].values()) == {"DENIED"}
    for private_value in (
        fixture.source.content,
        fixture.model.response_prefix,
        fixture.tool.lookup_value,
        "SYNTHETIC_SECRET_INPUT_CANARY",
        "SYNTHETIC_PRIVATE_INPUT_CANARY",
    ):
        assert private_value not in report.to_json_bytes().decode("utf-8")


def test_demo_is_deterministic_and_has_no_filesystem_or_external_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    before = set(tmp_path.iterdir())

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network, subprocess, or credential access is forbidden")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(CredentialBroker, "status", forbidden)
    monkeypatch.setattr(CredentialBroker, "resolve_for_test", forbidden)

    first = run_demo().to_json_bytes()
    second = run_demo().to_json_bytes()

    assert first == second
    assert first.endswith(b"}")
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("adapter_name", ["_FixtureModelAdapter", "_FixtureToolAdapter"])
def test_adapter_failure_fails_closed_without_exposing_exception(
    monkeypatch: pytest.MonkeyPatch, adapter_name: str
) -> None:
    adapter_type = getattr(demo_runner, adapter_name)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("SYNTHETIC_FAILURE_CANARY")

    method_name = "generate" if adapter_name == "_FixtureModelAdapter" else "call"
    monkeypatch.setattr(adapter_type, method_name, fail)

    with pytest.raises(DemoExecutionError) as raised:
        run_demo()

    assert "SYNTHETIC_FAILURE_CANARY" not in str(raised.value)


def test_failed_negative_probe_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    original = ModelGateway.generate
    successful_result: list[object] = []

    def forge_negative_success(gateway: object, request: object) -> object:
        result = original(gateway, request)
        if getattr(request, "model_id", None) == "synthetic/unregistered-demo-v1":
            assert successful_result
            return successful_result[0]
        if getattr(result, "failure", None) is None:
            successful_result.append(result)
        return result

    monkeypatch.setattr(ModelGateway, "generate", forge_negative_success)

    with pytest.raises(DemoExecutionError):
        run_demo()


def test_failed_tool_negative_probe_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    original = ToolGateway.call
    successful_result: list[object] = []

    def forge_negative_success(gateway: object, request: object) -> object:
        result = original(gateway, request)
        if getattr(request, "tool_id", None) == "demo.unregistered":
            assert successful_result
            return successful_result[0]
        if getattr(result, "failure", None) is None:
            successful_result.append(result)
        return result

    monkeypatch.setattr(ToolGateway, "call", forge_negative_success)

    with pytest.raises(DemoExecutionError):
        run_demo()
