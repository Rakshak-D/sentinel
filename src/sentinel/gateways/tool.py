"""Fail-closed CR0-D ToolGateway limited to registered synthetic read adapters."""

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from json import dumps
from uuid import uuid4

from sentinel.contracts import (
    BoundaryEnvelope,
    BoundaryKind,
    SensitivityLabel,
    SourceEnvelope,
    TrustLabel,
)
from sentinel.gateways.registry import GatewayRegistry, ToolAdapterRegistration
from sentinel.gateways.types import (
    GatewayFailureCode,
    ToolAdapterOutput,
    ToolCallResult,
    ToolCapability,
    ToolInvocation,
    ToolRequest,
    ToolResponse,
    canonical_json_bytes,
    safe_failure,
)

_SENSITIVITY_RANK = {
    SensitivityLabel.PUBLIC: 0,
    SensitivityLabel.INTERNAL: 1,
    SensitivityLabel.PRIVATE: 2,
    SensitivityLabel.SECRET: 3,
}


class ToolGateway:
    """The only tool-call surface in CR0-D; writes and approval actions remain OFF."""

    def __init__(self, registry: GatewayRegistry) -> None:
        if not isinstance(registry, GatewayRegistry):
            raise TypeError("ToolGateway requires a trusted GatewayRegistry")
        self.registry = registry

    def call(self, request: ToolRequest | Mapping[str, object]) -> ToolCallResult:
        """Validate and call one registered DEMO read-only adapter exactly once."""
        validated = self._validate_request(request)
        if validated is None:
            return ToolCallResult(
                response=None,
                failure=safe_failure(GatewayFailureCode.INVALID_REQUEST),
                boundary=None,
            )

        request_bytes = canonical_json_bytes(validated)
        registration = self.registry.find_tool(validated.tool_id)
        if registration is None:
            return self._fail(validated, GatewayFailureCode.UNKNOWN_TOOL, request_bytes)
        if registration.capability is not ToolCapability.READ_ONLY:
            return self._fail(validated, GatewayFailureCode.CAPABILITY_DENIED, request_bytes)
        if tuple(name for name, _value in validated.arguments) != registration.argument_names:
            return self._fail(validated, GatewayFailureCode.INVALID_REQUEST, request_bytes)

        sources = self.registry.resolve_sources(validated.source_ids)
        if sources is None or any(source.trust is TrustLabel.T5_UNKNOWN for source in sources):
            return self._fail(validated, GatewayFailureCode.PROVENANCE_INVALID, request_bytes)
        source_sensitivity = max(
            (source.sensitivity for source in sources),
            key=_SENSITIVITY_RANK.__getitem__,
        )
        if _SENSITIVITY_RANK[validated.sensitivity] < _SENSITIVITY_RANK[source_sensitivity]:
            return self._fail(validated, GatewayFailureCode.SENSITIVITY_DENIED, request_bytes)
        if validated.sensitivity is SensitivityLabel.SECRET:
            return self._fail(validated, GatewayFailureCode.SENSITIVITY_DENIED, request_bytes)

        invocation_bytes = self._invocation_bytes(validated, registration, sources)
        invocation = ToolInvocation(
            request=validated,
            sources=sources,
            capability=registration.capability,
            request_bytes=invocation_bytes,
        )
        request_digest = sha256(invocation_bytes).hexdigest()
        try:
            raw_output: object = registration.adapter.call(invocation)
        except Exception:
            return self._fail(
                validated,
                GatewayFailureCode.ADAPTER_FAILED,
                invocation_bytes,
                registration=registration,
                request_digest=request_digest,
                sources=sources,
            )
        try:
            output = self._validate_adapter_output(raw_output)
            output_text = output.output_bytes.decode("utf-8", errors="strict")
        except Exception:
            return self._fail(
                validated,
                GatewayFailureCode.ADAPTER_OUTPUT_INVALID,
                invocation_bytes,
                registration=registration,
                request_digest=request_digest,
                sources=sources,
            )

        output_digest = sha256(output.output_bytes).hexdigest()
        response = ToolResponse(
            output=output_text,
            result_ref=f"sha256:{output_digest}",
            source_ids=tuple(source.source_id for source in sources),
            source_trust=tuple(source.trust for source in sources),
            sensitivity=validated.sensitivity,
        )
        boundary = self._boundary(
            validated,
            registration.tool_id,
            sources,
            validated.sensitivity,
            request_digest,
            output.output_bytes,
            None,
        )
        return ToolCallResult(response=response, failure=None, boundary=boundary)

    @staticmethod
    def _validate_request(request: object) -> ToolRequest | None:
        try:
            raw: object
            if isinstance(request, ToolRequest):
                raw = dict(request.__dict__)
                if set(raw).difference(ToolRequest.model_fields) or request.model_extra:
                    return None
            elif isinstance(request, Mapping):
                raw = dict(request)
            else:
                return None
            return ToolRequest.model_validate(raw, strict=True)
        except Exception:
            return None

    @staticmethod
    def _validate_adapter_output(output: object) -> ToolAdapterOutput:
        if not isinstance(output, ToolAdapterOutput):
            raise TypeError("adapter output must use ToolAdapterOutput")
        raw = dict(output.__dict__)
        if set(raw).difference(ToolAdapterOutput.model_fields) or output.model_extra:
            raise ValueError("tool adapter output contains undeclared fields")
        return ToolAdapterOutput.model_validate(raw, strict=True)

    @staticmethod
    def _invocation_bytes(
        request: ToolRequest,
        registration: ToolAdapterRegistration,
        sources: tuple[SourceEnvelope, ...],
    ) -> bytes:
        payload = {
            "capability": registration.capability.value,
            "request": request.model_dump(mode="json"),
            "source_provenance": [
                {
                    "content_sha256": source.content_sha256,
                    "sensitivity": source.sensitivity.value,
                    "source_id": str(source.source_id),
                    "trust": source.trust.value,
                }
                for source in sources
            ],
            "tool_id": registration.tool_id,
        }
        return dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def _fail(
        self,
        request: ToolRequest,
        code: GatewayFailureCode,
        request_bytes: bytes,
        *,
        registration: ToolAdapterRegistration | None = None,
        request_digest: str | None = None,
        sources: tuple[SourceEnvelope, ...] = (),
    ) -> ToolCallResult:
        digest = request_digest or sha256(request_bytes).hexdigest()
        boundary = self._boundary(
            request,
            registration.tool_id if registration is not None else request.tool_id,
            sources,
            request.sensitivity,
            digest,
            None,
            code,
        )
        return ToolCallResult(response=None, failure=safe_failure(code), boundary=boundary)

    def _boundary(
        self,
        request: ToolRequest,
        adapter_id: str,
        sources: tuple[SourceEnvelope, ...],
        sensitivity: SensitivityLabel,
        request_digest: str,
        response_bytes: bytes | None,
        failure_code: GatewayFailureCode | None,
    ) -> BoundaryEnvelope:
        response_digest = sha256(response_bytes).hexdigest() if response_bytes is not None else None
        source_ids = tuple(source.source_id for source in sources) or request.source_ids
        return BoundaryEnvelope(
            boundary_id=uuid4(),
            run_id=request.run_id,
            seq=self.registry.next_sequence(request.run_id),
            kind=BoundaryKind.TOOL,
            adapter_id=adapter_id,
            request_ref=f"sha256:{request_digest}",
            response_ref=f"sha256:{response_digest}" if response_digest is not None else None,
            request_sha256=request_digest,
            response_sha256=response_digest,
            sensitivity=sensitivity,
            source_ids=source_ids,
            replay_injected=False,
            error_code=failure_code.value if failure_code is not None else None,
            created_at=datetime.now(UTC),
        )
