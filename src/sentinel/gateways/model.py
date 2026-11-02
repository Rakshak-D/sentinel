"""Fail-closed CR0-D ModelGateway with an explicit synthetic-only path."""

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from time import perf_counter_ns
from uuid import uuid4

from sentinel.contracts import (
    BoundaryEnvelope,
    BoundaryKind,
    SensitivityLabel,
    SourceEnvelope,
    TrustLabel,
)
from sentinel.gateways.registry import GatewayRegistry, ModelAdapterRegistration
from sentinel.gateways.types import (
    GatewayFailureCode,
    ModelAdapterOutput,
    ModelCallResult,
    ModelInvocation,
    ModelLocality,
    ModelRequest,
    ModelResponse,
    canonical_json_bytes,
    safe_failure,
)

_SENSITIVITY_RANK = {
    SensitivityLabel.PUBLIC: 0,
    SensitivityLabel.INTERNAL: 1,
    SensitivityLabel.PRIVATE: 2,
    SensitivityLabel.SECRET: 3,
}
_SUPPORTED_TEXT_SCHEMA = "sentinel.text.v1"


class ModelGateway:
    """The only model call surface in CR0-D; all registry entries are trusted demo code."""

    def __init__(self, registry: GatewayRegistry) -> None:
        if not isinstance(registry, GatewayRegistry):
            raise TypeError("ModelGateway requires a trusted GatewayRegistry")
        self.registry = registry

    def generate(self, request: ModelRequest | Mapping[str, object]) -> ModelCallResult:
        """Validate and execute one registered synthetic text adapter call.

        This method does not authorize requests. It rejects live, replay, cloud,
        non-PUBLIC, unsupported-schema, unregistered, and provenance-invalid calls.
        """
        validated = self._validate_request(request)
        if validated is None:
            return ModelCallResult(
                response=None,
                failure=safe_failure(GatewayFailureCode.INVALID_REQUEST),
                boundary=None,
            )

        request_bytes = canonical_json_bytes(validated)
        if validated.replay_mode:
            return self._fail(validated, GatewayFailureCode.REPLAY_UNAVAILABLE, request_bytes)
        if validated.deadline <= datetime.now(UTC):
            return self._fail(validated, GatewayFailureCode.DEADLINE_EXPIRED, request_bytes)
        if (
            validated.input_schema_id != _SUPPORTED_TEXT_SCHEMA
            or validated.output_schema_id != _SUPPORTED_TEXT_SCHEMA
        ):
            return self._fail(validated, GatewayFailureCode.SCHEMA_UNSUPPORTED, request_bytes)
        if validated.requested_profile.value != "local-only":
            return self._fail(validated, GatewayFailureCode.EXECUTION_DISABLED, request_bytes)

        registration = self.registry.find_model_adapter(
            validated.adapter_id, validated.model_id
        )
        if registration is None:
            code = (
                GatewayFailureCode.UNKNOWN_MODEL
                if self.registry.has_model_adapter(validated.adapter_id)
                else GatewayFailureCode.UNKNOWN_ADAPTER
            )
            return self._fail(validated, code, request_bytes)

        sources = self.registry.resolve_sources(validated.source_ids)
        if sources is None or any(source.trust is TrustLabel.T5_UNKNOWN for source in sources):
            return self._fail(validated, GatewayFailureCode.PROVENANCE_INVALID, request_bytes)

        source_sensitivity = max(
            (source.sensitivity for source in sources),
            key=_SENSITIVITY_RANK.__getitem__,
        )
        if validated.sensitivity is not source_sensitivity:
            return self._fail(validated, GatewayFailureCode.SENSITIVITY_DENIED, request_bytes)
        payload_digest = validated.payload_ref.removeprefix("sha256:")
        if not any(source.content_sha256 == payload_digest for source in sources):
            return self._fail(validated, GatewayFailureCode.PROVENANCE_INVALID, request_bytes)
        if validated.sensitivity is SensitivityLabel.SECRET:
            return self._fail(validated, GatewayFailureCode.SENSITIVITY_DENIED, request_bytes)
        if (
            validated.sensitivity is SensitivityLabel.PRIVATE
            and registration.locality is ModelLocality.CLOUD
        ):
            return self._fail(validated, GatewayFailureCode.SENSITIVITY_DENIED, request_bytes)
        if validated.sensitivity is not SensitivityLabel.PUBLIC:
            return self._fail(validated, GatewayFailureCode.SENSITIVITY_DENIED, request_bytes)
        if registration.locality is ModelLocality.CLOUD:
            return self._fail(validated, GatewayFailureCode.EXECUTION_DISABLED, request_bytes)

        demo_payload = self.registry.resolve_demo_payload(validated.payload_ref)
        if demo_payload is None:
            return self._fail(validated, GatewayFailureCode.PROVENANCE_INVALID, request_bytes)
        if not any(
            source.content_sha256 == demo_payload.payload_ref.removeprefix("sha256:")
            for source in sources
        ):
            return self._fail(validated, GatewayFailureCode.PROVENANCE_INVALID, request_bytes)

        invocation_bytes = self._invocation_bytes(
            validated, registration, sources, demo_payload.payload_bytes
        )
        invocation = ModelInvocation(
            request=validated,
            sources=sources,
            provider_id=registration.provider_id,
            model_id=registration.model_id,
            adapter_id=registration.adapter_id,
            locality=registration.locality,
            payload_bytes=demo_payload.payload_bytes,
            request_bytes=invocation_bytes,
        )
        request_digest = sha256(invocation_bytes).hexdigest()
        started = perf_counter_ns()
        try:
            raw_output: object = registration.adapter.generate(invocation)
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
        elapsed_ms = max(0, (perf_counter_ns() - started) // 1_000_000)
        response = ModelResponse(
            provider_id=registration.provider_id,
            provider_model_id=registration.model_id,
            output=output_text,
            schema_valid=True,
            raw_output_ref=f"sha256:{output_digest}",
            parsed_ref=f"sha256:{output_digest}",
            tokens_in=None,
            tokens_out=None,
            billed_amount=None,
            price_snapshot_ref=None,
            latency_ms=elapsed_ms,
            attempt_count=1,
            failure_code=None,
            egress_bytes_by_sensitivity=(),
            request_sha256=request_digest,
        )
        boundary = self._boundary(
            validated,
            registration.adapter_id,
            sources,
            SensitivityLabel.PUBLIC,
            request_digest,
            output.output_bytes,
            None,
        )
        return ModelCallResult(response=response, failure=None, boundary=boundary)

    @staticmethod
    def _validate_request(request: object) -> ModelRequest | None:
        try:
            raw: object
            if isinstance(request, ModelRequest):
                raw = dict(request.__dict__)
                if set(raw).difference(ModelRequest.model_fields) or request.model_extra:
                    return None
            elif isinstance(request, Mapping):
                raw = dict(request)
            else:
                return None
            return ModelRequest.model_validate(raw, strict=True)
        except Exception:
            return None

    @staticmethod
    def _validate_adapter_output(output: object) -> ModelAdapterOutput:
        if not isinstance(output, ModelAdapterOutput):
            raise TypeError("adapter output must use ModelAdapterOutput")
        raw = dict(output.__dict__)
        if set(raw).difference(ModelAdapterOutput.model_fields) or output.model_extra:
            raise ValueError("model adapter output contains undeclared fields")
        return ModelAdapterOutput.model_validate(raw, strict=True)

    @staticmethod
    def _invocation_bytes(
        request: ModelRequest,
        registration: ModelAdapterRegistration,
        sources: tuple[SourceEnvelope, ...],
        payload_bytes: bytes,
    ) -> bytes:
        from json import dumps

        payload = {
            "adapter_id": registration.adapter_id,
            "locality": registration.locality.value,
            "model_id": registration.model_id,
            "payload_utf8": payload_bytes.decode("utf-8", errors="strict"),
            "provider_id": registration.provider_id,
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
        request: ModelRequest,
        code: GatewayFailureCode,
        request_bytes: bytes,
        *,
        registration: ModelAdapterRegistration | None = None,
        request_digest: str | None = None,
        sources: tuple[SourceEnvelope, ...] = (),
    ) -> ModelCallResult:
        digest = request_digest or sha256(request_bytes).hexdigest()
        boundary = self._boundary(
            request,
            registration.adapter_id if registration is not None else request.adapter_id,
            sources,
            request.sensitivity,
            digest,
            None,
            code,
        )
        return ModelCallResult(response=None, failure=safe_failure(code), boundary=boundary)

    def _boundary(
        self,
        request: ModelRequest,
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
            kind=BoundaryKind.MODEL,
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
