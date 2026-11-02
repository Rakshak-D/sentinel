"""Immutable typed request, adapter, result, and failure contracts for gateways.

These contracts validate shape only. A valid request is not an authorization
decision, and a source trust label is not proof that a principal was authenticated.
"""

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictBytes,
    StrictFloat,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from sentinel.contracts import BoundaryEnvelope, SensitivityLabel, SourceEnvelope, TrustLabel

_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_.:-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_CONTENT_REF_PATTERN = rf"^sha256:{_SHA256_PATTERN[1:-1]}$"

GatewayIdentifier = Annotated[
    str,
    StringConstraints(strict=True, pattern=_IDENTIFIER_PATTERN, max_length=128),
]
ModelIdentifier = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[a-z][a-z0-9_.:/-]{0,127}$", max_length=128),
]
PromptVersion = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9]+(?:\.[0-9]+){0,2}(?:[-+][a-zA-Z0-9.-]+)?$"),
]
Sha256Digest = Annotated[str, StringConstraints(strict=True, pattern=_SHA256_PATTERN)]
ContentReference = Annotated[
    str,
    StringConstraints(strict=True, pattern=_CONTENT_REF_PATTERN, max_length=71),
]
ToolArgumentValue = Annotated[StrictStr, Field(max_length=4096)]


class ModelTaskClass(StrEnum):
    """Small task-class vocabulary accepted by the synthetic text adapter."""

    TRIAGE = "triage"
    EXTRACTION = "extraction"
    SUMMARIZATION = "summarization"
    CLASSIFICATION = "classification"


class ModelProfile(StrEnum):
    """Blueprint profile names; CR0-D executes only the local-only demo profile."""

    LOCAL_ONLY = "local-only"
    HYBRID = "hybrid"
    CLOUD_MAX = "cloud-max"


class ExecutionMode(StrEnum):
    """Execution context; the registry currently admits DEMO only."""

    LIVE = "LIVE"
    DEMO = "DEMO"
    REPLAY = "REPLAY"


class ModelLocality(StrEnum):
    """Registered route classification, not a network endpoint."""

    LOOPBACK = "loopback"
    CLOUD = "cloud"


class ToolCapability(StrEnum):
    """Static capability assigned to a registered tool by trusted code."""

    READ_ONLY = "read_only"
    WRITE_LOCAL = "write_local"
    WRITE_EXTERNAL = "write_external"
    SEND = "send"
    APPROVAL = "approval"
    EXECUTE = "execute"


class AuthorizationStatus(StrEnum):
    """The gateways do not implement or infer policy authorization."""

    NOT_EVALUATED = "not_evaluated"


class GatewayFailureCode(StrEnum):
    """Bounded public failure codes; exception text is never propagated."""

    INVALID_REQUEST = "invalid_request"
    UNKNOWN_ADAPTER = "unknown_adapter"
    UNKNOWN_MODEL = "unknown_model"
    UNKNOWN_TOOL = "unknown_tool"
    PROVENANCE_INVALID = "provenance_invalid"
    SENSITIVITY_DENIED = "sensitivity_denied"
    EXECUTION_DISABLED = "execution_disabled"
    CAPABILITY_DENIED = "capability_denied"
    SCHEMA_UNSUPPORTED = "schema_unsupported"
    DEADLINE_EXPIRED = "deadline_expired"
    ADAPTER_FAILED = "adapter_failed"
    ADAPTER_OUTPUT_INVALID = "adapter_output_invalid"
    REPLAY_UNAVAILABLE = "replay_unavailable"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ModelRequest(_FrozenModel):
    """Bounded text-only request based on the §7 ModelGateway fields.

    ``payload_ref`` resolves through the trusted in-memory demo registry. Trust is
    resolved from registered source envelopes and is absent from this request.
    """

    call_id: UUID
    run_id: UUID
    adapter_id: GatewayIdentifier
    model_id: ModelIdentifier
    task_class: ModelTaskClass
    prompt_id: GatewayIdentifier
    prompt_version: PromptVersion
    prompt_sha256: Sha256Digest
    input_schema_id: GatewayIdentifier
    output_schema_id: GatewayIdentifier
    source_ids: Annotated[tuple[UUID, ...], Field(max_length=128)]
    sensitivity: SensitivityLabel
    payload_ref: ContentReference
    redaction_manifest_ref: Sha256Digest | None
    config_sha256: Sha256Digest
    temperature: Annotated[StrictFloat, Field(ge=0.0, le=2.0)]
    max_output_tokens: Annotated[StrictInt, Field(ge=1, le=8192)]
    deadline: AwareDatetime
    requested_profile: ModelProfile
    replay_mode: StrictBool

    @field_validator("deadline")
    @classmethod
    def normalize_deadline_to_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("source_ids")
    @classmethod
    def reject_duplicate_source_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("source_ids must not contain duplicates")
        return value



class DemoPayload(_FrozenModel):
    """Trusted, bounded in-memory content resolved by a demo request reference."""

    payload_ref: ContentReference
    payload_bytes: Annotated[StrictBytes, Field(max_length=32_768, repr=False)]

    @model_validator(mode="after")
    def validate_reference_and_text(self) -> "DemoPayload":
        digest = hashlib.sha256(self.payload_bytes).hexdigest()
        if self.payload_ref != f"sha256:{digest}":
            raise ValueError("demo payload reference must match its bytes")
        try:
            self.payload_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("demo model payload must be UTF-8 text") from exc
        return self


class ToolRequest(_FrozenModel):
    """Typed scalar arguments and provenance references for one registered tool."""

    call_id: UUID
    run_id: UUID
    tool_id: GatewayIdentifier
    arguments: Annotated[
        tuple[tuple[GatewayIdentifier, ToolArgumentValue], ...],
        Field(max_length=32, repr=False),
    ]
    source_ids: Annotated[tuple[UUID, ...], Field(max_length=128)]
    sensitivity: SensitivityLabel

    @field_validator("arguments")
    @classmethod
    def reject_duplicate_argument_names(
        cls, value: tuple[tuple[str, str], ...]
    ) -> tuple[tuple[str, str], ...]:
        names = tuple(name for name, _argument in value)
        if len(names) != len(set(names)):
            raise ValueError("tool argument names must be unique")
        if names != tuple(sorted(names)):
            raise ValueError("tool argument names must be in canonical order")
        return value

    @field_validator("source_ids")
    @classmethod
    def reject_duplicate_source_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("source_ids must not contain duplicates")
        return value


class ModelAdapterOutput(_FrozenModel):
    """Exact output bytes returned by one registered synthetic model adapter."""

    output_bytes: Annotated[StrictBytes, Field(max_length=65_536, repr=False)]


class ToolAdapterOutput(_FrozenModel):
    """Exact output bytes returned by one registered synthetic read adapter."""

    output_bytes: Annotated[StrictBytes, Field(max_length=65_536, repr=False)]


class ModelInvocation(_FrozenModel):
    """Resolved, immutable input passed only to a registered demo adapter."""

    request: ModelRequest
    sources: tuple[SourceEnvelope, ...]
    provider_id: GatewayIdentifier
    model_id: GatewayIdentifier
    adapter_id: GatewayIdentifier
    locality: ModelLocality
    payload_bytes: Annotated[StrictBytes, Field(repr=False, max_length=32_768)]
    request_bytes: Annotated[StrictBytes, Field(repr=False)]


class ToolInvocation(_FrozenModel):
    """Resolved input and canonical bytes passed only to a registered demo tool."""

    request: ToolRequest
    sources: tuple[SourceEnvelope, ...]
    capability: ToolCapability
    request_bytes: Annotated[StrictBytes, Field(repr=False)]


class ModelResponse(_FrozenModel):
    """Typed §7 response metadata for the local synthetic execution path."""

    provider_id: GatewayIdentifier
    provider_model_id: GatewayIdentifier
    output: Annotated[StrictStr, Field(max_length=65_536, repr=False)]
    output_trust: Literal[TrustLabel.T3_DERIVED] = TrustLabel.T3_DERIVED
    schema_valid: StrictBool
    raw_output_ref: ContentReference
    parsed_ref: ContentReference
    tokens_in: StrictInt | None
    tokens_out: StrictInt | None
    billed_amount: Decimal | None
    price_snapshot_ref: ContentReference | None
    latency_ms: Annotated[StrictInt, Field(ge=0)]
    attempt_count: Annotated[StrictInt, Field(ge=1)]
    failure_code: GatewayIdentifier | None
    egress_bytes_by_sensitivity: tuple[tuple[SensitivityLabel, StrictInt], ...]
    request_sha256: Sha256Digest


class ToolResponse(_FrozenModel):
    """Typed result for a synthetic read-only tool invocation."""

    output: Annotated[StrictStr, Field(max_length=65_536, repr=False)]
    result_ref: ContentReference
    source_ids: tuple[UUID, ...]
    source_trust: tuple[TrustLabel, ...]
    sensitivity: SensitivityLabel


class GatewayFailure(_FrozenModel):
    """Non-sensitive, non-retryable failure returned by a gateway."""

    code: GatewayFailureCode
    message: Annotated[StrictStr, Field(max_length=160)]
    retryable: Literal[False] = False


class ModelCallResult(_FrozenModel):
    """Model result or typed failure, with optional boundary metadata."""

    response: ModelResponse | None
    failure: GatewayFailure | None
    boundary: BoundaryEnvelope | None
    authorization: AuthorizationStatus = AuthorizationStatus.NOT_EVALUATED
    external_effect: Literal[False] = False

    @model_validator(mode="after")
    def validate_one_outcome(self) -> "ModelCallResult":
        if (self.response is None) == (self.failure is None):
            raise ValueError("exactly one of response or failure is required")
        if self.response is not None:
            if self.boundary is None or self.boundary.kind.value != "model":
                raise ValueError("successful model result requires model boundary metadata")
            if (
                self.boundary.error_code is not None
                or self.response.request_sha256 != self.boundary.request_sha256
                or self.response.raw_output_ref != self.boundary.response_ref
                or self.response.parsed_ref != self.boundary.response_ref
            ):
                raise ValueError("model result metadata does not match its boundary")
        elif self.failure is not None and self.boundary is not None:
            if (
                self.boundary.response_ref is not None
                or self.boundary.response_sha256 is not None
                or self.boundary.error_code != self.failure.code.value
            ):
                raise ValueError("failed result cannot contain a response digest")
        return self


class ToolCallResult(_FrozenModel):
    """Tool result or typed failure; the result cannot represent an external effect."""

    response: ToolResponse | None
    failure: GatewayFailure | None
    boundary: BoundaryEnvelope | None
    authorization: AuthorizationStatus = AuthorizationStatus.NOT_EVALUATED
    external_effect: Literal[False] = False

    @model_validator(mode="after")
    def validate_one_outcome(self) -> "ToolCallResult":
        if (self.response is None) == (self.failure is None):
            raise ValueError("exactly one of response or failure is required")
        if self.response is not None:
            if self.boundary is None or self.boundary.kind.value != "tool":
                raise ValueError("successful tool result requires tool boundary metadata")
            if (
                self.boundary.error_code is not None
                or self.response.result_ref != self.boundary.response_ref
                or self.response.source_ids != self.boundary.source_ids
                or self.response.sensitivity is not self.boundary.sensitivity
            ):
                raise ValueError("tool result metadata does not match its boundary")
        elif self.failure is not None and self.boundary is not None:
            if (
                self.boundary.response_ref is not None
                or self.boundary.response_sha256 is not None
                or self.boundary.error_code != self.failure.code.value
            ):
                raise ValueError("failed result cannot contain a response digest")
        return self


_SAFE_FAILURE_MESSAGES: dict[GatewayFailureCode, str] = {
    GatewayFailureCode.INVALID_REQUEST: "The gateway request is invalid.",
    GatewayFailureCode.UNKNOWN_ADAPTER: "The requested model adapter is not registered.",
    GatewayFailureCode.UNKNOWN_MODEL: "The requested model is not registered for that adapter.",
    GatewayFailureCode.UNKNOWN_TOOL: "The requested tool is not registered.",
    GatewayFailureCode.PROVENANCE_INVALID: "Required source provenance is unavailable or invalid.",
    GatewayFailureCode.SENSITIVITY_DENIED: "The requested sensitivity is unavailable in demo mode.",
    GatewayFailureCode.EXECUTION_DISABLED: "This execution profile is disabled in CR0-D.",
    GatewayFailureCode.CAPABILITY_DENIED: "Only registered synthetic read-only tools can run.",
    GatewayFailureCode.SCHEMA_UNSUPPORTED: "The requested input or output schema is unsupported.",
    GatewayFailureCode.DEADLINE_EXPIRED: "The request deadline has expired.",
    GatewayFailureCode.ADAPTER_FAILED: "The registered adapter failed; no retry was attempted.",
    GatewayFailureCode.ADAPTER_OUTPUT_INVALID: "The registered adapter returned invalid output.",
    GatewayFailureCode.REPLAY_UNAVAILABLE: "Replay execution is unavailable in CR0-D.",
}


def safe_failure(code: GatewayFailureCode) -> GatewayFailure:
    """Build a bounded failure without copying adapter or request content."""
    return GatewayFailure(code=code, message=_SAFE_FAILURE_MESSAGES[code])


def canonical_json_bytes(value: BaseModel) -> bytes:
    """Serialize a validated gateway DTO as deterministic UTF-8 JSON bytes."""
    return json.dumps(
        value.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
