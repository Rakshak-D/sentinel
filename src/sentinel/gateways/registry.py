"""Immutable application-code registry for synthetic model/tool adapters.

Request data can name a registered adapter, but cannot create one. Registration
objects are trusted code configuration and this CR0-D registry accepts DEMO-only
adapters; it is not an authorization policy or a live-provider registry.
"""

import re
from dataclasses import dataclass, field
from threading import Lock
from typing import Protocol
from uuid import UUID

from sentinel.contracts import SourceEnvelope
from sentinel.gateways.types import (
    DemoPayload,
    ExecutionMode,
    ModelAdapterOutput,
    ModelInvocation,
    ModelLocality,
    ToolAdapterOutput,
    ToolCapability,
    ToolInvocation,
)

_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_MODEL_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9_.:/-]{0,127}$")


class SyntheticModelAdapter(Protocol):
    """Trusted application-code adapter interface for in-memory demo execution."""

    demo_only: bool

    def generate(self, invocation: ModelInvocation) -> ModelAdapterOutput:
        """Return synthetic output bytes without external effects."""


class SyntheticToolAdapter(Protocol):
    """Trusted application-code adapter interface for in-memory demo reads."""

    demo_only: bool

    def call(self, invocation: ToolInvocation) -> ToolAdapterOutput:
        """Return synthetic result bytes without external effects."""


@dataclass(frozen=True, slots=True)
class ModelAdapterRegistration:
    """One fixed adapter/model identity and its reviewed locality classification."""

    adapter_id: str
    provider_id: str
    model_id: str
    locality: ModelLocality
    demo_only: bool
    adapter: SyntheticModelAdapter

    def __post_init__(self) -> None:
        for field_name in ("adapter_id", "provider_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
                raise ValueError(f"{field_name} must be a bounded lower-case identifier")
        if not isinstance(self.model_id, str) or not _MODEL_IDENTIFIER_PATTERN.fullmatch(
            self.model_id
        ):
            raise ValueError("model_id must be a bounded lower-case model identifier")
        if not isinstance(self.locality, ModelLocality):
            raise ValueError("model locality must use a registered ModelLocality value")
        if self.demo_only is not True or getattr(self.adapter, "demo_only", False) is not True:
            raise ValueError("only explicitly registered demo model adapters are supported")
        if not callable(getattr(self.adapter, "generate", None)):
            raise ValueError("model adapter must implement generate")


@dataclass(frozen=True, slots=True)
class ToolAdapterRegistration:
    """One static tool identity, argument allowlist and capability classification."""

    tool_id: str
    capability: ToolCapability
    argument_names: tuple[str, ...]
    demo_only: bool
    adapter: SyntheticToolAdapter

    def __post_init__(self) -> None:
        if not isinstance(self.tool_id, str) or not _IDENTIFIER_PATTERN.fullmatch(self.tool_id):
            raise ValueError("tool_id must be a bounded lower-case identifier")
        if not isinstance(self.capability, ToolCapability):
            raise ValueError("tool capability must use a registered ToolCapability value")
        if not isinstance(self.argument_names, tuple):
            raise ValueError("argument_names must be an immutable tuple")
        if any(
            not isinstance(name, str) or not _IDENTIFIER_PATTERN.fullmatch(name)
            for name in self.argument_names
        ):
            raise ValueError("tool argument names must be bounded lower-case identifiers")
        if self.argument_names != tuple(sorted(set(self.argument_names))):
            raise ValueError("tool argument names must be unique and canonically ordered")
        if self.demo_only is not True or getattr(self.adapter, "demo_only", False) is not True:
            raise ValueError("only explicitly registered demo tools are supported")
        if not callable(getattr(self.adapter, "call", None)):
            raise ValueError("tool adapter must implement call")


@dataclass(frozen=True, slots=True)
class GatewayRegistry:
    """Fixed trusted registrations and provenance for one explicitly DEMO context.

    Adapters and sources must be supplied by application code. The gateway never
    imports code, opens URLs, resolves paths, or executes request-supplied handlers.
    Source envelopes are labels/references, not authentication evidence.
    """

    execution_mode: ExecutionMode
    sources: tuple[SourceEnvelope, ...] = ()
    demo_payloads: tuple[DemoPayload, ...] = ()
    model_adapters: tuple[ModelAdapterRegistration, ...] = ()
    tool_adapters: tuple[ToolAdapterRegistration, ...] = ()
    _sequence_lock: Lock = field(default_factory=Lock, init=False, repr=False, compare=False)
    _sequences: dict[UUID, int] = field(default_factory=dict, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.execution_mode is not ExecutionMode.DEMO:
            raise ValueError("gateway registry supports only explicit DEMO execution")
        if not isinstance(self.sources, tuple) or any(
            not isinstance(source, SourceEnvelope) for source in self.sources
        ):
            raise ValueError("sources must be a tuple of validated SourceEnvelope values")
        validated_sources: list[SourceEnvelope] = []
        for source in self.sources:
            source_values = dict(source.__dict__)
            if set(source_values).difference(SourceEnvelope.model_fields) or source.model_extra:
                raise ValueError("registered source envelope contains undeclared fields")
            validated_sources.append(SourceEnvelope.model_validate(source_values, strict=True))
        object.__setattr__(self, "sources", tuple(validated_sources))
        source_ids = tuple(source.source_id for source in self.sources)
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("registered source IDs must be unique")
        if not isinstance(self.demo_payloads, tuple) or any(
            not isinstance(payload, DemoPayload) for payload in self.demo_payloads
        ):
            raise ValueError("demo_payloads must be a tuple of validated DemoPayload values")
        validated_payloads: list[DemoPayload] = []
        for payload in self.demo_payloads:
            payload_values = dict(payload.__dict__)
            if set(payload_values).difference(DemoPayload.model_fields) or payload.model_extra:
                raise ValueError("registered demo payload contains undeclared fields")
            validated_payloads.append(DemoPayload.model_validate(payload_values, strict=True))
        object.__setattr__(self, "demo_payloads", tuple(validated_payloads))
        payload_refs = tuple(payload.payload_ref for payload in self.demo_payloads)
        if len(payload_refs) != len(set(payload_refs)):
            raise ValueError("registered demo payload references must be unique")
        source_digests = {source.content_sha256 for source in self.sources}
        if any(
            payload.payload_ref.removeprefix("sha256:") not in source_digests
            for payload in self.demo_payloads
        ):
            raise ValueError("registered demo payloads must match a registered source digest")
        if not isinstance(self.model_adapters, tuple) or any(
            not isinstance(adapter, ModelAdapterRegistration) for adapter in self.model_adapters
        ):
            raise ValueError("model_adapters must be an immutable registration tuple")
        model_keys = tuple((item.adapter_id, item.model_id) for item in self.model_adapters)
        if len(model_keys) != len(set(model_keys)):
            raise ValueError("registered adapter/model identities must be unique")
        if not isinstance(self.tool_adapters, tuple) or any(
            not isinstance(adapter, ToolAdapterRegistration) for adapter in self.tool_adapters
        ):
            raise ValueError("tool_adapters must be an immutable registration tuple")
        tool_ids = tuple(item.tool_id for item in self.tool_adapters)
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("registered tool IDs must be unique")

    def resolve_sources(self, source_ids: tuple[UUID, ...]) -> tuple[SourceEnvelope, ...] | None:
        """Resolve exactly the requested refs from trusted registry state."""
        source_map = {source.source_id: source for source in self.sources}
        resolved = tuple(source_map.get(source_id) for source_id in source_ids)
        if not source_ids or any(source is None for source in resolved):
            return None
        return tuple(source for source in resolved if source is not None)

    def resolve_demo_payload(self, payload_ref: str) -> DemoPayload | None:
        """Resolve a content reference only from trusted in-memory DEMO setup."""
        return next(
            (payload for payload in self.demo_payloads if payload.payload_ref == payload_ref),
            None,
        )

    def find_model_adapter(
        self, adapter_id: str, model_id: str
    ) -> ModelAdapterRegistration | None:
        """Return only the exact pre-registered adapter/model pair."""
        return next(
            (
                item
                for item in self.model_adapters
                if item.adapter_id == adapter_id and item.model_id == model_id
            ),
            None,
        )

    def has_model_adapter(self, adapter_id: str) -> bool:
        """Tell a bounded failure whether the adapter ID or model ID was unknown."""
        return any(item.adapter_id == adapter_id for item in self.model_adapters)

    def find_tool(self, tool_id: str) -> ToolAdapterRegistration | None:
        """Return only a pre-registered tool identity."""
        return next((item for item in self.tool_adapters if item.tool_id == tool_id), None)

    def next_sequence(self, run_id: UUID) -> int:
        """Allocate a volatile per-run sequence for metadata; this is not persistence."""
        with self._sequence_lock:
            next_value = self._sequences.get(run_id, 0) + 1
            self._sequences[run_id] = next_value
            return next_value
