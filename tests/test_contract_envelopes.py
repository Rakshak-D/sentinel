"""Source and boundary envelope validation tests with synthetic identifiers."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from sentinel.contracts.envelopes import BoundaryEnvelope, ByteSpan, SourceEnvelope
from sentinel.contracts.labels import SensitivityLabel, TrustLabel

DIGEST = "a" * 64
SOURCE_ID = UUID("44e11e17-d39f-4f57-a59c-909ba74a3e83")
RUN_ID = UUID("564e40e2-3d4a-4931-8f4b-5ca0f039c183")
OBSERVED_AT = "2026-11-02T10:30:00Z"


def source_data(**updates: object) -> dict[str, object]:
    data: dict[str, object] = {
        "source_id": SOURCE_ID,
        "provider_id": "synthetic-mail",
        "content_sha256": DIGEST,
        "observed_at": OBSERVED_AT,
        "trust": "T4 EXTERNAL",
        "sensitivity": "PRIVATE",
        "parent_ids": (),
        "byte_spans": (
            {
                "span_id": UUID("5d43a941-e3c4-4cbc-a48b-84ee6b3efcf2"),
                "start_byte": 0,
                "end_byte": 12,
                "text_sha256": "b" * 64,
            },
        ),
    }
    data.update(updates)
    return data


def boundary_data(**updates: object) -> dict[str, object]:
    data: dict[str, object] = {
        "boundary_id": UUID("3c9459d7-6b14-476e-9f88-caa4a2f01daf"),
        "run_id": RUN_ID,
        "seq": 1,
        "kind": "model",
        "adapter_id": "synthetic-model",
        "request_ref": f"sha256:{'c' * 64}",
        "response_ref": f"sha256:{'d' * 64}",
        "request_sha256": "c" * 64,
        "response_sha256": "d" * 64,
        "sensitivity": "PRIVATE",
        "source_ids": (SOURCE_ID,),
        "replay_injected": False,
        "error_code": None,
        "created_at": OBSERVED_AT,
    }
    data.update(updates)
    return data


def test_source_envelope_uses_required_typed_fields() -> None:
    envelope = SourceEnvelope.model_validate(source_data())

    assert envelope.source_id == SOURCE_ID
    assert envelope.provider_id == "synthetic-mail"
    assert envelope.content_sha256 == DIGEST
    assert envelope.observed_at == datetime(2026, 11, 2, 10, 30, tzinfo=UTC)
    assert envelope.trust is TrustLabel.T4_EXTERNAL
    assert envelope.sensitivity is SensitivityLabel.PRIVATE
    assert envelope.parent_ids == ()
    assert isinstance(envelope.byte_spans[0], ByteSpan)


@pytest.mark.parametrize(
    "field",
    [
        "source_id",
        "provider_id",
        "content_sha256",
        "observed_at",
        "trust",
        "sensitivity",
        "parent_ids",
        "byte_spans",
    ],
)
def test_missing_source_fields_are_rejected(field: str) -> None:
    data = source_data()
    del data[field]

    with pytest.raises(ValidationError):
        SourceEnvelope.model_validate(data)


@pytest.mark.parametrize(
    "updates",
    [
        {"source_id": "not-a-uuid"},
        {"observed_at": "2026-11-02T10:30:00"},
        {"content_sha256": "a" * 63},
        {"content_sha256": "z" * 64},
        {"content_sha256": "A" * 64},
        {"trust": "OWNER_INTENT"},
        {"sensitivity": None},
    ],
)
def test_source_envelope_rejects_invalid_identity_time_digest_or_labels(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        SourceEnvelope.model_validate(source_data(**updates))


@pytest.mark.parametrize(
    "span",
    [
        {"span_id": uuid4(), "start_byte": -1, "end_byte": 1, "text_sha256": DIGEST},
        {"span_id": uuid4(), "start_byte": 4, "end_byte": 4, "text_sha256": DIGEST},
        {"span_id": uuid4(), "start_byte": 5, "end_byte": 2, "text_sha256": DIGEST},
        {"span_id": uuid4(), "start_byte": 0, "end_byte": 1, "text_sha256": "bad"},
        {"span_id": uuid4(), "start_byte": "zero", "end_byte": 1, "text_sha256": DIGEST},
    ],
)
def test_invalid_byte_spans_are_rejected(span: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SourceEnvelope.model_validate(source_data(byte_spans=(span,)))


def test_source_parent_references_reject_duplicates_self_and_invalid_values() -> None:
    with pytest.raises(ValidationError):
        SourceEnvelope.model_validate(source_data(parent_ids=(RUN_ID, RUN_ID)))
    with pytest.raises(ValidationError):
        SourceEnvelope.model_validate(source_data(parent_ids=(SOURCE_ID,)))
    with pytest.raises(ValidationError):
        SourceEnvelope.model_validate(source_data(parent_ids=("bad-parent",)))


def test_external_source_trust_is_preserved_without_authority_promotion() -> None:
    envelope = SourceEnvelope.model_validate(source_data(trust="T4 EXTERNAL"))

    assert envelope.trust is TrustLabel.T4_EXTERNAL
    assert envelope.trust is not TrustLabel.T1_OWNER_INTENT


def test_source_payload_rejects_malformed_nested_span_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        SourceEnvelope.model_validate(source_data(byte_spans=({"start_byte": "bad"},)))
    with pytest.raises(ValidationError):
        SourceEnvelope.model_validate(source_data(untrusted_payload="synthetic body"))


def test_source_json_round_trip() -> None:
    envelope = SourceEnvelope.model_validate(source_data())

    assert SourceEnvelope.model_validate_json(envelope.model_dump_json()) == envelope


@pytest.mark.parametrize("kind", ["model", "tool"])
def test_boundary_envelope_classifies_model_or_tool(kind: str) -> None:
    envelope = BoundaryEnvelope.model_validate(boundary_data(kind=kind))

    assert envelope.kind.value == kind
    assert envelope.source_ids == (SOURCE_ID,)
    assert envelope.sensitivity is SensitivityLabel.PRIVATE


@pytest.mark.parametrize(
    "field",
    [
        "boundary_id",
        "run_id",
        "seq",
        "kind",
        "adapter_id",
        "request_ref",
        "response_ref",
        "request_sha256",
        "response_sha256",
        "sensitivity",
        "source_ids",
        "replay_injected",
        "error_code",
        "created_at",
    ],
)
def test_missing_required_boundary_fields_are_rejected(field: str) -> None:
    data = boundary_data()
    del data[field]

    with pytest.raises(ValidationError):
        BoundaryEnvelope.model_validate(data)


@pytest.mark.parametrize(
    "updates",
    [
        {"seq": 0},
        {"seq": -1},
        {"seq": True},
        {"kind": "provider"},
        {"boundary_id": "bad-uuid"},
        {"created_at": "2026-11-02T10:30:00"},
        {"request_sha256": "bad"},
        {"response_sha256": "e" * 63},
        {"request_ref": "not-a-content-reference"},
        {"sensitivity": "UNKNOWN"},
        {"source_ids": ("not-a-uuid",)},
        {"adapter_id": "bad adapter id"},
    ],
)
def test_invalid_boundary_fields_are_rejected(updates: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        BoundaryEnvelope.model_validate(boundary_data(**updates))


def test_boundary_response_reference_and_digest_must_be_paired() -> None:
    with pytest.raises(ValidationError):
        BoundaryEnvelope.model_validate(boundary_data(response_ref=None))
    with pytest.raises(ValidationError):
        BoundaryEnvelope.model_validate(boundary_data(response_sha256=None))

    no_response = BoundaryEnvelope.model_validate(
        boundary_data(response_ref=None, response_sha256=None, error_code="timeout")
    )
    assert no_response.response_ref is None
    assert no_response.response_sha256 is None


def test_boundary_references_must_match_their_digests() -> None:
    with pytest.raises(ValidationError):
        BoundaryEnvelope.model_validate(boundary_data(request_ref=f"sha256:{'e' * 64}"))
    with pytest.raises(ValidationError):
        BoundaryEnvelope.model_validate(boundary_data(response_ref=f"sha256:{'e' * 64}"))


@pytest.mark.parametrize(
    "extra",
    [
        {"handler": "os.system"},
        {"provider_token": "synthetic-token-not-a-secret"},
        {"tool_dispatch": "call-any-tool"},
        {"payload": "synthetic raw model payload"},
    ],
)
def test_boundary_rejects_executable_or_secret_like_extra_fields(
    extra: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        BoundaryEnvelope.model_validate(boundary_data(**extra))


def test_boundary_rejects_duplicate_source_references_and_round_trips_json() -> None:
    with pytest.raises(ValidationError):
        BoundaryEnvelope.model_validate(boundary_data(source_ids=(SOURCE_ID, SOURCE_ID)))

    envelope = BoundaryEnvelope.model_validate(boundary_data())
    assert BoundaryEnvelope.model_validate_json(envelope.model_dump_json()) == envelope


def test_source_and_boundary_models_are_immutable() -> None:
    source = SourceEnvelope.model_validate(source_data())
    boundary = BoundaryEnvelope.model_validate(boundary_data())

    with pytest.raises(ValidationError):
        source.trust = TrustLabel.T1_OWNER_INTENT  # type: ignore[misc]
    with pytest.raises(ValidationError):
        source.byte_spans[0].start_byte = 5  # type: ignore[misc]
    with pytest.raises(ValidationError):
        boundary.seq = 2  # type: ignore[misc]
    with pytest.raises(AttributeError):
        boundary.source_ids.append(uuid4())  # type: ignore[attr-defined]
