"""Deterministic canonical serialization tests for the typed contracts."""

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from sentinel.contracts.canonical import canonical_json_bytes, canonical_sha256
from sentinel.contracts.envelopes import BoundaryEnvelope, SourceEnvelope
from sentinel.contracts.labels import SensitivityLabel, TrustLabel

SOURCE_DATA: dict[str, object] = {
    "source_id": UUID("44e11e17-d39f-4f57-a59c-909ba74a3e83"),
    "provider_id": "synthetic-file",
    "content_sha256": "a" * 64,
    "observed_at": datetime(2026, 11, 2, 10, 30, tzinfo=UTC),
    "trust": TrustLabel.T4_EXTERNAL,
    "sensitivity": SensitivityLabel.INTERNAL,
    "parent_ids": (),
    "byte_spans": (),
}

BOUNDARY_DATA: dict[str, object] = {
    "boundary_id": UUID("3c9459d7-6b14-476e-9f88-caa4a2f01daf"),
    "run_id": UUID("564e40e2-3d4a-4931-8f4b-5ca0f039c183"),
    "seq": 1,
    "kind": "tool",
    "adapter_id": "synthetic-tool",
    "request_ref": f"sha256:{'c' * 64}",
    "response_ref": f"sha256:{'d' * 64}",
    "request_sha256": "c" * 64,
    "response_sha256": "d" * 64,
    "sensitivity": SensitivityLabel.PRIVATE,
    "source_ids": (UUID("44e11e17-d39f-4f57-a59c-909ba74a3e83"),),
    "replay_injected": False,
    "error_code": None,
    "created_at": datetime(2026, 11, 2, 10, 30, tzinfo=UTC),
}


def test_equivalent_objects_have_identical_canonical_bytes() -> None:
    source_forward = SourceEnvelope.model_validate(SOURCE_DATA)
    source_reverse = SourceEnvelope.model_validate(dict(reversed(list(SOURCE_DATA.items()))))
    boundary_forward = BoundaryEnvelope.model_validate(BOUNDARY_DATA)
    boundary_reverse = BoundaryEnvelope.model_validate(dict(reversed(list(BOUNDARY_DATA.items()))))

    assert canonical_json_bytes(source_forward) == canonical_json_bytes(source_reverse)
    assert canonical_json_bytes(boundary_forward) == canonical_json_bytes(boundary_reverse)


def test_equivalent_instants_have_identical_canonical_bytes() -> None:
    utc_data = dict(SOURCE_DATA)
    offset_data = dict(SOURCE_DATA)
    utc_data["observed_at"] = "2026-11-02T10:30:00Z"
    offset_data["observed_at"] = "2026-11-02T16:00:00+05:30"

    assert canonical_json_bytes(SourceEnvelope.model_validate(utc_data)) == canonical_json_bytes(
        SourceEnvelope.model_validate(offset_data)
    )


@pytest.mark.parametrize(
    "model,data",
    [
        (SourceEnvelope, SOURCE_DATA),
        (BoundaryEnvelope, BOUNDARY_DATA),
    ],
)
def test_canonical_keys_are_sorted_and_hash_is_deterministic(
    model: type[SourceEnvelope] | type[BoundaryEnvelope], data: dict[str, object]
) -> None:
    envelope = model.model_validate(data)
    encoded = canonical_json_bytes(envelope)

    assert encoded == canonical_json_bytes(model.model_validate(dict(reversed(list(data.items())))))
    assert canonical_sha256(envelope) == hashlib.sha256(encoded).hexdigest()
    assert canonical_sha256(envelope) == canonical_sha256(model.model_validate(data))
    serialized_keys = list(json.loads(encoded).keys())
    assert serialized_keys == sorted(serialized_keys)


def test_canonical_bytes_do_not_change_after_rejected_mutations() -> None:
    envelope = SourceEnvelope.model_validate(SOURCE_DATA)
    before = canonical_json_bytes(envelope)

    with pytest.raises(ValidationError):
        envelope.sensitivity = SensitivityLabel.SECRET  # type: ignore[misc]

    assert canonical_json_bytes(envelope) == before


@pytest.mark.parametrize("value", [{"arbitrary": "mapping"}, object(), b"raw bytes"])
def test_canonical_serializer_rejects_objects_outside_contract_types(value: object) -> None:
    with pytest.raises(TypeError):
        canonical_json_bytes(value)  # type: ignore[arg-type]


def test_canonical_serializer_revalidates_untrusted_model_copies() -> None:
    source = SourceEnvelope.model_validate(SOURCE_DATA)
    invalid_copy = source.model_copy(update={"content_sha256": "not-a-digest"})

    with pytest.raises(ValidationError):
        canonical_json_bytes(invalid_copy)


def test_model_json_serialization_is_stable_after_round_trip() -> None:
    source = SourceEnvelope.model_validate(SOURCE_DATA)
    restored = SourceEnvelope.model_validate_json(source.model_dump_json())

    assert canonical_json_bytes(restored) == canonical_json_bytes(source)
