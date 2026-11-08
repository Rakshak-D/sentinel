from __future__ import annotations

import hashlib
import json
import struct

import pytest

from tools.cr2_g_b1.protocol import (
    MAX_FRAME_BYTES,
    CanaryStore,
    ProtocolError,
    encode_request,
    process_frame,
)


def _payload(frame: bytes) -> dict[str, object]:
    assert len(frame) >= 4
    size = struct.unpack(">I", frame[:4])[0]
    assert size == len(frame) - 4
    return json.loads(frame[4:].decode("utf-8"))


def test_health_is_a_fixed_non_authorizing_response(tmp_path) -> None:
    store = CanaryStore.initialize(str(tmp_path / "canary.db"))

    actual = _payload(process_frame(encode_request("req-1", "health"), store))

    assert actual == {
        "payload": {
            "authorization": "DISABLED",
            "prototype_status": "NON_AUTHORIZING",
        },
        "reason_code": "NONE",
        "request_id": "req-1",
        "schema_version": "sentinel.cr2-g-b1-response.v1",
        "status": "OK",
    }


def test_canary_status_returns_only_fixed_synthetic_metadata(tmp_path) -> None:
    store = CanaryStore.initialize(str(tmp_path / "canary.db"))

    actual = _payload(process_frame(encode_request("req-2", "canary_status"), store))

    assert actual["status"] == "OK"
    assert actual["payload"] == {
        "canary_id": "synthetic-canary-0001",
        "classification": "SYNTHETIC_ONLY",
        "state": "PRESENT",
    }
    assert "owner_verified" not in actual


@pytest.mark.parametrize("command", ["enroll", "approve", "exec", "unknown"])
def test_privileged_and_unknown_commands_are_denied_without_state_change(
    tmp_path,
    command: str,
) -> None:
    path = tmp_path / "canary.db"
    store = CanaryStore.initialize(str(path))
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    actual = _payload(process_frame(encode_request("req-deny", command), store))

    after = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual["status"] == "DENIED"
    assert actual["payload"] is None
    assert after == before


@pytest.mark.parametrize(
    "raw_payload",
    [
        b'{"schema_version":"sentinel.cr2-g-b1-request.v1","request_id":"x",'
        b'"command":"health","command":"approve","arguments":{}}',
        b'{"schema_version":"sentinel.cr2-g-b1-request.v1","request_id":"x",'
        b'"command":"health","arguments":{},"owner_verified":true}',
        b'{"schema_version":"sentinel.cr2-g-b1-request.v1","request_id":true,'
        b'"command":"health","arguments":{}}',
        b'{"schema_version":"sentinel.cr2-g-b1-request.v1","request_id":"x",'
        b'"command":"health","arguments":{"authenticated":true}}',
    ],
)
def test_ambiguous_or_authority_claim_payloads_fail_closed(raw_payload: bytes) -> None:
    frame = struct.pack(">I", len(raw_payload)) + raw_payload

    with pytest.raises(ProtocolError):
        process_frame(frame, object())


@pytest.mark.parametrize(
    "claim",
    ["owner_verified", "trusted", "approved", "is_admin", "authenticated"],
)
def test_authority_claims_never_enter_protocol_schema(claim: str) -> None:
    body = json.dumps(
        {
            "schema_version": "sentinel.cr2-g-b1-request.v1",
            "request_id": "authority-test",
            "command": "health",
            "arguments": {},
            claim: True,
        },
        separators=(",", ":"),
    ).encode("utf-8")

    with pytest.raises(ProtocolError, match="REQUEST_FIELDS"):
        process_frame(struct.pack(">I", len(body)) + body, object())


def test_oversized_and_trailing_frames_fail_closed() -> None:
    oversized = struct.pack(">I", MAX_FRAME_BYTES + 1) + b"x" * (MAX_FRAME_BYTES + 1)
    trailing = encode_request("req-3", "health") + b"x"

    with pytest.raises(ProtocolError):
        process_frame(oversized, object())
    with pytest.raises(ProtocolError):
        process_frame(trailing, object())


@pytest.mark.parametrize(
    "raw_payload",
    [
        b'{"schema_version":"wrong","request_id":"x","command":"health","arguments":{}}',
        b'{"schema_version":"sentinel.cr2-g-b1-request.v1","request_id":"x",'
        b'"command":"health","arguments":{},"nested":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{}}}}}}}}}',
        b'{"schema_version":"sentinel.cr2-g-b1-request.v1","request_id":"x",'
        b'"command":"health","arguments":{},"n":NaN}',
    ],
)
def test_unsupported_version_nonfinite_and_deep_json_fail_closed(raw_payload: bytes) -> None:
    frame = struct.pack(">I", len(raw_payload)) + raw_payload

    with pytest.raises(ProtocolError):
        process_frame(frame, object())


def test_response_encoding_is_deterministic(tmp_path) -> None:
    store = CanaryStore.initialize(str(tmp_path / "stable.db"))
    request = encode_request("same-request", "canary_status")

    first = process_frame(request, store)
    second = process_frame(request, store)

    assert first == second


def test_malformed_request_does_not_touch_canary_store(tmp_path) -> None:
    path = tmp_path / "malformed-does-not-write.db"
    store = CanaryStore.initialize(path)
    before = hashlib.sha256(path.read_bytes()).digest()
    malformed = struct.pack(">I", 2) + b"{}"

    with pytest.raises(ProtocolError):
        process_frame(malformed, store)

    assert hashlib.sha256(path.read_bytes()).digest() == before
