"""Strict, non-authorizing IPC protocol for the CR2-G-B1 lab prototype."""

from __future__ import annotations

import json
import re
import struct
from collections.abc import Mapping
from typing import Any

from tools.cr2_g_b1.store import CanaryStore, CanaryStoreError

REQUEST_SCHEMA = "sentinel.cr2-g-b1-request.v1"
RESPONSE_SCHEMA = "sentinel.cr2-g-b1-response.v1"
MAX_FRAME_BYTES = 4096
_MAX_NESTING = 8
_REQUEST_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_COMMAND = re.compile(r"\A[a-z][a-z0-9_]{0,31}\Z", re.ASCII)


class ProtocolError(ValueError):
    """Bounded protocol rejection; its text never includes request data."""

    def __init__(self, reason_code: str = "INVALID_FRAME") -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ProtocolError("NONFINITE_JSON_NUMBER")


def _check_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > _MAX_NESTING:
                raise ProtocolError("NESTING_LIMIT")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise ProtocolError("INVALID_JSON")
    if in_string or depth != 0:
        raise ProtocolError("INVALID_JSON")


def _frame(payload: bytes) -> bytes:
    if not 0 < len(payload) <= MAX_FRAME_BYTES:
        raise ProtocolError("FRAME_SIZE")
    return struct.pack(">I", len(payload)) + payload


def encode_request(request_id: str, command: str) -> bytes:
    """Create a canonical test/client request with no caller arguments."""
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise ProtocolError("INVALID_REQUEST_ID")
    if not isinstance(command, str) or not _COMMAND.fullmatch(command):
        raise ProtocolError("INVALID_COMMAND")
    payload = json.dumps(
        {
            "schema_version": REQUEST_SCHEMA,
            "request_id": request_id,
            "command": command,
            "arguments": {},
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _frame(payload)


def _decode_request(frame: bytes) -> tuple[str, str]:
    if not isinstance(frame, bytes) or len(frame) < 5:
        raise ProtocolError("INVALID_FRAME")
    declared = struct.unpack(">I", frame[:4])[0]
    payload = frame[4:]
    if declared != len(payload) or declared > MAX_FRAME_BYTES:
        raise ProtocolError("FRAME_SIZE")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolError("INVALID_UTF8") from exc
    _check_nesting(text)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except ProtocolError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ProtocolError("INVALID_JSON") from exc
    if not isinstance(parsed, dict) or set(parsed) != {
        "schema_version",
        "request_id",
        "command",
        "arguments",
    }:
        raise ProtocolError("REQUEST_FIELDS")
    request_id = parsed["request_id"]
    command = parsed["command"]
    if parsed["schema_version"] != REQUEST_SCHEMA:
        raise ProtocolError("UNSUPPORTED_VERSION")
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise ProtocolError("INVALID_REQUEST_ID")
    if not isinstance(command, str) or not _COMMAND.fullmatch(command):
        raise ProtocolError("INVALID_COMMAND")
    if not isinstance(parsed["arguments"], dict) or parsed["arguments"]:
        raise ProtocolError("ARGUMENTS_NOT_ALLOWED")
    return request_id, command


def _encode_response(
    request_id: str,
    *,
    status: str,
    reason_code: str,
    payload: Mapping[str, str] | None,
) -> bytes:
    body = json.dumps(
        {
            "schema_version": RESPONSE_SCHEMA,
            "request_id": request_id,
            "status": status,
            "reason_code": reason_code,
            "payload": dict(payload) if payload is not None else None,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _frame(body)


def process_frame(frame: bytes, store: CanaryStore) -> bytes:
    """Validate one request and return a fixed, non-authorizing response."""
    request_id, command = _decode_request(frame)
    if command == "health":
        return _encode_response(
            request_id,
            status="OK",
            reason_code="NONE",
            payload={"authorization": "DISABLED", "prototype_status": "NON_AUTHORIZING"},
        )
    if command == "canary_status":
        if not isinstance(store, CanaryStore):
            raise ProtocolError("CANARY_UNAVAILABLE")
        try:
            canary = store.status()
        except CanaryStoreError as exc:
            raise ProtocolError("CANARY_UNAVAILABLE") from exc
        return _encode_response(
            request_id,
            status="OK",
            reason_code="NONE",
            payload=canary,
        )
    reason = "COMMAND_DISABLED" if command in {"enroll", "approve"} else "UNKNOWN_COMMAND"
    return _encode_response(
        request_id,
        status="DENIED",
        reason_code=reason,
        payload=None,
    )


__all__ = [
    "MAX_FRAME_BYTES",
    "CanaryStore",
    "ProtocolError",
    "encode_request",
    "process_frame",
]
