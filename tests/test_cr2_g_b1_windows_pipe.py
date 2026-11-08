from __future__ import annotations

import json
import os
import struct
import threading
import uuid

import pytest

from tools.cr2_g_b1.protocol import encode_request
from tools.cr2_g_b1.store import CanaryStore
from tools.cr2_g_b1.windows_pipe import (
    BrokerPipeError,
    current_process_user_sid,
    request_pipe,
    serve_one_request,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Win32 named-pipe API test")


def _response_payload(frame: bytes) -> dict[str, object]:
    length = struct.unpack(">I", frame[:4])[0]
    assert length == len(frame) - 4
    return json.loads(frame[4:].decode("utf-8"))


def _start_server(
    *,
    pipe_name: str,
    allowed_sid: str,
    store: CanaryStore,
) -> tuple[threading.Thread, list[Exception]]:
    errors: list[Exception] = []

    def target() -> None:
        try:
            serve_one_request(
                pipe_name=pipe_name,
                allowed_client_sid=allowed_sid,
                store=store,
                timeout_ms=2500,
            )
        except Exception as exc:  # surfaced to the test thread
            errors.append(exc)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, errors


def _name() -> str:
    return rf"\\.\pipe\SentinelCR2GB1-{uuid.uuid4()}"


def test_real_local_pipe_reads_token_and_serves_only_fixed_health(tmp_path) -> None:
    sid = current_process_user_sid()
    assert sid.startswith("S-1-")
    store = CanaryStore.initialize(tmp_path / "pipe.db")
    pipe_name = _name()
    thread, errors = _start_server(pipe_name=pipe_name, allowed_sid=sid, store=store)

    response = request_pipe(pipe_name, encode_request("pipe-1", "health"), timeout_ms=2200)

    thread.join(timeout=3)
    assert not thread.is_alive()
    assert errors == []
    assert _response_payload(response)["payload"] == {
        "authorization": "DISABLED",
        "prototype_status": "NON_AUTHORIZING",
    }


def test_real_local_pipe_returns_only_synthetic_canary_metadata(tmp_path) -> None:
    sid = current_process_user_sid()
    store = CanaryStore.initialize(tmp_path / "pipe-canary.db")
    pipe_name = _name()
    thread, errors = _start_server(pipe_name=pipe_name, allowed_sid=sid, store=store)

    response = request_pipe(
        pipe_name,
        encode_request("pipe-canary", "canary_status"),
        timeout_ms=2200,
    )

    thread.join(timeout=3)
    assert not thread.is_alive()
    assert errors == []
    assert _response_payload(response)["payload"] == {
        "canary_id": "synthetic-canary-0001",
        "classification": "SYNTHETIC_ONLY",
        "state": "PRESENT",
    }


def test_real_pipe_dacl_denies_a_client_sid_not_in_the_acl(tmp_path) -> None:
    sid = current_process_user_sid()
    denied_sid = "S-1-5-18" if sid != "S-1-5-18" else "S-1-5-19"
    store = CanaryStore.initialize(tmp_path / "denied-pipe.db")
    pipe_name = _name()
    thread, errors = _start_server(
        pipe_name=pipe_name,
        allowed_sid=denied_sid,
        store=store,
    )

    with pytest.raises(BrokerPipeError, match="PIPE_ACCESS_DENIED"):
        request_pipe(pipe_name, encode_request("pipe-denied", "canary_status"), timeout_ms=1500)

    thread.join(timeout=3)
    assert not thread.is_alive()
    assert errors and isinstance(errors[0], BrokerPipeError)
    assert errors[0].reason_code == "PIPE_TIMEOUT"


def test_pipe_name_and_sid_configuration_are_closed() -> None:
    store = object()
    with pytest.raises(BrokerPipeError, match="INVALID_PIPE_NAME"):
        serve_one_request(
            pipe_name=r"\\.\pipe\arbitrary-name",
            allowed_client_sid="S-1-5-18",
            store=store,  # type: ignore[arg-type]
        )
    with pytest.raises(BrokerPipeError, match="INVALID_ALLOWED_SID"):
        serve_one_request(
            pipe_name=_name(),
            allowed_client_sid="owner_verified=true",
            store=store,  # type: ignore[arg-type]
        )
