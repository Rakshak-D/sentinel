from __future__ import annotations

import ctypes
import os
import threading
import time
import uuid
from ctypes import wintypes
from pathlib import Path

import pytest

from tools.cr2_g_b1 import windows_pipe
from tools.cr2_g_b1.protocol import encode_request
from tools.cr2_g_b1.store import CanaryStore
from tools.cr2_g_b1.windows_pipe import (
    BrokerPipeError,
    current_process_user_sid,
    request_pipe,
    serve_one_request,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Win32 named-pipe API test")

_FILE_READ_DATA = 0x0001
_FILE_WRITE_DATA = 0x0002
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_CREATE_PIPE_INSTANCE = 0x0004
_SYNCHRONIZE = 0x00100000
_GENERIC_WRITE = 0x40000000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_GENERIC_READ = 0x80000000
_GENERIC_ALL = 0x10000000
_CLIENT_PIPE_MASK = _FILE_READ_DATA | _FILE_WRITE_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE


def _pipe_name() -> str:
    return rf"\\.\pipe\SentinelCR2GB1-review-{uuid.uuid4()}"


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


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", wintypes.DWORD),
        ("AclBytesInUse", wintypes.DWORD),
        ("AclBytesFree", wintypes.DWORD),
    ]


def _client_ace_mask(pipe_handle: wintypes.HANDLE, client_sid: str) -> int:
    """Read the DACL from the live pipe object, not the input SDDL string."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]

    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    # SE_FILE_OBJECT is the documented object type for named pipes.
    error = advapi32.GetSecurityInfo(
        pipe_handle,
        1,
        0x00000004,  # DACL_SECURITY_INFORMATION
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    assert error == 0
    try:
        info = _AclSizeInformation()
        assert advapi32.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2)
        for index in range(info.AceCount):
            ace = wintypes.LPVOID()
            assert advapi32.GetAce(dacl, index, ctypes.byref(ace))
            header = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte))
            if header[0] != 0:  # ACCESS_ALLOWED_ACE_TYPE
                continue
            words = ctypes.cast(ace, ctypes.POINTER(wintypes.DWORD))
            mask = int(words[1])
            sid_pointer = ctypes.c_void_p(ctypes.cast(ace, ctypes.c_void_p).value + 8)
            sid_text = wintypes.LPWSTR()
            assert advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_text))
            try:
                if sid_text.value == client_sid:
                    return mask
            finally:
                kernel32.LocalFree(ctypes.cast(sid_text, wintypes.HLOCAL))
        raise AssertionError("configured client ACE was not present in the live DACL")
    finally:
        kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))


def test_live_pipe_client_ace_excludes_pipe_creation_and_admin_rights(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sid = current_process_user_sid()
    original_require = windows_pipe._require_windows
    kernel32, advapi32 = original_require()
    created = threading.Event()
    handle_box: list[wintypes.HANDLE] = []

    class CapturingKernel:
        def __getattr__(self, name: str):
            return getattr(kernel32, name)

        def CreateNamedPipeW(self, *args):
            handle = kernel32.CreateNamedPipeW(*args)
            handle_box.append(handle)
            created.set()
            return handle

    monkeypatch.setattr(windows_pipe, "_require_windows", lambda: (CapturingKernel(), advapi32))
    store = CanaryStore.initialize(tmp_path / "dacl-inspect.db")
    name = _pipe_name()
    thread, errors = _start_server(pipe_name=name, allowed_sid=sid, store=store)
    try:
        assert created.wait(2)
        mask = _client_ace_mask(handle_box[0], sid)
        response = request_pipe(name, encode_request("dacl-check", "health"), timeout_ms=1500)
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert errors == []
        assert response
    finally:
        thread.join(timeout=3)
    effective_mask = mask
    # Generic-write maps FILE_APPEND_DATA (0x4), which is also
    # FILE_CREATE_PIPE_INSTANCE for a named-pipe object.
    if mask & _GENERIC_WRITE:
        effective_mask |= 0x00020000 | 0x0002 | 0x0004 | 0x100 | 0x10 | _SYNCHRONIZE
    assert mask == _CLIENT_PIPE_MASK
    assert effective_mask & _FILE_CREATE_PIPE_INSTANCE == 0
    assert mask & (_WRITE_DAC | _WRITE_OWNER | _GENERIC_READ | _GENERIC_WRITE | _GENERIC_ALL) == 0


@pytest.mark.parametrize(
    ("stall_point", "prefix_length"),
    [("before_header", 0), ("partial_header", 2), ("partial_body", 7)],
)
def test_client_io_deadline_covers_stalled_response_regions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stall_point: str,
    prefix_length: int,
) -> None:
    sid = current_process_user_sid()
    store = CanaryStore.initialize(tmp_path / f"stall-{stall_point}.db")
    name = _pipe_name()
    server_errors: list[Exception]
    original_write_all = windows_pipe._write_all
    stalled = threading.Event()
    release = threading.Event()
    first_write = True
    server_thread: threading.Thread | None = None

    def stall_response(kernel, handle, payload, deadline):
        nonlocal first_write
        if threading.current_thread() is server_thread and first_write:
            first_write = False
            if prefix_length:
                original_write_all(kernel, handle, payload[:prefix_length], deadline)
            stalled.set()
            release.wait(3)
            if prefix_length < len(payload):
                original_write_all(kernel, handle, payload[prefix_length:], deadline)
            return
        return original_write_all(kernel, handle, payload, deadline)

    monkeypatch.setattr(windows_pipe, "_write_all", stall_response)
    server_thread, server_errors = _start_server(pipe_name=name, allowed_sid=sid, store=store)
    outcome: dict[str, object] = {}
    finished = threading.Event()

    def client() -> None:
        try:
            outcome["response"] = request_pipe(
                name, encode_request(f"timeout-{stall_point}", "health"), timeout_ms=140
            )
        except Exception as exc:
            outcome["error"] = exc
        finally:
            finished.set()

    client_thread = threading.Thread(target=client, daemon=True)
    client_thread.start()
    completed_before_release = False
    try:
        assert stalled.wait(2)
        completed_before_release = finished.wait(0.45)
    finally:
        release.set()
        client_thread.join(timeout=3)
        server_thread.join(timeout=3)
    assert not client_thread.is_alive()
    assert not server_thread.is_alive()
    assert completed_before_release, f"client exceeded its deadline while stalled at {stall_point}"
    assert isinstance(outcome.get("error"), BrokerPipeError)
    assert outcome["error"].reason_code == "PIPE_TIMEOUT"  # type: ignore[union-attr]


def test_client_returns_bounded_error_when_server_disconnects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sid = current_process_user_sid()
    store = CanaryStore.initialize(tmp_path / "disconnect.db")
    name = _pipe_name()
    original_write_all = windows_pipe._write_all
    disconnected = threading.Event()
    server_thread: threading.Thread | None = None

    def disconnect_before_response(kernel, handle, payload, deadline):
        if threading.current_thread() is server_thread:
            del kernel, handle, payload, deadline
            disconnected.set()
            raise BrokerPipeError("TEST_SERVER_DISCONNECTED")
        return original_write_all(kernel, handle, payload, deadline)

    monkeypatch.setattr(windows_pipe, "_write_all", disconnect_before_response)
    server_thread, server_errors = _start_server(pipe_name=name, allowed_sid=sid, store=store)
    outcome: dict[str, object] = {}
    finished = threading.Event()

    def client() -> None:
        try:
            request_pipe(name, encode_request("disconnect", "health"), timeout_ms=1000)
        except Exception as exc:
            outcome["error"] = exc
        finally:
            finished.set()

    client_thread = threading.Thread(target=client, daemon=True)
    client_thread.start()
    assert disconnected.wait(2)
    assert finished.wait(1)
    client_thread.join(timeout=1)
    server_thread.join(timeout=2)
    assert not client_thread.is_alive()
    assert not server_thread.is_alive()
    assert isinstance(outcome.get("error"), BrokerPipeError)


def test_absent_server_connection_obeys_the_same_bounded_deadline() -> None:
    name = _pipe_name()
    started = time.monotonic()
    with pytest.raises(BrokerPipeError, match="PIPE_CONNECT_TIMEOUT"):
        request_pipe(name, encode_request("no-server", "health"), timeout_ms=120)
    assert time.monotonic() - started < 0.6
