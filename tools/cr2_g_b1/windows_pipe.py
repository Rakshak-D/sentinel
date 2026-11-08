"""Uninstalled Windows named-pipe host for CR2-G-B1 laboratory work.

This module uses a temporary, one-instance local pipe. It is not a Windows
service and does not establish protected storage or owner authentication.
"""

from __future__ import annotations

import ctypes
import os
import re
import struct
import time
from ctypes import wintypes
from typing import Any

from tools.cr2_g_b1.protocol import MAX_FRAME_BYTES, ProtocolError, process_frame
from tools.cr2_g_b1.store import CanaryStore

_PIPE_NAME = re.compile(r"\\\\\.\\pipe\\SentinelCR2GB1-[A-Za-z0-9-]{1,64}\Z", re.ASCII)
_SID = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\Z", re.ASCII)
_ERROR_IO_PENDING = 997
_ERROR_PIPE_CONNECTED = 535
_ERROR_ACCESS_DENIED = 5
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_PIPE_ACCESS_DUPLEX = 0x00000003
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_FILE_FLAG_OVERLAPPED = 0x40000000
_PIPE_TYPE_BYTE = 0x00000000
_PIPE_READMODE_BYTE = 0x00000000
_PIPE_WAIT = 0x00000000
_PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_OPEN_EXISTING = 3
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_ERROR_INSUFFICIENT_BUFFER = 122
_RESPONSE_ACK = b"\x06"
_WinApi = Any


class BrokerPipeError(RuntimeError):
    """Fixed-code Windows pipe failure with no handle/path details."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


def _require_windows() -> tuple[_WinApi, _WinApi]:
    if os.name != "nt":
        raise BrokerPipeError("WINDOWS_ONLY")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.RevertToSelf.restype = wintypes.BOOL
    advapi32.RevertToSelf.argtypes = []
    kernel32.GetCurrentThread.restype = wintypes.HANDLE
    kernel32.GetCurrentThread.argtypes = []

    kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
    ]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.CreateEventW.argtypes = [
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.BOOL,
        wintypes.LPCWSTR,
    ]
    kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Overlapped)]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(_Overlapped),
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(_Overlapped),
    ]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.GetOverlappedResult.restype = wintypes.BOOL
    kernel32.GetOverlappedResult.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_Overlapped),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
    ]
    kernel32.CancelIoEx.restype = wintypes.BOOL
    kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Overlapped)]
    kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
    kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.GetLastError.argtypes = []
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]

    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ImpersonateNamedPipeClient.restype = wintypes.BOOL
    advapi32.ImpersonateNamedPipeClient.argtypes = [wintypes.HANDLE]
    advapi32.OpenThreadToken.restype = wintypes.BOOL
    advapi32.OpenThreadToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.BOOL,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    return kernel32, advapi32


def _win_error(kernel32: _WinApi) -> BrokerPipeError:
    # Deliberately discard the OS message: it can contain implementation data.
    del kernel32
    return BrokerPipeError("WINDOWS_PIPE_OPERATION_FAILED")


def _last_error_code() -> int:
    return ctypes.get_last_error()


def _sid_for_token(advapi32: _WinApi, kernel32: _WinApi, token: wintypes.HANDLE) -> str:
    sid_string = wintypes.LPWSTR()
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        if _last_error_code() != _ERROR_INSUFFICIENT_BUFFER or not needed.value:
            raise BrokerPipeError("CALLER_TOKEN_QUERY_FAILED")
        token_buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token, _TOKEN_USER, token_buffer, needed.value, ctypes.byref(needed)
        ):
            raise BrokerPipeError("CALLER_TOKEN_QUERY_FAILED")
        user = ctypes.cast(token_buffer, ctypes.POINTER(_TokenUser)).contents
        if not advapi32.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(sid_string)):
            raise BrokerPipeError("CALLER_SID_CONVERSION_FAILED")
        result = sid_string.value
        if result is None or not _SID.fullmatch(result):
            raise BrokerPipeError("CALLER_SID_INVALID")
        return result
    finally:
        if sid_string:
            kernel32.LocalFree(ctypes.cast(sid_string, wintypes.HLOCAL))


def _token_user_sid(kernel32: _WinApi, advapi32: _WinApi) -> str:
    token = wintypes.HANDLE()
    if not advapi32.OpenThreadToken(
        kernel32.GetCurrentThread(), _TOKEN_QUERY, True, ctypes.byref(token)
    ):
        raise BrokerPipeError("CALLER_TOKEN_OPEN_FAILED")
    try:
        return _sid_for_token(advapi32, kernel32, token)
    finally:
        kernel32.CloseHandle(token)


def current_process_user_sid() -> str:
    """Return the caller process account SID for disposable lab configuration."""
    kernel32, advapi32 = _require_windows()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise BrokerPipeError("PROCESS_TOKEN_UNAVAILABLE")
    try:
        return _sid_for_token(advapi32, kernel32, token)
    finally:
        kernel32.CloseHandle(token)


def request_pipe(pipe_name: str, frame: bytes, timeout_ms: int = 2000) -> bytes:
    """Small lab client that can only exchange one bounded protocol frame."""
    if os.name != "nt":
        raise BrokerPipeError("WINDOWS_ONLY")
    if not _PIPE_NAME.fullmatch(pipe_name) or not 1 <= timeout_ms <= 10_000:
        raise BrokerPipeError("INVALID_PIPE_REQUEST")
    if not isinstance(frame, bytes) or len(frame) < 5 or len(frame) > MAX_FRAME_BYTES + 4:
        raise BrokerPipeError("FRAME_SIZE")
    size = struct.unpack(">I", frame[:4])[0]
    if size != len(frame) - 4 or size > MAX_FRAME_BYTES:
        raise BrokerPipeError("FRAME_SIZE")
    kernel32, _ = _require_windows()
    deadline = time.monotonic() + timeout_ms / 1000
    handle = wintypes.HANDLE()
    while time.monotonic() < deadline:
        remaining = int(max(0.0, deadline - time.monotonic()) * 1000)
        kernel32.WaitNamedPipeW(pipe_name, min(remaining, 100))
        handle = kernel32.CreateFileW(
            pipe_name,
            _GENERIC_READ | _GENERIC_WRITE,
            0,
            None,
            _OPEN_EXISTING,
            0,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if handle and ctypes.cast(handle, ctypes.c_void_p).value != invalid_handle:
            break
        error = kernel32.GetLastError()
        if error not in {2, 231, 121}:
            if error == _ERROR_ACCESS_DENIED:
                raise BrokerPipeError("PIPE_ACCESS_DENIED")
            raise BrokerPipeError("PIPE_CONNECT_FAILED")
    else:
        raise BrokerPipeError("PIPE_CONNECT_TIMEOUT")
    try:
        written = wintypes.DWORD()
        write_buffer = ctypes.create_string_buffer(frame)
        if not kernel32.WriteFile(
            handle, write_buffer, len(frame), ctypes.byref(written), None
        ) or written.value != len(frame):
            raise BrokerPipeError("PIPE_WRITE_FAILED")
        header = _client_read_exact(kernel32, handle, 4)
        response_length = struct.unpack(">I", header)[0]
        if not 0 < response_length <= MAX_FRAME_BYTES:
            raise BrokerPipeError("RESPONSE_SIZE")
        response = header + _client_read_exact(kernel32, handle, response_length)
        written = wintypes.DWORD()
        ack = ctypes.create_string_buffer(_RESPONSE_ACK)
        if not kernel32.WriteFile(
            handle, ack, 1, ctypes.byref(written), None
        ) or written.value != 1:
            raise BrokerPipeError("PIPE_ACK_FAILED")
        return response
    finally:
        kernel32.CloseHandle(handle)


def _client_read_exact(kernel32: _WinApi, handle: wintypes.HANDLE, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        buffer = ctypes.create_string_buffer(size - len(result))
        count = wintypes.DWORD()
        if not kernel32.ReadFile(
            handle, buffer, len(buffer), ctypes.byref(count), None
        ) or count.value == 0:
            raise BrokerPipeError("PIPE_READ_FAILED")
        result.extend(buffer.raw[: count.value])
    return bytes(result)


def _wait_overlapped(
    kernel32: _WinApi,
    handle: wintypes.HANDLE,
    overlapped: _Overlapped,
    timeout_ms: int,
) -> int:
    outcome = kernel32.WaitForSingleObject(overlapped.hEvent, max(0, timeout_ms))
    if outcome == _WAIT_TIMEOUT:
        kernel32.CancelIoEx(handle, ctypes.byref(overlapped))
        transferred = wintypes.DWORD()
        kernel32.GetOverlappedResult(
            handle, ctypes.byref(overlapped), ctypes.byref(transferred), True
        )
        raise BrokerPipeError("PIPE_TIMEOUT")
    if outcome != _WAIT_OBJECT_0:
        raise _win_error(kernel32)
    transferred = wintypes.DWORD()
    if not kernel32.GetOverlappedResult(
        handle, ctypes.byref(overlapped), ctypes.byref(transferred), False
    ):
        raise _win_error(kernel32)
    return transferred.value


def _connect(kernel32: _WinApi, pipe: wintypes.HANDLE, timeout_ms: int) -> None:
    overlapped = _Overlapped()
    event = kernel32.CreateEventW(None, True, False, None)
    if not event:
        raise _win_error(kernel32)
    overlapped.hEvent = event
    try:
        if kernel32.ConnectNamedPipe(pipe, ctypes.byref(overlapped)):
            return
        error = _last_error_code()
        if error == _ERROR_PIPE_CONNECTED:
            return
        if error != _ERROR_IO_PENDING:
            raise _win_error(kernel32)
        outcome = kernel32.WaitForSingleObject(event, timeout_ms)
        if outcome == _WAIT_TIMEOUT:
            kernel32.CancelIoEx(pipe, ctypes.byref(overlapped))
            transferred = wintypes.DWORD()
            kernel32.GetOverlappedResult(
                pipe, ctypes.byref(overlapped), ctypes.byref(transferred), True
            )
            raise BrokerPipeError("PIPE_TIMEOUT")
        if outcome != _WAIT_OBJECT_0:
            raise _win_error(kernel32)
        transferred = wintypes.DWORD()
        if not kernel32.GetOverlappedResult(
            pipe, ctypes.byref(overlapped), ctypes.byref(transferred), False
        ):
            raise _win_error(kernel32)
    finally:
        kernel32.CloseHandle(event)


def _read_exact(
    kernel32: _WinApi,
    handle: wintypes.HANDLE,
    size: int,
    deadline: float,
) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        remaining_ms = int(max(0.0, deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            raise BrokerPipeError("PIPE_TIMEOUT")
        wanted = size - len(chunks)
        buffer = ctypes.create_string_buffer(wanted)
        transferred = wintypes.DWORD()
        overlapped = _Overlapped()
        event = kernel32.CreateEventW(None, True, False, None)
        if not event:
            raise _win_error(kernel32)
        overlapped.hEvent = event
        try:
            ok = kernel32.ReadFile(
                handle, buffer, wanted, ctypes.byref(transferred), ctypes.byref(overlapped)
            )
            if not ok:
                error = _last_error_code()
                if error != _ERROR_IO_PENDING:
                    raise _win_error(kernel32)
                transferred.value = _wait_overlapped(kernel32, handle, overlapped, remaining_ms)
            if transferred.value == 0:
                raise BrokerPipeError("PIPE_EOF")
            chunks.extend(buffer.raw[: transferred.value])
        finally:
            kernel32.CloseHandle(event)
    return bytes(chunks)


def _write_all(
    kernel32: _WinApi,
    handle: wintypes.HANDLE,
    payload: bytes,
    deadline: float,
) -> None:
    offset = 0
    while offset < len(payload):
        remaining_ms = int(max(0.0, deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            raise BrokerPipeError("PIPE_TIMEOUT")
        part = payload[offset:]
        buffer = ctypes.create_string_buffer(part)
        transferred = wintypes.DWORD()
        overlapped = _Overlapped()
        event = kernel32.CreateEventW(None, True, False, None)
        if not event:
            raise _win_error(kernel32)
        overlapped.hEvent = event
        try:
            ok = kernel32.WriteFile(
                handle,
                buffer,
                len(part),
                ctypes.byref(transferred),
                ctypes.byref(overlapped),
            )
            if not ok:
                error = _last_error_code()
                if error != _ERROR_IO_PENDING:
                    raise _win_error(kernel32)
                transferred.value = _wait_overlapped(kernel32, handle, overlapped, remaining_ms)
            if transferred.value == 0:
                raise BrokerPipeError("PIPE_WRITE_FAILED")
            offset += transferred.value
        finally:
            kernel32.CloseHandle(event)


def serve_one_request(
    *,
    pipe_name: str,
    allowed_client_sid: str,
    store: CanaryStore,
    timeout_ms: int = 2000,
) -> None:
    """Serve exactly one local request under an explicit SID pipe DACL.

    The client token is obtained by named-pipe impersonation. The SID is only
    an OS-account gate; it is not a human identity or approval signal.
    """
    if os.name != "nt":
        raise BrokerPipeError("WINDOWS_ONLY")
    if not isinstance(pipe_name, str) or not _PIPE_NAME.fullmatch(pipe_name):
        raise BrokerPipeError("INVALID_PIPE_NAME")
    if not isinstance(allowed_client_sid, str) or not _SID.fullmatch(allowed_client_sid):
        raise BrokerPipeError("INVALID_ALLOWED_SID")
    if not 1 <= timeout_ms <= 10_000:
        raise BrokerPipeError("INVALID_TIMEOUT")
    kernel32, advapi32 = _require_windows()
    sddl = f"D:P(A;;GA;;;SY)(A;;GRGW;;;{allowed_client_sid})"
    descriptor = wintypes.LPVOID()
    descriptor_size = wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), ctypes.byref(descriptor_size)
    ):
        raise BrokerPipeError("PIPE_SECURITY_DESCRIPTOR_FAILED")
    attributes = _SecurityAttributes(
        ctypes.sizeof(_SecurityAttributes), descriptor, False
    )
    pipe = wintypes.HANDLE()
    try:
        pipe = kernel32.CreateNamedPipeW(
            pipe_name,
            _PIPE_ACCESS_DUPLEX | _FILE_FLAG_FIRST_PIPE_INSTANCE | _FILE_FLAG_OVERLAPPED,
            _PIPE_TYPE_BYTE
            | _PIPE_READMODE_BYTE
            | _PIPE_WAIT
            | _PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_FRAME_BYTES + 4,
            MAX_FRAME_BYTES + 4,
            timeout_ms,
            ctypes.byref(attributes),
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if not pipe or ctypes.cast(pipe, ctypes.c_void_p).value == invalid_handle:
            raise BrokerPipeError("PIPE_CREATE_FAILED")
    finally:
        kernel32.LocalFree(ctypes.cast(descriptor, wintypes.HLOCAL))

    try:
        _connect(kernel32, pipe, timeout_ms)
        deadline = time.monotonic() + timeout_ms / 1000
        header = _read_exact(kernel32, pipe, 4, deadline)
        payload_length = struct.unpack(">I", header)[0]
        if not 0 < payload_length <= MAX_FRAME_BYTES:
            raise BrokerPipeError("FRAME_SIZE")
        payload = _read_exact(kernel32, pipe, payload_length, deadline)

        # Named-pipe impersonation binds to the client's most recent message;
        # therefore the bounded frame is read before inspecting its token.
        impersonated = False
        try:
            if not advapi32.ImpersonateNamedPipeClient(pipe):
                raise BrokerPipeError("PIPE_IMPERSONATION_FAILED")
            impersonated = True
            caller_sid = _token_user_sid(kernel32, advapi32)
        finally:
            if impersonated and not advapi32.RevertToSelf():
                raise BrokerPipeError("CALLER_TOKEN_REVERT_FAILED")
        if caller_sid != allowed_client_sid:
            raise BrokerPipeError("CALLER_NOT_ALLOWED")

        try:
            response = process_frame(header + payload, store)
        except ProtocolError as exc:
            # Protocol failures are closed without reflecting attacker data.
            raise BrokerPipeError(exc.reason_code) from None
        _write_all(kernel32, pipe, response, deadline)
        if _read_exact(kernel32, pipe, 1, deadline) != _RESPONSE_ACK:
            raise BrokerPipeError("RESPONSE_ACK_INVALID")
    finally:
        kernel32.DisconnectNamedPipe(pipe)
        kernel32.CloseHandle(pipe)


__all__ = ["BrokerPipeError", "serve_one_request"]
